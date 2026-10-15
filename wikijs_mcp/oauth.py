"""OAuth 2.1 authorization server for MCP clients such as claude.ai (fase 5).

The SDK's handlers do the protocol work (PKCE, redirect URI checks, client
authentication, error responses); this provider stores everything in the Store and
puts the user in between: `authorize` parks the request and sends the browser to a
consent page (web.py), which requires a Wiki.js login and an explicit "Allow".

Routes live under `<base>/oauth` (`/authorize`, `/token`, `/register`, `/revoke`),
because `<base>/token` is the personal token page. Metadata is served where clients
look for it (RFC 8414 / RFC 9728 path insertion), which is outside `<base>/` and
needs its own reverse proxy locations.
"""

import json
import logging
from urllib.parse import urlsplit

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.server.auth.routes import create_auth_routes
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.routing import BaseRoute, Mount, Route

from .config import WikiJSConfig
from .store import Store

logger = logging.getLogger(__name__)

ACCESS_TOKEN_TTL = 3600
SCOPE = "wiki"
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def issuer_url(config: WikiJSConfig) -> str:
    return f"{config.public_url.rstrip('/')}{config.mcp_base_path.rstrip('/')}/oauth"


def _allowed_redirect_uri(uri: str) -> bool:
    """HTTPS anywhere, or plain HTTP to a local loopback port (native apps)."""
    parts = urlsplit(uri)
    # No user info: `https://claude.ai@evil.example/` goes to evil.example
    if parts.fragment or parts.username is not None or parts.password is not None:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    return parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTS


def redirect_origin(uri: str) -> str:
    """scheme://host[:port] of a redirect URI, without any user info, for display
    and for the consent page's CSP."""
    parts = urlsplit(uri)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    port = f":{parts.port}" if parts.port else ""
    return f"{parts.scheme}://{host}{port}"


class WikiOAuthProvider:
    """OAuthAuthorizationServerProvider backed by the Store."""

    def __init__(self, config: WikiJSConfig, store: Store):
        self.config = config
        self.store = store

    def consent_url(self, pending_id: str) -> str:
        base = self.config.mcp_base_path.rstrip("/")
        return f"{self.config.public_url.rstrip('/')}{base}/oauth/consent/{pending_id}"

    # Clients ----------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        info = await self.store.get_oauth_client(client_id)
        return OAuthClientInformationFull.model_validate_json(info) if info else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        for uri in client_info.redirect_uris or []:
            if not _allowed_redirect_uri(str(uri)):
                raise RegistrationError(
                    error="invalid_redirect_uri",
                    error_description=(
                        "Redirect URIs must use https, or http on a loopback address"
                    ),
                )
        await self.store.save_oauth_client(
            client_info.client_id, client_info.model_dump_json()
        )

    # Authorization ----------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Park the request; the user logs in and consents on our own page."""
        pending_id = await self.store.create_oauth_pending(
            client.client_id, params.model_dump_json()
        )
        return self.consent_url(pending_id)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        found = await self.store.get_oauth_code(client.client_id, authorization_code)
        if found is None:
            return None
        wiki_user_id, params, expires_at = found
        params = AuthorizationParams.model_validate_json(params)
        return AuthorizationCode(
            code=authorization_code,
            scopes=params.scopes or [SCOPE],
            expires_at=expires_at,
            client_id=client.client_id,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
            subject=str(wiki_user_id),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        if not await self.store.consume_oauth_code(
            client.client_id, authorization_code.code
        ):
            raise TokenError("invalid_grant", "Authorization code was already used")
        return await self._issue(
            client.client_id, int(authorization_code.subject), authorization_code.scopes
        )

    # Refresh ----------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        found = await self.store.get_refresh_token(client.client_id, refresh_token)
        if found is None:
            await self._end_grant_if_reused(client.client_id, refresh_token)
            return None
        wiki_user_id, scopes, expires_at = found
        return RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=expires_at,
            subject=str(wiki_user_id),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotation: a refresh token works once
        if not await self.store.revoke_refresh_token(
            client.client_id, refresh_token.token
        ):
            await self._end_grant_if_reused(client.client_id, refresh_token.token)
            raise TokenError("invalid_grant", "Refresh token was already used")
        return await self._issue(
            client.client_id, int(refresh_token.subject), scopes or refresh_token.scopes
        )

    async def _end_grant_if_reused(self, client_id: str, refresh_token: str) -> None:
        """A used refresh token coming back means it leaked (or the client lost a
        response): either the thief or the app holds the newer one, so end the
        whole grant and let the user sign in again (OAuth 2.1, section 4.3.1)."""
        wiki_user_id = await self.store.used_refresh_token_owner(
            client_id, refresh_token
        )
        if wiki_user_id is not None:
            logger.warning(
                f"Reused refresh token of OAuth app {client_id} for wiki user "
                f"{wiki_user_id}; access of the app revoked"
            )
            await self.store.revoke_oauth_grant(wiki_user_id, client_id)

    async def _issue(
        self, client_id: str, wiki_user_id: int, scopes: list[str]
    ) -> OAuthToken:
        # Also refuse when the stored Wiki.js session lapsed: the client then runs
        # the authorization flow again, and the user signs in to the wiki anew
        if not await self.store.user_login_is_current(
            wiki_user_id, self.config.token_renewal
        ):
            raise TokenError("invalid_grant", "The wiki login has expired")
        client = await self.get_client(client_id)
        name = (client.client_name if client else None) or client_id
        _, access_token = await self.store.create_token(
            wiki_user_id,
            name,
            ACCESS_TOKEN_TTL,
            kind="oauth",
            client_id=client_id,
            scopes=scopes,
        )
        refresh_token, _ = await self.store.create_refresh_token(
            client_id, wiki_user_id, scopes
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(scopes),
            refresh_token=refresh_token,
        )

    # Access tokens and revocation ----------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        user = await self.store.get_user_for_token(token)
        if user is None or user.token_kind != "oauth":
            return None
        return AccessToken(
            token=token,
            client_id=user.client_id,
            scopes=user.scopes,
            expires_at=user.token_expires_at,
            subject=str(user.wiki_user_id),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Revoking either token ends the whole grant of that app for the user."""
        if token.subject:
            await self.store.revoke_oauth_grant(int(token.subject), token.client_id)


def oauth_routes(config: WikiJSConfig, provider: WikiOAuthProvider) -> list[BaseRoute]:
    """The SDK's authorization server routes, mounted under <base>/oauth.

    The SDK registers them at the root (`/authorize`, ...) while its metadata names
    them relative to the issuer, so they are mounted at the issuer's path. The
    metadata is also served at the RFC 8414 location
    `/.well-known/oauth-authorization-server<issuer path>`.
    """
    issuer = issuer_url(config)
    routes = create_auth_routes(
        provider=provider,
        issuer_url=AnyHttpUrl(issuer),
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=[SCOPE], default_scopes=[SCOPE]
        ),
        revocation_options=RevocationOptions(enabled=True),
    )
    issuer_path = urlsplit(issuer).path
    metadata = next(
        r for r in routes if r.path == "/.well-known/oauth-authorization-server"
    )
    return [
        Route(
            f"/.well-known/oauth-authorization-server{issuer_path}",
            endpoint=metadata.endpoint,
            methods=["GET", "OPTIONS"],
        ),
        Mount(issuer_path, routes=routes),
    ]


def client_display(client_info: str) -> tuple[str, str]:
    """(name, redirect hosts) of a stored client, for the consent and token pages."""
    info = json.loads(client_info)
    hosts = sorted(
        {
            redirect_origin(str(uri)).split("://", 1)[1]
            for uri in info.get("redirect_uris") or []
        }
    )
    return info.get("client_name") or info.get("client_id", "unknown app"), ", ".join(
        hosts
    )
