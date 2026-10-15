"""Who is calling: MCP token verification and the per-request Wiki.js user."""

import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken

from . import wiki_jwt
from .errors import WikiAuthError, WikiAuthExpired
from .store import Store


@dataclass
class SessionUser:
    """The Wiki.js user a tool call runs as."""

    wiki_user_id: int
    email: str
    jwt: str
    on_new_jwt: Callable[[str], Awaitable[None]] | None = None
    # Called when Wiki.js no longer accepts the session
    on_session_lost: Callable[[], Awaitable[None]] | None = None


UserSource = Callable[[], Awaitable[SessionUser]]


class StoreTokenVerifier:
    """MCP SDK TokenVerifier backed by the token store.

    Only OAuth access tokens are accepted. A token whose user has no usable Wiki.js
    session (lapsed after `jwt_renewal` unused, or wiped) is rejected too: the
    client then gets a 401 and runs the OAuth flow again, so the user signs in to
    the wiki anew instead of every tool call failing.
    """

    def __init__(self, store: Store, jwt_renewal: int, clock=time.time):
        self._store = store
        self._jwt_renewal = jwt_renewal
        self._clock = clock

    def _usable(self, jwt: str | None) -> bool:
        if jwt is None:
            return False
        try:
            return wiki_jwt.is_renewable(jwt, self._jwt_renewal, self._clock())
        except WikiAuthError:
            return False

    async def verify_token(self, token: str) -> AccessToken | None:
        user = await self._store.get_user_for_token(token)
        if user is None or user.token_kind != "oauth" or not self._usable(user.jwt):
            return None
        await self._store.touch(user.token_id)
        return AccessToken(
            token=token,
            client_id=user.client_id,
            scopes=user.scopes,
            expires_at=user.token_expires_at,
            subject=str(user.wiki_user_id),
        )


def token_user_source(store: Store) -> UserSource:
    """The user behind the bearer token of the current HTTP request."""

    async def current_user() -> SessionUser:
        access_token = get_access_token()
        user = (
            await store.get_user_for_token(access_token.token) if access_token else None
        )
        if user is None or user.jwt is None:
            raise WikiAuthExpired("No usable Wiki.js session for this token")

        async def on_new_jwt(jwt: str) -> None:
            await store.update_jwt(user.wiki_user_id, jwt)

        async def on_session_lost() -> None:
            await store.forget_jwt(user.wiki_user_id)

        return SessionUser(
            user.wiki_user_id, user.email, user.jwt, on_new_jwt, on_session_lost
        )

    return current_user


def static_user_source(jwt: str, wiki_user_id: int, email: str) -> UserSource:
    """A single fixed user, for local development over stdio."""
    user = SessionUser(wiki_user_id, email, jwt)

    async def on_new_jwt(new_jwt: str) -> None:
        user.jwt = new_jwt

    user.on_new_jwt = on_new_jwt

    async def current_user() -> SessionUser:
        return user

    return current_user
