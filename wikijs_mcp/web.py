"""Browser routes: log in through Wiki.js, consent to OAuth apps, manage them.

Login flow (Wiki.js 2.5, see FASE0-RESULTATEN.md, point 6):
1. GET  <base>/login            stores a one-time state bound to this browser, sets
                                Wiki.js's `loginRedirect` cookie to our callback and
                                sends the browser to Wiki.js's login for the strategy.
2. Wiki.js logs the user in at the IdP, sets its `jwt` cookie and redirects to
   `loginRedirect` (which wins over a group's login redirect).
3. GET  <base>/auth/callback/<state>
                                checks state and browser, takes over the fresh `jwt`
                                cookie, verifies it with Wiki.js and opens a web session.
4. GET  <base>/oauth/consent/<id>
                                lets the signed-in user allow or deny an OAuth app.
5. GET  <base>/apps             lists connected apps; POST <base>/apps/disconnect.
"""

import html
import logging
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from mcp.server import FastMCP
from mcp.server.auth.provider import AuthorizationParams, construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from . import wiki_jwt
from .client import WikiJSClient
from .config import WikiJSConfig
from .errors import WikiError
from .oauth import client_display
from .store import LOGIN_STATE_TTL, Store

logger = logging.getLogger(__name__)

WEB_SESSION_TTL = 3600
LOGIN_COOKIE = "mcp_login"
SESSION_COOKIE = "mcp_session"
# A login must yield a JWT issued after it started (plus clock skew)
FRESH_LOGIN_SLACK = 60
WARN_BEFORE = 3 * 86400

SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    # Not no-referrer: then browsers send `Origin: null` on form posts, which the
    # Origin check rejects. same-origin still sends nothing to other sites.
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
}

STYLE = """
body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem;
color:#1f2328;line-height:1.5}
h1{font-size:1.5rem}h2{font-size:1.15rem;margin-top:2rem}
code,pre{background:#f3f4f6;border-radius:4px}pre{padding:.75rem;overflow-x:auto;
white-space:pre-wrap;word-break:break-all}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:.35rem;
border-bottom:1px solid #ddd}
.note{background:#fff8c5;padding:.75rem;border-radius:4px}
.ok{background:#dafbe1;padding:.75rem;border-radius:4px}
.error{background:#ffebe9;padding:.75rem;border-radius:4px}
button{cursor:pointer}form.inline{display:inline}
"""


def _fmt(timestamp: int | None) -> str:
    if not timestamp:
        return "never"
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def _page(
    title: str,
    body: str,
    status_code: int = 200,
    form_targets: tuple[str, ...] = (),
) -> HTMLResponse:
    """An HTML page. `form_targets` are extra origins a form may end up at:
    browsers apply the CSP form-action also to the redirect after a post."""
    document = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{html.escape(title)}</title><style>{STYLE}</style></head>"
        f"<body><h1>{html.escape(title)}</h1>{body}</body></html>"
    )
    headers = dict(SECURITY_HEADERS)
    if form_targets:
        headers["Content-Security-Policy"] = headers["Content-Security-Policy"].replace(
            "form-action 'self'", "form-action 'self' " + " ".join(form_targets)
        )
    return HTMLResponse(document, status_code=status_code, headers=headers)


class WebRoutes:
    """Login, consent and connected-apps pages under the MCP base path."""

    def __init__(
        self,
        config: WikiJSConfig,
        store: Store,
        clock=time.time,
    ):
        self.config = config
        self.store = store
        self._clock = clock
        self.base = config.mcp_base_path.rstrip("/")
        self.secure = config.public_url.startswith("https://")
        public = urlsplit(config.public_url)
        self.public_origin = f"{public.scheme}://{public.netloc}"

    def register(self, app: FastMCP) -> None:
        routes = [
            (f"{self.base}/login", ["GET"], self.login),
            (f"{self.base}/auth/callback/{{state}}", ["GET"], self.callback),
            (f"{self.base}/apps", ["GET"], self.apps_page),
            (f"{self.base}/apps/disconnect", ["POST"], self.disconnect_app),
            (f"{self.base}/logout", ["POST"], self.logout),
            (f"{self.base}/oauth/consent/{{pending_id}}", ["GET"], self.consent),
            (f"{self.base}/oauth/consent/{{pending_id}}", ["POST"], self.decide),
        ]
        for path, methods, handler in routes:
            app.custom_route(path, methods=methods)(handler)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _now(self) -> int:
        return int(self._clock())

    def _safe_next(self, value: str | None) -> str:
        """Only local paths under the base path; anything else is an open redirect."""
        default = f"{self.base}/apps"
        if (
            not value
            or not value.startswith(f"{self.base}/")
            or value.startswith("//")
            or "\\" in value
            or "://" in value
            or any(ord(ch) < 32 for ch in value)
        ):
            return default
        return value

    def _wiki_login_url(self) -> str:
        # The local strategy has no /login/local route; it logs in on the form
        if self.config.strategy_key == "local":
            return "/login"
        return f"/login/{self.config.strategy_key}"

    def _set_cookie(
        self, response: Response, name: str, value: str, max_age: int
    ) -> None:
        response.set_cookie(
            name,
            value,
            max_age=max_age,
            path=self.base,
            secure=self.secure,
            httponly=True,
            samesite="lax",
        )

    def _clear_cookie(self, response: Response, name: str) -> None:
        response.delete_cookie(
            name, path=self.base, secure=self.secure, httponly=True, samesite="lax"
        )

    def _error(self, message: str, status_code: int = 400) -> HTMLResponse:
        body = (
            f"<p class='error'>{html.escape(message)}</p>"
            f"<p><a href='{self.base}/login'>Log in again</a></p>"
        )
        return _page("Wiki MCP login", body, status_code)

    async def _session(self, request: Request):
        session_id = request.cookies.get(SESSION_COOKIE)
        return await self.store.get_web_session(session_id) if session_id else None

    async def _form_session(self, request: Request):
        """Session and form for a state-changing POST, or None if not allowed."""
        origin = request.headers.get("origin")
        if origin and origin != self.public_origin:
            return None, None
        session = await self._session(request)
        if session is None:
            return None, None
        form = await request.form()
        csrf = str(form.get("csrf", ""))
        if not secrets.compare_digest(csrf, session.csrf_secret):
            return None, None
        return session, form

    def _redirect_to_login(self) -> RedirectResponse:
        return RedirectResponse(
            f"{self.base}/login?next={self.base}/apps", status_code=303
        )

    # ------------------------------------------------------------------
    # Login
    # ------------------------------------------------------------------

    async def login(self, request: Request) -> Response:
        next_path = self._safe_next(request.query_params.get("next"))
        state, binding = await self.store.create_login_state(next_path)
        response = RedirectResponse(self._wiki_login_url(), status_code=303)
        for name, value in SECURITY_HEADERS.items():
            response.headers[name] = value
        self._set_cookie(response, LOGIN_COOKIE, binding, LOGIN_STATE_TTL)
        # Read by Wiki.js (server side after OIDC, client side after the local
        # login form), so not HttpOnly and on the root path. Written by hand:
        # Starlette would quote the value because of the '/', and Wiki.js only
        # accepts values starting with '/'. The state is URL-safe base64.
        redirect_cookie = (
            f"loginRedirect={self.base}/auth/callback/{state}; Max-Age={LOGIN_STATE_TTL}; "
            "Path=/; SameSite=Lax" + ("; Secure" if self.secure else "")
        )
        response.headers.append("set-cookie", redirect_cookie)
        return response

    async def callback(self, request: Request) -> Response:
        state = request.path_params["state"]
        binding = request.cookies.get(LOGIN_COOKIE, "")
        next_path = await self.store.consume_login_state(state, binding)
        if next_path is None:
            return self._error(
                "This login link has expired or was started in another browser."
            )

        jwt = request.cookies.get("jwt")
        if not jwt:
            return self._error("Wiki.js did not sign you in.")
        try:
            claims = wiki_jwt.payload(jwt)
        except WikiError:
            return self._error("Wiki.js returned an unreadable session.")
        # Only a JWT from this very login counts, so the IdP was really consulted
        if (
            int(claims.get("iat", 0))
            < self._now() - LOGIN_STATE_TTL - FRESH_LOGIN_SLACK
        ):
            return self._error(
                "Wiki.js returned an old session instead of a new login."
            )

        try:
            async with WikiJSClient(self.config, jwt) as client:
                profile = await client.get_profile()
                jwt = client.jwt
        except WikiError:
            logger.warning("Login callback: Wiki.js did not accept the session")
            return self._error("Wiki.js did not accept the session.")
        if not profile.get("id"):
            return self._error("Wiki.js did not accept the session.")

        user_id = await self.store.upsert_login(jwt, profile)
        session_id = await self.store.create_web_session(user_id, WEB_SESSION_TTL)
        logger.info(f"Login for wiki user {user_id}")

        response = RedirectResponse(next_path, status_code=303)
        self._clear_cookie(response, LOGIN_COOKIE)
        self._set_cookie(response, SESSION_COOKIE, session_id, WEB_SESSION_TTL)
        return response

    async def logout(self, request: Request) -> Response:
        session, _ = await self._form_session(request)
        if session is None:
            return self._redirect_to_login()
        await self.store.delete_web_session(request.cookies[SESSION_COOKIE])
        response = _page(
            "Signed out",
            "<p>You are signed out of this page. Your connected apps keep their "
            "access until you disconnect them.</p>"
            f"<p><a href='{self.base}/apps'>Sign in again</a></p>",
        )
        self._clear_cookie(response, SESSION_COOKIE)
        return response

    # ------------------------------------------------------------------
    # Connected apps
    # ------------------------------------------------------------------

    async def apps_page(self, request: Request) -> Response:
        session = await self._session(request)
        if session is None:
            return self._redirect_to_login()
        now = self._now()
        relogin_at = session.login_at + self.config.session_max_age
        jwt_dies_at = session.jwt_exp + self.config.token_renewal
        csrf = html.escape(session.csrf_secret)

        body = (
            f"<p>Signed in as <strong>{html.escape(session.name)}</strong> "
            f"({html.escape(session.email)}).</p>"
        )
        notes = [
            "Your apps act as you in the wiki until "
            f"<strong>{_fmt(relogin_at)}</strong>; after that they ask you to sign "
            "in again."
        ]
        if relogin_at - now < WARN_BEFORE:
            notes.append("<strong>That is soon.</strong>")
        if jwt_dies_at < relogin_at:
            notes.append(
                f"If none of your apps is used before {_fmt(jwt_dies_at)}, they ask "
                "you to sign in again sooner."
            )
        notes.append(
            "Signing out of the wiki does not disconnect apps; disconnect them below."
        )
        body += f"<p class='note'>{' '.join(notes)}</p>"

        command = f"claude mcp add --transport http wikijs {self.config.mcp_url}"
        body += (
            "<h2>Connect an app</h2>"
            "<p>Add this address as an MCP server (or custom connector) in your app; "
            "it then asks you to sign in here:</p>"
            f"<pre>{html.escape(self.config.mcp_url)}</pre>"
            f"<p>For Claude Code:</p><pre>{html.escape(command)}</pre>"
        )

        body += "<h2>Connected apps</h2>"
        grants = await self.store.list_oauth_grants(session.wiki_user_id)
        if grants:
            rows = ""
            for grant in grants:
                name, hosts = client_display(grant["client_info"])
                rows += (
                    f"<tr><td>{html.escape(name)}</td><td>{html.escape(hosts)}</td>"
                    f"<td>{_fmt(grant['since'])}</td>"
                    f"<td>{_fmt(grant['last_refresh'])}</td><td>"
                    f"<form class='inline' method='post' action='{self.base}/apps/disconnect'>"
                    f"<input type='hidden' name='csrf' value='{csrf}'>"
                    f"<input type='hidden' name='client_id' value='{html.escape(grant['client_id'])}'>"
                    "<button type='submit'>Disconnect</button></form></td></tr>"
                )
            body += (
                "<table><tr><th>App</th><th>Redirects to</th><th>Connected</th>"
                f"<th>Last refreshed</th><th></th></tr>{rows}</table>"
            )
        else:
            body += "<p>No apps are connected.</p>"

        body += (
            f"<h2>Sign out</h2><form method='post' action='{self.base}/logout'>"
            f"<input type='hidden' name='csrf' value='{csrf}'>"
            "<button type='submit'>Sign out of this page</button></form>"
        )
        return _page("Wiki MCP apps", body)

    async def disconnect_app(self, request: Request) -> Response:
        session, form = await self._form_session(request)
        if session is None:
            return self._redirect_to_login()
        client_id = str(form.get("client_id", ""))
        await self.store.revoke_oauth_grant(session.wiki_user_id, client_id)
        logger.info(
            f"OAuth app {client_id} disconnected by wiki user {session.wiki_user_id}"
        )
        return RedirectResponse(f"{self.base}/apps", status_code=303)

    # ------------------------------------------------------------------
    # OAuth consent (fase 5)
    # ------------------------------------------------------------------

    async def _pending(self, pending_id: str):
        """(client_id, client_info, params) of a pending authorization, or None."""
        pending = await self.store.get_oauth_pending(pending_id)
        if pending is None:
            return None
        client_id, params = pending
        client_info = await self.store.get_oauth_client(client_id)
        if client_info is None:
            return None
        return client_id, client_info, AuthorizationParams.model_validate_json(params)

    async def consent(self, request: Request) -> Response:
        pending_id = request.path_params["pending_id"]
        pending = await self._pending(pending_id)
        if pending is None:
            return self._error(
                "This authorization request has expired. Start connecting the app again."
            )
        session = await self._session(request)
        if session is None:
            return RedirectResponse(
                f"{self.base}/login?next={self.base}/oauth/consent/{pending_id}",
                status_code=303,
            )
        _, client_info, params = pending
        name, _ = client_display(client_info)
        redirect = urlsplit(str(params.redirect_uri))
        csrf = html.escape(session.csrf_secret)
        abilities = (
            "read every wiki page you can read"
            if self.config.read_only
            else "read and change every wiki page you can read and change"
        )
        body = (
            f"<p>Signed in as <strong>{html.escape(session.name)}</strong> "
            f"({html.escape(session.email)}).</p>"
            f"<p><strong>{html.escape(name)}</strong> wants to act as you in the wiki: "
            f"it can {abilities}.</p>"
            f"<p class='note'>After you allow it, you are sent to "
            f"<strong>{html.escape(redirect.scheme)}://{html.escape(redirect.netloc)}</strong>. "
            "Only continue if you just started connecting this app yourself and "
            "recognise that address.</p>"
            f"<p>The app keeps access until you disconnect it on the "
            f"<a href='{self.base}/apps'>apps page</a>, or until "
            f"{_fmt(session.login_at + self.config.session_max_age)} unless you sign "
            "in again.</p>"
            f"<form method='post' action='{self.base}/oauth/consent/{html.escape(pending_id)}'>"
            f"<input type='hidden' name='csrf' value='{csrf}'>"
            "<button type='submit' name='decision' value='allow'>Allow</button> "
            "<button type='submit' name='decision' value='deny'>Deny</button></form>"
        )
        # Allow/Deny redirect to the app; the CSP must allow that destination
        return _page(
            "Connect an app to the wiki",
            body,
            form_targets=(f"{redirect.scheme}://{redirect.netloc}",),
        )

    async def decide(self, request: Request) -> Response:
        pending_id = request.path_params["pending_id"]
        session, form = await self._form_session(request)
        if session is None:
            return self._redirect_to_login()
        pending = await self._pending(pending_id)
        # Single use: whoever deletes it first decides
        if pending is None or not await self.store.delete_oauth_pending(pending_id):
            return self._error("This authorization request has expired.")
        client_id, _, params = pending

        if form.get("decision") != "allow":
            target = construct_redirect_uri(
                str(params.redirect_uri), error="access_denied", state=params.state
            )
            return RedirectResponse(target, status_code=303)

        code, _ = await self.store.create_oauth_code(
            client_id, session.wiki_user_id, params.model_dump_json()
        )
        logger.info(
            f"OAuth app {client_id} authorized by wiki user {session.wiki_user_id}"
        )
        target = construct_redirect_uri(
            str(params.redirect_uri), code=code, state=params.state
        )
        return RedirectResponse(target, status_code=303)
