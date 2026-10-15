"""Tests for the login flow and token management pages."""

import re
import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from mcp.server import FastMCP

from tests.conftest import TEST_FERNET_KEY
from tests.helpers import make_jwt
from wikijs_mcp.errors import WikiAuthRevoked
from wikijs_mcp.store import Store
from wikijs_mcp.web import LOGIN_COOKIE, SESSION_COOKIE, WebRoutes

PROFILE = {"id": 3, "name": "Lezer A", "email": "a@example.com", "groups": ["lezers"]}


@pytest.fixture
async def store(tmp_path):
    async with Store(str(tmp_path / "db.sqlite"), TEST_FERNET_KEY, 30 * 86400) as store:
        yield store


@pytest.fixture
def routes(mock_wiki_config, store):
    return WebRoutes(mock_wiki_config, store)


@pytest.fixture
async def http(routes):
    app = FastMCP("test")
    routes.register(app)
    transport = httpx.ASGITransport(app=app.streamable_http_app())
    async with httpx.AsyncClient(
        transport=transport, base_url="https://wiki.example.com"
    ) as client:
        yield client


@pytest.fixture
def wiki():
    """The Wiki.js client used by the login callback."""
    with patch("wikijs_mcp.web.WikiJSClient") as client_class:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.get_profile.return_value = PROFILE

        def create(config, jwt, *args):
            instance.jwt = jwt  # a renewed JWT would replace this
            return instance

        client_class.side_effect = create
        yield instance


def set_cookies(response):
    return response.headers.get_list("set-cookie")


async def start_login(http, next_path=None):
    params = {"next": next_path} if next_path else None
    response = await http.get("/mcp/login", params=params)
    state = re.search(
        r"loginRedirect=/mcp/auth/callback/([\w-]+)", str(set_cookies(response))
    )
    return response, state.group(1)


async def signed_in(http, store, user_id=3):
    await store.upsert_login(make_jwt(id=user_id), {**PROFILE, "id": user_id})
    session_id = await store.create_web_session(user_id, 3600)
    http.cookies.set(SESSION_COOKIE, session_id, domain="wiki.example.com", path="/mcp")
    page = await http.get("/mcp/token")
    return re.search(r"name='csrf' value='([^']+)'", page.text).group(1)


@pytest.mark.unit
class TestLogin:
    async def test_redirects_to_wiki_strategy_with_cookies(self, http):
        response, state = await start_login(http)

        assert response.status_code == 303
        assert response.headers["location"] == "/login/oidc"
        cookies = set_cookies(response)
        login_cookie = next(c for c in cookies if c.startswith(f"{LOGIN_COOKIE}="))
        assert "HttpOnly" in login_cookie
        assert "Path=/mcp" in login_cookie
        assert "Secure" in login_cookie
        assert "Max-Age=600" in login_cookie
        redirect = next(c for c in cookies if c.startswith("loginRedirect="))
        # Unquoted: Wiki.js only follows values starting with '/'
        assert redirect.startswith(f"loginRedirect=/mcp/auth/callback/{state};")
        assert "Path=/;" in redirect
        assert "HttpOnly" not in redirect  # the local login form reads it in JS
        assert "Secure" in redirect
        assert response.headers["cache-control"] == "no-store"

    async def test_local_strategy_uses_login_form(self, mock_wiki_config, store):
        config = mock_wiki_config.model_copy(update={"strategy_key": "local"})

        assert WebRoutes(config, store)._wiki_login_url() == "/login"

    async def test_no_secure_cookies_over_http(self, mock_wiki_config, store):
        config = mock_wiki_config.model_copy(
            update={"public_url": "http://127.0.0.1:3090"}
        )

        assert WebRoutes(config, store).secure is False

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("/mcp/token", "/mcp/token"),
            ("/mcp/token?x=1", "/mcp/token?x=1"),
            (None, "/mcp/token"),
            ("", "/mcp/token"),
            ("https://evil.example/mcp/", "/mcp/token"),
            ("//evil.example/mcp/", "/mcp/token"),
            ("/other", "/mcp/token"),
            ("/mcp", "/mcp/token"),
            ("/mcp/\\evil", "/mcp/token"),
            ("/mcp/x\r\nSet-Cookie: a=b", "/mcp/token"),
            ("/mcp/https://evil", "/mcp/token"),
        ],
    )
    def test_safe_next(self, routes, value, expected):
        assert routes._safe_next(value) == expected


@pytest.mark.unit
class TestCallback:
    async def complete(self, http, state, jwt=None):
        http.cookies.set(
            "jwt", jwt or make_jwt(id=3), domain="wiki.example.com", path="/"
        )
        return await http.get(f"/mcp/auth/callback/{state}")

    async def test_success(self, http, store, wiki):
        _, state = await start_login(http, "/mcp/token?welcome=1")

        response = await self.complete(http, state)

        assert response.status_code == 303
        assert response.headers["location"] == "/mcp/token?welcome=1"
        cookies = set_cookies(response)
        session_cookie = next(c for c in cookies if c.startswith(f"{SESSION_COOKIE}="))
        assert "HttpOnly" in session_cookie and "Path=/mcp" in session_cookie
        assert "Max-Age=3600" in session_cookie
        assert any(c.startswith(f'{LOGIN_COOKIE}=""') for c in cookies)
        session_id = session_cookie.split(";")[0].split("=", 1)[1]
        assert (await store.get_web_session(session_id)).wiki_user_id == 3

    async def test_state_is_single_use(self, http, wiki):
        _, state = await start_login(http)
        await self.complete(http, state)

        assert (await self.complete(http, state)).status_code == 400

    async def test_state_bound_to_browser(self, http, routes, wiki):
        _, state = await start_login(http)
        http.cookies.set(
            LOGIN_COOKIE, "other-browser", domain="wiki.example.com", path="/mcp"
        )

        response = await self.complete(http, state)

        assert response.status_code == 400
        assert "another browser" in response.text

    async def test_unknown_state(self, http, wiki):
        assert (await self.complete(http, "nope")).status_code == 400

    async def test_no_jwt_cookie(self, http, wiki):
        _, state = await start_login(http)

        response = await http.get(f"/mcp/auth/callback/{state}")

        assert response.status_code == 400
        assert "did not sign you in" in response.text

    async def test_old_jwt_is_not_a_login(self, http, wiki):
        """An old wiki cookie must not bypass the IdP."""
        _, state = await start_login(http)

        response = await self.complete(
            http, state, make_jwt(id=3, iat=int(time.time()) - 3600)
        )

        assert response.status_code == 400
        assert "old session" in response.text
        wiki.get_profile.assert_not_called()

    @pytest.mark.parametrize(
        "profile_effect", [{"side_effect": WikiAuthRevoked("x")}, {"return_value": {}}]
    )
    async def test_wiki_rejects_jwt(self, http, store, wiki, profile_effect):
        wiki.get_profile = AsyncMock(**profile_effect)
        _, state = await start_login(http)

        response = await self.complete(http, state)

        assert response.status_code == 400
        assert "did not accept" in response.text

    async def test_login_keeps_existing_tokens(self, http, store, wiki):
        await store.upsert_login(make_jwt(id=3), PROFILE)
        _, token = await store.create_token(3, "laptop", 3600)
        new_jwt = make_jwt(id=3, expires_in=7200)
        _, state = await start_login(http)

        await self.complete(http, state, new_jwt)

        assert (await store.get_user_for_token(token)).jwt == new_jwt


@pytest.mark.unit
class TestTokenPage:
    async def test_requires_session(self, http):
        response = await http.get("/mcp/token")

        assert response.status_code == 303
        assert response.headers["location"] == "/mcp/login?next=/mcp/token"

    async def test_page(self, http, store):
        await signed_in(http, store)

        response = await http.get("/mcp/token")

        assert response.status_code == 200
        assert "Lezer A" in response.text
        assert "<option value='90' selected>" in response.text
        assert "does not revoke these tokens" in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]

    async def test_ttl_choices_respect_maximum(self, mock_wiki_config, store):
        config = mock_wiki_config.model_copy(
            update={"pat_max_ttl": 30 * 86400, "pat_default_ttl": 14 * 86400}
        )

        assert WebRoutes(config, store)._ttl_choices() == [7, 14, 30]

    async def test_create_token(self, http, store):
        csrf = await signed_in(http, store)

        response = await http.post(
            "/mcp/token",
            data={"csrf": csrf, "name": "laptop", "ttl_days": "30"},
            headers={"Origin": "https://wiki.example.com"},
        )

        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        token = re.search(r"wikimcp_[\w-]+", response.text).group(0)
        assert (
            "claude mcp add --transport http wikijs https://wiki.example.com/mcp/"
            in (response.text)
        )
        user = await store.get_user_for_token(token)
        assert user.wiki_user_id == 3
        assert user.token_expires_at - time.time() == pytest.approx(30 * 86400, abs=5)
        listed = await http.get("/mcp/token")
        assert "laptop" in listed.text
        assert token not in listed.text

    @pytest.mark.parametrize(
        "data,headers",
        [
            ({"csrf": "wrong", "name": "x", "ttl_days": "30"}, {}),
            ({"name": "x", "ttl_days": "30"}, {}),
            (
                {"csrf": None, "name": "x", "ttl_days": "30"},
                {"Origin": "https://evil.example"},
            ),
        ],
    )
    async def test_create_token_needs_csrf_and_origin(self, http, store, data, headers):
        csrf = await signed_in(http, store)
        if "csrf" in data and data["csrf"] is None:
            data["csrf"] = csrf

        response = await http.post("/mcp/token", data=data, headers=headers)

        assert response.status_code == 303
        assert await store.list_tokens(3) == []

    @pytest.mark.parametrize(
        "name,ttl", [("", "30"), ("x" * 101, "30"), ("x", "1000"), ("x", "abc")]
    )
    async def test_create_token_validation(self, http, store, name, ttl):
        csrf = await signed_in(http, store)

        response = await http.post(
            "/mcp/token", data={"csrf": csrf, "name": name, "ttl_days": ttl}
        )

        assert response.status_code == 400
        assert await store.list_tokens(3) == []

    async def test_revoke(self, http, store):
        csrf = await signed_in(http, store)
        token_id, token = await store.create_token(3, "laptop", 3600)

        response = await http.post(
            "/mcp/token/revoke", data={"csrf": csrf, "token_id": str(token_id)}
        )

        assert response.status_code == 303
        assert await store.get_user_for_token(token) is None

    async def test_cannot_revoke_other_users_token(self, http, store):
        await store.upsert_login(make_jwt(id=4), {**PROFILE, "id": 4})
        other_id, other_token = await store.create_token(4, "theirs", 3600)
        csrf = await signed_in(http, store, user_id=3)

        await http.post(
            "/mcp/token/revoke", data={"csrf": csrf, "token_id": str(other_id)}
        )

        assert await store.get_user_for_token(other_token) is not None

    async def test_logout(self, http, store):
        csrf = await signed_in(http, store)
        _, token = await store.create_token(3, "laptop", 3600)

        response = await http.post("/mcp/logout", data={"csrf": csrf})

        assert response.status_code == 200
        assert "keep working" in response.text
        assert (await http.get("/mcp/token")).status_code == 303
        assert await store.get_user_for_token(token) is not None
