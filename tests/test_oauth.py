"""Tests for the OAuth authorization server (fase 5), through the SDK's handlers."""

import base64
import hashlib
import re
import secrets
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from tests.conftest import TEST_FERNET_KEY
from tests.helpers import make_jwt
from wikijs_mcp.auth import StoreTokenVerifier
from wikijs_mcp.oauth import _allowed_redirect_uri, client_display, redirect_origin
from wikijs_mcp.server import build_http_app
from wikijs_mcp.store import OAUTH_CODE_TTL, OAUTH_PENDING_TTL, Store
from wikijs_mcp.web import SESSION_COOKIE

BASE = "https://wiki.example.com"
REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PROFILE = {"id": 3, "name": "Lezer A", "email": "a@example.com"}
MAX_AGE = 30 * 86400
RENEWAL = 14 * 86400


class Clock:
    def __init__(self):
        import time

        self.now = time.time()

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
async def store(tmp_path, clock):
    async with Store(str(tmp_path / "db.sqlite"), TEST_FERNET_KEY, MAX_AGE, clock) as s:
        yield s


@pytest.fixture
def oauth_config(mock_wiki_config):
    return mock_wiki_config


@pytest.fixture
async def http(oauth_config, store):
    app = build_http_app(oauth_config, store)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url=BASE
    ) as client:
        yield client


def pkce():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def register(http, redirect=REDIRECT, name="Claude"):
    response = await http.post(
        "/mcp/oauth/register",
        json={
            "redirect_uris": [redirect],
            "client_name": name,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["client_id"]


async def sign_in(http, store, user_id=3):
    await store.upsert_login(make_jwt(id=user_id), {**PROFILE, "id": user_id})
    session_id = await store.create_web_session(user_id, 3600)
    http.cookies.set(SESSION_COOKIE, session_id, domain="wiki.example.com", path="/mcp")


async def authorize(http, client_id, challenge, state="xyz"):
    response = await http.get(
        "/mcp/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": "wiki",
        },
    )
    assert response.status_code == 302, response.text
    return urlsplit(response.headers["location"]).path


async def consent(http, consent_path, decision="allow"):
    page = await http.get(consent_path)
    csrf = re.search(r"name='csrf' value='([^']+)'", page.text).group(1)
    # As a browser does it: with the page's Origin
    response = await http.post(
        consent_path,
        data={"csrf": csrf, "decision": decision},
        headers={"Origin": BASE},
    )
    return response, parse_qs(urlsplit(response.headers.get("location", "")).query)


async def token_request(http, **data):
    return await http.post("/mcp/oauth/token", data=data)


async def full_flow(http, store):
    """Register, authorize, consent and exchange; returns (client_id, tokens)."""
    client_id = await register(http)
    verifier, challenge = pkce()
    consent_path = await authorize(http, client_id, challenge)
    await sign_in(http, store)
    _, query = await consent(http, consent_path)
    response = await token_request(
        http,
        grant_type="authorization_code",
        code=query["code"][0],
        redirect_uri=REDIRECT,
        client_id=client_id,
        code_verifier=verifier,
    )
    assert response.status_code == 200, response.text
    return client_id, response.json()


@pytest.mark.unit
class TestMetadata:
    async def test_protected_resource(self, http):
        response = await http.get("/.well-known/oauth-protected-resource/mcp/")

        assert response.json()["resource"] == f"{BASE}/mcp/"
        assert response.json()["authorization_servers"] == [f"{BASE}/mcp/oauth"]

    @pytest.mark.parametrize(
        "path",
        [
            "/.well-known/oauth-authorization-server/mcp/oauth",
            "/mcp/oauth/.well-known/oauth-authorization-server",
        ],
    )
    async def test_authorization_server(self, http, path):
        metadata = (await http.get(path)).json()

        assert metadata["issuer"] == f"{BASE}/mcp/oauth"
        assert metadata["authorization_endpoint"] == f"{BASE}/mcp/oauth/authorize"
        assert metadata["token_endpoint"] == f"{BASE}/mcp/oauth/token"
        assert metadata["registration_endpoint"] == f"{BASE}/mcp/oauth/register"
        assert metadata["revocation_endpoint"] == f"{BASE}/mcp/oauth/revoke"
        assert metadata["code_challenge_methods_supported"] == ["S256"]

    async def test_www_authenticate_points_to_metadata(self, http):
        response = await http.post("/mcp/", json={})

        assert response.status_code == 401
        assert (
            f'resource_metadata="{BASE}/.well-known/oauth-protected-resource/mcp/"'
            in response.headers["www-authenticate"]
        )

    async def test_no_personal_token_page(self, http):
        """Only OAuth: <base>/token is gone; the OAuth endpoint is <base>/oauth/token."""
        assert (await http.get("/mcp/token")).status_code == 404


@pytest.mark.unit
class TestRegistration:
    @pytest.mark.parametrize(
        "uri,allowed",
        [
            ("https://claude.ai/api/mcp/auth_callback", True),
            ("http://localhost:33418/callback", True),
            ("http://127.0.0.1:9999/callback", True),
            ("http://[::1]:9999/callback", True),
            ("http://evil.example/callback", False),
            ("https://claude.ai/cb#fragment", False),
            ("javascript:alert(1)", False),
            ("myapp://callback", False),
            # User info makes the real host hard to see
            ("https://claude.ai@evil.example/cb", False),
            ("https://user:pass@claude.ai/cb", False),
            ("http://localhost@evil.example/cb", False),
        ],
    )
    def test_redirect_uri_policy(self, uri, allowed):
        assert _allowed_redirect_uri(uri) is allowed

    async def test_rejects_user_info_in_redirect(self, http):
        response = await http.post(
            "/mcp/oauth/register",
            json={
                "redirect_uris": ["https://claude.ai@evil.example/cb"],
                "client_name": "Claude",
            },
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_redirect_uri"

    @pytest.mark.parametrize(
        "uri,origin",
        [
            ("https://claude.ai/api/mcp/auth_callback", "https://claude.ai"),
            ("https://claude.ai@evil.example/cb", "https://evil.example"),
            ("http://localhost:33418/callback", "http://localhost:33418"),
            ("http://[::1]:9999/callback", "http://[::1]:9999"),
        ],
    )
    def test_redirect_origin_shows_real_host(self, uri, origin):
        assert redirect_origin(uri) == origin

    def test_client_display_shows_real_host(self):
        """Clients stored before user info was refused are shown by their real host."""
        info = (
            '{"client_id": "x", "redirect_uris": ["https://claude.ai@evil.example/cb"]}'
        )

        assert client_display(info) == ("x", "evil.example")

    async def test_rejects_foreign_http_redirect(self, http):
        response = await http.post(
            "/mcp/oauth/register",
            json={"redirect_uris": ["http://evil.example/cb"], "client_name": "evil"},
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_redirect_uri"


@pytest.mark.unit
class TestAuthorizationFlow:
    async def test_consent_requires_wiki_login(self, http):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])

        response = await http.get(consent_path)

        assert response.status_code == 303
        assert response.headers["location"] == f"/mcp/login?next={consent_path}"

    async def test_consent_page_names_app_and_redirect(self, http, store):
        client_id = await register(http, name="<b>Claude</b>")
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)

        page = await http.get(consent_path)

        assert "calling itself <strong>&lt;b&gt;Claude&lt;/b&gt;</strong>" in page.text
        assert "https://claude.ai" in page.text
        assert "read every wiki page you can read" in page.text
        assert page.headers["x-frame-options"] == "DENY"
        # Browsers apply form-action to the redirect after Allow/Deny
        assert (
            "form-action 'self' https://claude.ai;"
            in (page.headers["content-security-policy"])
        )

    async def test_full_flow_issues_working_tokens(self, http, store):
        client_id, tokens = await full_flow(http, store)

        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 3600
        assert tokens["scope"] == "wiki"
        access = await StoreTokenVerifier(store, RENEWAL).verify_token(
            tokens["access_token"]
        )
        assert access.subject == "3"
        assert access.client_id == client_id

    async def test_deny(self, http, store):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1], state="s1")
        await sign_in(http, store)

        response, query = await consent(http, consent_path, decision="deny")

        assert response.headers["location"].startswith(REDIRECT)
        assert query == {"error": ["access_denied"], "state": ["s1"]}

    async def test_consent_is_single_use(self, http, store):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        page = await http.get(consent_path)
        csrf = re.search(r"name='csrf' value='([^']+)'", page.text).group(1)
        await http.post(consent_path, data={"csrf": csrf, "decision": "allow"})

        again = await http.post(consent_path, data={"csrf": csrf, "decision": "allow"})

        assert again.status_code == 400

    async def test_consent_needs_csrf(self, http, store):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)

        response = await http.post(consent_path, data={"decision": "allow"})

        assert response.status_code == 303
        assert "/mcp/login" in response.headers["location"]

    @pytest.mark.parametrize(
        "fetch_metadata",
        [
            # fetch() from a script in a wiki page
            {"Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"},
            # form.submit() without a click
            {
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
            },
            # a form posted into a hidden iframe
            {
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "iframe",
                "Sec-Fetch-User": "?1",
            },
            # from another site
            {
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
            },
        ],
    )
    async def test_consent_needs_a_click(self, http, store, fetch_metadata):
        """A script on the wiki's origin can read the CSRF token, but cannot fake
        a user's click; the request stays pending for the real user."""
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        page = await http.get(consent_path)
        csrf = re.search(r"name='csrf' value='([^']+)'", page.text).group(1)

        response = await http.post(
            consent_path,
            data={"csrf": csrf, "decision": "allow"},
            headers={"Origin": BASE, **fetch_metadata},
        )

        assert response.status_code == 403
        assert "location" not in response.headers
        assert (await http.get(consent_path)).status_code == 200

    async def test_consent_by_click(self, http, store):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        page = await http.get(consent_path)
        csrf = re.search(r"name='csrf' value='([^']+)'", page.text).group(1)

        response = await http.post(
            consent_path,
            data={"csrf": csrf, "decision": "allow"},
            headers={
                "Origin": BASE,
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-User": "?1",
            },
        )

        assert response.status_code == 303
        assert "code=" in response.headers["location"]

    async def test_pending_request_expires(self, http, store, clock):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        clock.now += OAUTH_PENDING_TTL

        assert (await http.get(consent_path)).status_code == 400

    async def test_wrong_pkce_verifier(self, http, store):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        _, query = await consent(http, consent_path)

        response = await token_request(
            http,
            grant_type="authorization_code",
            code=query["code"][0],
            redirect_uri=REDIRECT,
            client_id=client_id,
            code_verifier=pkce()[0],
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    async def test_code_is_single_use_and_expires(self, http, store, clock):
        client_id = await register(http)
        verifier, challenge = pkce()
        consent_path = await authorize(http, client_id, challenge)
        await sign_in(http, store)
        _, query = await consent(http, consent_path)
        exchange = {
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "redirect_uri": REDIRECT,
            "client_id": client_id,
            "code_verifier": verifier,
        }

        assert (await token_request(http, **exchange)).status_code == 200
        assert (await token_request(http, **exchange)).status_code == 400

        verifier, challenge = pkce()
        consent_path = await authorize(http, client_id, challenge)
        _, query = await consent(http, consent_path)
        clock.now += OAUTH_CODE_TTL + 1
        expired = {**exchange, "code": query["code"][0], "code_verifier": verifier}
        assert (await token_request(http, **expired)).status_code == 400

    async def test_code_bound_to_client(self, http, store):
        client_id = await register(http)
        other_client = await register(http, name="Other")
        verifier, challenge = pkce()
        consent_path = await authorize(http, client_id, challenge)
        await sign_in(http, store)
        _, query = await consent(http, consent_path)

        response = await token_request(
            http,
            grant_type="authorization_code",
            code=query["code"][0],
            redirect_uri=REDIRECT,
            client_id=other_client,
            code_verifier=verifier,
        )

        assert response.status_code == 400


@pytest.mark.unit
class TestRefreshAndRevoke:
    async def test_refresh_rotates(self, http, store):
        client_id, tokens = await full_flow(http, store)
        refresh = {
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_id,
        }

        first = await token_request(http, **refresh)
        reused = await token_request(http, **refresh)

        assert first.status_code == 200
        assert first.json()["refresh_token"] != tokens["refresh_token"]
        assert reused.status_code == 400
        assert reused.json()["error"] == "invalid_grant"

    async def test_refresh_stops_at_session_max_age(self, http, store, clock):
        client_id, tokens = await full_flow(http, store)
        clock.now += MAX_AGE

        response = await token_request(
            http,
            grant_type="refresh_token",
            refresh_token=tokens["refresh_token"],
            client_id=client_id,
        )

        assert response.status_code == 400

    async def test_refresh_stops_when_wiki_session_lapsed(self, http, store, clock):
        """Unused for longer than the renewal period: the stored Wiki.js session is
        dead, so refreshing fails and the client signs the user in again."""
        client_id, tokens = await full_flow(http, store)
        clock.now += 1800 + RENEWAL + 1  # past the JWT's exp plus renewal period

        response = await token_request(
            http,
            grant_type="refresh_token",
            refresh_token=tokens["refresh_token"],
            client_id=client_id,
        )

        assert response.status_code == 400
        assert response.json()["error"] == "invalid_grant"

    async def test_revoke_ends_the_grant(self, http, store):
        client_id, tokens = await full_flow(http, store)

        response = await http.post(
            "/mcp/oauth/revoke",
            data={
                "token": tokens["refresh_token"],
                "client_id": client_id,
                "client_secret": "",  # the SDK requires the field, even when empty
            },
        )

        assert response.status_code == 200
        assert (
            await StoreTokenVerifier(store, RENEWAL).verify_token(
                tokens["access_token"]
            )
            is None
        )
        refreshed = await token_request(
            http,
            grant_type="refresh_token",
            refresh_token=tokens["refresh_token"],
            client_id=client_id,
        )
        assert refreshed.status_code == 400


@pytest.mark.unit
class TestAppsPage:
    async def test_lists_app(self, http, store):
        await full_flow(http, store)

        page = (await http.get("/mcp/apps")).text

        assert "Connected apps" in page
        assert "Claude" in page and "claude.ai" in page

    async def test_disconnect(self, http, store):
        client_id, tokens = await full_flow(http, store)
        page = (await http.get("/mcp/apps")).text
        csrf = re.search(r"name='csrf' value='([^']+)'", page).group(1)

        response = await http.post(
            "/mcp/apps/disconnect", data={"csrf": csrf, "client_id": client_id}
        )

        assert response.status_code == 303
        assert (
            await StoreTokenVerifier(store, RENEWAL).verify_token(
                tokens["access_token"]
            )
            is None
        )
        assert "No apps are connected" in (await http.get("/mcp/apps")).text


@pytest.mark.unit
class TestPurge:
    async def test_unused_registrations_are_removed(self, http, store, clock):
        unused = await register(http, name="Unused")
        used, _ = await full_flow(http, store)
        clock.now += 86400

        await store.purge_expired()

        assert await store.get_oauth_client(unused) is None
        assert await store.get_oauth_client(used) is not None

    async def test_expired_pending_and_codes_are_removed(self, http, store, clock):
        client_id = await register(http)
        consent_path = await authorize(http, client_id, pkce()[1])
        await sign_in(http, store)
        await consent(http, await authorize(http, client_id, pkce()[1]))
        clock.now += OAUTH_PENDING_TTL

        await store.purge_expired()

        for table in ("oauth_pending", "oauth_codes"):
            async with store.db.execute(f"SELECT COUNT(*) FROM {table}") as cursor:
                assert (await cursor.fetchone())[0] == 0
        assert consent_path
