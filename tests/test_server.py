"""Tests for MCP server functionality."""

import json
import logging
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.auth.provider import AccessToken
from mcp.server.fastmcp.exceptions import ToolError
from starlette.testclient import TestClient

from tests.conftest import TEST_FERNET_KEY
from tests.helpers import make_jwt
from wikijs_mcp import auth, wiki_jwt
from wikijs_mcp.auth import (
    SessionUser,
    StoreTokenVerifier,
    static_user_source,
    token_user_source,
)
from wikijs_mcp.errors import (
    WikiAuthExpired,
    WikiAuthRevoked,
    WikiError,
    WikiForbidden,
    WikiNotFound,
)
from wikijs_mcp.server import WikiJSMCPServer
from wikijs_mcp.store import Store

READ_TOOLS = {
    "wiki_search",
    "wiki_get_page",
    "wiki_list_pages",
    "wiki_get_tree",
    "wiki_list_tags",
    "wiki_get_site_info",
    "wiki_get_history",
    "wiki_get_version",
    "wiki_whoami",
}
WRITE_TOOLS = {
    "wiki_create_page",
    "wiki_update_page",
    "wiki_delete_page",
    "wiki_move_page",
}

META = {
    "id": 3,
    "path": "docs/algemeen",
    "locale": "en",
    "title": "Algemene docs",
    "description": "Beschrijving",
    "contentType": "markdown",
    "isPublished": True,
    "isPrivate": False,
    "createdAt": "2026-01-01",
    "updatedAt": "2026-02-01",
    "tags": ["algemeen"],
}
SOURCE = {
    "path": "docs/algemeen",
    "locale": "en",
    "page_id": 3,
    "content": "# Inhoud\n\nTekst met ballon.",
    "effective_permissions": {
        "pages": {"read": True, "write": False},
        "source": {"read": True},
        "history": {"read": False},
    },
}


def text_of(result):
    """Extract text from an MCP tool response (old and new formats)."""
    if isinstance(result, tuple):
        content, _ = result
        return content[0].text
    return result[0].text


@pytest.fixture
def user():
    return SessionUser(3, "lezer-a@example.com", make_jwt(), AsyncMock())


@pytest.fixture
def write_config(mock_wiki_config):
    return mock_wiki_config.model_copy(update={"read_only": False})


@pytest.fixture
def client():
    """The WikiJSClient the server creates for each tool call."""
    with patch("wikijs_mcp.server.WikiJSClient") as client_class:
        instance = AsyncMock()
        instance.__aenter__.return_value = instance
        instance.__aexit__.return_value = None
        instance.get_page_meta.return_value = META
        instance.get_page_source.return_value = SOURCE
        instance.resolve_page_id.return_value = 3
        instance.get_default_locale.return_value = "en"
        client_class.return_value = instance
        instance.client_class = client_class
        yield instance


def make_server(config, user):
    async def source():
        return user

    return WikiJSMCPServer(config, user_source=source)


@pytest.fixture
def server(mock_wiki_config, user):
    return make_server(mock_wiki_config, user)


@pytest.fixture
def write_server(write_config, user):
    return make_server(write_config, user)


@pytest.mark.integration
class TestSetup:
    async def test_read_only_registers_only_read_tools(self, server):
        tools = await server.app.list_tools()

        assert {tool.name for tool in tools} == READ_TOOLS

    async def test_write_tools_when_not_read_only(self, write_server):
        tools = await write_server.app.list_tools()

        assert {tool.name for tool in tools} == READ_TOOLS | WRITE_TOOLS

    async def test_delete_is_marked_destructive(self, write_server):
        tools = {tool.name: tool for tool in await write_server.app.list_tools()}

        assert tools["wiki_delete_page"].annotations.destructiveHint is True

    def test_instructions(self, server, write_server):
        instructions = server.app.instructions

        assert "numeric ID (from list/search results)" not in instructions
        assert "read:source" in instructions
        assert "wiki_whoami" in instructions
        assert "does not exist" in instructions
        assert "edits" not in instructions
        assert "edits" in write_server.app.instructions

    def test_ignores_unreadable_env_file_in_working_dir(
        self, mock_wiki_config, tmp_path, monkeypatch
    ):
        """The root-only .env for systemd must not crash the service user."""
        env_file = tmp_path / ".env"
        env_file.write_text("FASTMCP_DEBUG=true\n")
        env_file.chmod(0)
        monkeypatch.chdir(tmp_path)

        server = WikiJSMCPServer(mock_wiki_config)

        assert server.app.settings.debug is False

    def test_loads_config_when_not_given(self, mock_wiki_config):
        with patch("wikijs_mcp.server.WikiJSConfig.load_config") as load_config:
            load_config.return_value = mock_wiki_config

            assert WikiJSMCPServer().config == mock_wiki_config

    async def test_one_client_per_call_with_the_users_jwt(self, server, client, user):
        await server.app.call_tool("wiki_list_tags", {})

        client.client_class.assert_called_once_with(
            server.config, user.jwt, user.on_new_jwt
        )


@pytest.mark.integration
class TestReadTools:
    async def test_search(self, server, client):
        client.search_pages.return_value = [
            {
                "title": "Docs",
                "path": "docs/algemeen",
                "locale": "en",
                "description": "D",
            }
        ]

        text = text_of(
            await server.app.call_tool("wiki_search", {"query": "docs", "locale": "nl"})
        )

        assert "Found 1 pages for query 'docs'" in text
        assert "Path: docs/algemeen" in text
        assert "ID" not in text
        client.search_pages.assert_awaited_once_with("docs", 10, "nl")

    async def test_search_no_results(self, server, client):
        client.search_pages.return_value = []

        text = text_of(await server.app.call_tool("wiki_search", {"query": "niets"}))

        assert "No pages found for query: niets" in text

    async def test_get_page_by_path(self, server, client):
        text = text_of(
            await server.app.call_tool("wiki_get_page", {"path": "docs/algemeen"})
        )

        assert text.startswith("# Algemene docs")
        assert "**ID:** 3" in text
        assert "**Tags:** algemeen" in text
        assert "**Published:**" not in text
        assert text.endswith(SOURCE["content"])
        client.get_page_meta.assert_awaited_once_with(path="docs/algemeen", locale=None)
        client.get_page_source.assert_awaited_once_with("docs/algemeen", "en", None)

    async def test_get_page_by_id_and_version(self, server, client):
        text = text_of(
            await server.app.call_tool("wiki_get_page", {"id": 3, "version_id": 7})
        )

        assert "**Version:** 7" in text
        client.get_page_meta.assert_awaited_once_with(page_id=3)
        client.get_page_source.assert_awaited_once_with("docs/algemeen", "en", 7)

    async def test_get_page_metadata_only(self, server, client):
        client.get_page_meta.return_value = {**META, "isPublished": False}

        text = text_of(
            await server.app.call_tool(
                "wiki_get_page", {"path": "docs/algemeen", "metadata_only": True}
            )
        )

        assert "**Published:** no" in text
        assert "---" not in text
        client.get_page_source.assert_not_called()

    @pytest.mark.parametrize("args", [{}, {"path": "a", "id": 1}])
    async def test_get_page_validation(self, server, client, args):
        with pytest.raises(ToolError, match="'path' or 'id'|both"):
            await server.app.call_tool("wiki_get_page", args)

    async def test_get_page_not_in_list(self, server, client):
        client.get_page_meta.return_value = None

        with pytest.raises(
            ToolError, match="No access to bestaat/niet, or it does not exist"
        ):
            await server.app.call_tool("wiki_get_page", {"path": "bestaat/niet"})

    @pytest.mark.parametrize("error", [WikiForbidden("403"), WikiNotFound("302")])
    async def test_forbidden_and_missing_look_the_same(self, server, client, error):
        client.get_page_source.side_effect = error

        with pytest.raises(ToolError) as info:
            await server.app.call_tool("wiki_get_page", {"path": "geheim/plan"})

        message = str(info.value)
        assert "No access to geheim/plan, or it does not exist." in message
        assert "read:source" in message
        assert "403" not in message and "302" not in message

    async def test_list_pages(self, server, client):
        client.list_pages.return_value = [META]

        text = text_of(
            await server.app.call_tool(
                "wiki_list_pages", {"tags": ["algemeen"], "locale": "en", "limit": 5}
            )
        )

        assert "Path: docs/algemeen (ID: 3)" in text
        client.list_pages.assert_awaited_once_with(
            5,
            tags=["algemeen"],
            order_by="TITLE",
            order_by_direction="ASC",
            locale="en",
        )

    @pytest.mark.parametrize(
        "args", [{"order_by": "AUTHOR"}, {"order_by_direction": "UP"}]
    )
    async def test_list_pages_validation(self, server, client, args):
        with pytest.raises(ToolError, match="Invalid order_by"):
            await server.app.call_tool("wiki_list_pages", args)

    async def test_get_tree(self, server, client):
        client.get_page_tree.return_value = [
            {"depth": 0, "title": "docs", "isFolder": True, "path": "docs"},
            {
                "depth": 1,
                "title": "Algemeen",
                "isFolder": False,
                "path": "docs/algemeen",
            },
        ]

        text = text_of(
            await server.app.call_tool("wiki_get_tree", {"parent_path": "docs"})
        )

        assert "📁 docs/" in text
        assert "  📄 Algemeen (docs/algemeen)" in text
        client.get_page_tree.assert_awaited_once_with("docs", "ALL", None, None)

    async def test_list_tags(self, server, client):
        client.list_tags.return_value = [{"tag": "algemeen", "title": "Algemeen"}]

        text = text_of(await server.app.call_tool("wiki_list_tags", {}))

        assert "**Algemeen**" in text

    async def test_site_info_without_site_config(self, server, client):
        client.get_localization_config.return_value = {
            "locale": "nl",
            "namespacing": True,
            "namespaces": ["nl", "en"],
        }

        text = text_of(await server.app.call_tool("wiki_get_site_info", {}))

        assert "**URL:** https://wiki.example.com" in text
        assert "**Default Locale:** nl" in text
        assert "**Locale Namespaces:** nl, en" in text
        client.get_site_info.assert_not_called()

    async def test_history_by_path(self, server, client):
        client.get_page_history.return_value = {
            "trail": [{"versionId": 2, "authorName": "A", "actionType": "edit"}],
            "total": 1,
        }

        text = text_of(
            await server.app.call_tool("wiki_get_history", {"path": "docs/algemeen"})
        )

        assert "Version 2" in text
        client.resolve_page_id.assert_awaited_once_with("docs/algemeen", None)
        client.get_page_history.assert_awaited_once_with(3, 0, 100)

    async def test_history_unknown_id_does_not_reach_wikijs(self, server, client):
        """Wiki.js leaks whether an id exists through a TypeError on history."""
        client.get_page_meta.return_value = None

        with pytest.raises(ToolError, match="No access to page 99"):
            await server.app.call_tool("wiki_get_history", {"id": 99})

        client.get_page_history.assert_not_called()

    async def test_version(self, server, client):
        client.get_page_version.return_value = {
            "title": "Oud",
            "versionId": 2,
            "content": "oude tekst",
        }

        text = text_of(
            await server.app.call_tool(
                "wiki_get_version", {"path": "docs/algemeen", "version_id": 2}
            )
        )

        assert text.startswith("# Oud")
        assert text.endswith("oude tekst")
        client.get_page_version.assert_awaited_once_with(3, 2)

    async def test_whoami(self, server, client):
        client.jwt = make_jwt(permissions=["read:pages", "read:source"])
        client.get_profile.return_value = {
            "name": "Lezer A",
            "email": "a@example.com",
            "groups": ["lezers-a"],
        }

        text = text_of(await server.app.call_tool("wiki_whoami", {}))

        assert "**Name:** Lezer A" in text
        assert "**Groups:** lezers-a" in text
        assert "**Global permissions:** read:pages, read:source" in text
        assert "Effective permissions on" not in text
        client.get_page_source.assert_not_called()

    async def test_whoami_with_path(self, server, client):
        client.jwt = make_jwt()
        client.get_profile.return_value = {"name": "A", "email": "a", "groups": []}

        text = text_of(
            await server.app.call_tool("wiki_whoami", {"path": "docs/algemeen"})
        )

        assert (
            "**Effective permissions on en/docs/algemeen:** pages: read; source: read"
            in text
        )


@pytest.mark.integration
class TestWriteTools:
    async def test_create(self, write_server, client):
        client.create_page.return_value = {
            "page": {"id": 9, "path": "nieuw", "title": "N"}
        }

        text = text_of(
            await write_server.app.call_tool(
                "wiki_create_page", {"path": "nieuw", "title": "N", "content": "x"}
            )
        )

        assert "**ID:** 9" in text
        assert client.create_page.call_args.kwargs["locale"] is None

    async def test_update_with_edits(self, write_server, client):
        client.get_page_source.return_value = {**SOURCE, "content": "a b a"}
        client.update_page.return_value = {"page": {"id": 3, "title": "T", "path": "p"}}

        text = text_of(
            await write_server.app.call_tool(
                "wiki_update_page",
                {
                    "path": "docs/algemeen",
                    "edits": [{"old_text": "a", "new_text": "c"}],
                },
            )
        )

        assert "Applied 1 edit(s)" in text
        assert client.update_page.call_args.kwargs == {
            "page_id": 3,
            "content": "c b a",
            "title": None,
            "description": None,
            "tags": None,
        }

    async def test_update_full_content(self, write_server, client):
        client.update_page.return_value = {"page": {"id": 3}}

        await write_server.app.call_tool(
            "wiki_update_page", {"id": 3, "content": "nieuw", "title": "T"}
        )

        kwargs = client.update_page.call_args.kwargs
        assert kwargs["content"] == "nieuw"
        assert kwargs["title"] == "T"
        client.get_page_source.assert_not_called()

    async def test_update_old_text_missing(self, write_server, client):
        with pytest.raises(ToolError, match="old_text not found"):
            await write_server.app.call_tool(
                "wiki_update_page",
                {"path": "docs/algemeen", "edits": [{"old_text": "zeppelin"}]},
            )
        client.update_page.assert_not_called()

    @pytest.mark.parametrize(
        "args,match",
        [
            ({"path": "p", "content": "x", "edits": []}, "both 'content' and 'edits'"),
            ({"path": "p", "edits": [{"old_text": ""}]}, "non-empty 'old_text'"),
            ({"content": "x"}, "'path' or 'id'"),
        ],
    )
    async def test_update_validation(self, write_server, client, args, match):
        with pytest.raises(ToolError, match=match):
            await write_server.app.call_tool("wiki_update_page", args)

    async def test_delete(self, write_server, client):
        client.delete_page.return_value = {"responseResult": {"succeeded": True}}

        text = text_of(
            await write_server.app.call_tool(
                "wiki_delete_page", {"path": "docs/algemeen"}
            )
        )

        assert "Successfully deleted docs/algemeen (ID: 3)" in text
        client.delete_page.assert_awaited_once_with(page_id=3)

    async def test_move(self, write_server, client):
        client.move_page.return_value = {"responseResult": {"succeeded": True}}

        text = text_of(
            await write_server.app.call_tool(
                "wiki_move_page",
                {"path": "docs/algemeen", "destination_path": "docs/b"},
            )
        )

        assert "**From:** docs/algemeen (locale: en)" in text
        assert "**To:** docs/b (locale: en)" in text
        client.move_page.assert_awaited_once_with(
            page_id=3, destination_path="docs/b", destination_locale=None
        )

    async def test_move_forbidden_explains_permission(self, write_server, client):
        client.move_page.side_effect = WikiForbidden("Forbidden")

        with pytest.raises(ToolError, match="requires manage:pages"):
            await write_server.app.call_tool(
                "wiki_move_page", {"path": "docs/algemeen", "destination_path": "x"}
            )


@pytest.mark.integration
class TestErrorsAndAudit:
    async def test_expired_session(self, server, client):
        client.list_tags.side_effect = WikiAuthExpired("expired")

        with pytest.raises(ToolError, match="session has expired.*re-authenticate"):
            await server.app.call_tool("wiki_list_tags", {})

    @pytest.mark.parametrize("error", [WikiAuthExpired("x"), WikiAuthRevoked("x")])
    async def test_lost_session_is_forgotten(self, mock_wiki_config, client, error):
        """So the next request gets a 401 and the client signs in again."""
        lost = AsyncMock()
        user = SessionUser(3, "a@example.com", make_jwt(), AsyncMock(), lost)
        server = make_server(mock_wiki_config, user)
        client.list_tags.side_effect = error

        with pytest.raises(ToolError):
            await server.app.call_tool("wiki_list_tags", {})

        lost.assert_awaited_once()

    async def test_other_errors_keep_the_session(self, mock_wiki_config, client):
        lost = AsyncMock()
        user = SessionUser(3, "a@example.com", make_jwt(), AsyncMock(), lost)
        server = make_server(mock_wiki_config, user)
        client.list_tags.side_effect = WikiForbidden("x")

        with pytest.raises(ToolError):
            await server.app.call_tool("wiki_list_tags", {})

        lost.assert_not_called()

    async def test_revoked_session(self, server, client):
        client.list_tags.side_effect = WikiAuthRevoked("Unauthorized")

        with pytest.raises(ToolError, match="no longer accepts this session"):
            await server.app.call_tool("wiki_list_tags", {})

    async def test_other_wiki_error(self, server, client):
        client.list_tags.side_effect = WikiError("boom")

        with pytest.raises(ToolError, match="Wiki.js error: boom"):
            await server.app.call_tool("wiki_list_tags", {})

    async def test_no_user_source(self, mock_wiki_config, client):
        server = WikiJSMCPServer(mock_wiki_config)

        with pytest.raises(ToolError, match="session has expired"):
            await server.app.call_tool("wiki_list_tags", {})

    async def test_user_without_session(self, mock_wiki_config, client):
        async def source():
            raise WikiAuthExpired("No usable Wiki.js session")

        server = WikiJSMCPServer(mock_wiki_config, user_source=source)

        with pytest.raises(ToolError, match="session has expired"):
            await server.app.call_tool("wiki_list_tags", {})
        client.client_class.assert_not_called()

    @pytest.mark.parametrize(
        "side_effect,outcome",
        [
            (None, "ok"),
            (WikiForbidden("x"), "denied"),
            (WikiAuthRevoked("x"), "expired"),
            (WikiError("x"), "error"),
        ],
    )
    async def test_audit_log(self, server, client, user, caplog, side_effect, outcome):
        client.get_page_source.side_effect = side_effect
        caplog.set_level(logging.INFO, logger="wikijs_mcp.audit")

        try:
            await server.app.call_tool("wiki_get_page", {"path": "docs/algemeen"})
        except ToolError:
            pass

        records = [r for r in caplog.records if r.name == "wikijs_mcp.audit"]
        assert len(records) == 1
        entry = json.loads(records[0].getMessage())
        assert entry == {
            "tool": "wiki_get_page",
            "target": "docs/algemeen",
            "user_id": 3,
            "email": "lezer-a@example.com",
            "outcome": outcome,
        }
        assert user.jwt not in caplog.text
        assert SOURCE["content"] not in caplog.text


@pytest.mark.unit
class TestAuth:
    @pytest.fixture
    async def store(self, tmp_path):
        async with Store(
            str(tmp_path / "db.sqlite"), TEST_FERNET_KEY, 30 * 86400
        ) as store:
            yield store

    async def stored_user(self, store, jwt=None):
        jwt = jwt or make_jwt(id=3)
        await store.upsert_login(jwt, {"id": 3, "email": "a@example.com", "name": "A"})
        token_id, token = await store.create_token(
            3, "Claude", 3600, kind="oauth", client_id="app-1"
        )
        return jwt, token_id, token

    def verifier(self, store, clock=None):
        return StoreTokenVerifier(
            store, 14 * 86400, **({"clock": clock} if clock else {})
        )

    async def test_verifier_accepts_oauth_token(self, store):
        _, token_id, token = await self.stored_user(store)

        access = await self.verifier(store).verify_token(token)

        assert access.subject == "3"
        assert access.client_id == "app-1"
        assert access.token == token
        assert (await store.list_tokens(3))[0]["last_used_at"] is not None

    async def test_verifier_rejects_unknown_token(self, store):
        assert await self.verifier(store).verify_token("wikimcp_nope") is None

    async def test_verifier_rejects_personal_tokens(self, store):
        """Only OAuth: personal tokens from earlier versions no longer work."""
        await self.stored_user(store)
        _, pat = await store.create_token(3, "laptop", 3600, kind="pat")

        assert await self.verifier(store).verify_token(pat) is None

    async def test_verifier_rejects_token_when_wiki_session_lapsed(self, store):
        """The client then gets a 401 and runs the OAuth flow (and wiki login) again."""
        jwt, _, token = await self.stored_user(store)
        lapsed_at = wiki_jwt.expires_at(jwt) + 14 * 86400

        assert await self.verifier(store, clock=lambda: lapsed_at - 1).verify_token(
            token
        )
        assert (
            await self.verifier(store, clock=lambda: lapsed_at + 1).verify_token(token)
            is None
        )

    async def test_verifier_rejects_token_after_session_lost(self, store, monkeypatch):
        _, _, token = await self.stored_user(store)
        monkeypatch.setattr(
            auth,
            "get_access_token",
            lambda: AccessToken(token=token, client_id="app-1", scopes=[]),
        )

        await (await token_user_source(store)()).on_session_lost()

        assert await self.verifier(store).verify_token(token) is None

    async def test_token_user_source(self, store, monkeypatch):
        jwt, _, token = await self.stored_user(store)
        monkeypatch.setattr(
            auth,
            "get_access_token",
            lambda: AccessToken(token=token, client_id="app-1", scopes=[]),
        )

        user = await token_user_source(store)()

        assert user.wiki_user_id == 3
        assert user.jwt == jwt
        renewed = make_jwt(id=3, expires_in=7200)
        await user.on_new_jwt(renewed)
        assert (await store.get_user_for_token(token)).jwt == renewed

    async def test_token_user_source_without_token(self, store, monkeypatch):
        monkeypatch.setattr(auth, "get_access_token", lambda: None)

        with pytest.raises(WikiAuthExpired):
            await token_user_source(store)()

    async def test_token_user_source_with_purged_jwt(self, store, monkeypatch):
        _, _, token = await self.stored_user(store)
        await store.db.execute("UPDATE users SET jwt_encrypted = NULL")
        monkeypatch.setattr(
            auth,
            "get_access_token",
            lambda: AccessToken(token=token, client_id="app-1", scopes=[]),
        )

        with pytest.raises(WikiAuthExpired):
            await token_user_source(store)()

    async def test_static_user_source_keeps_renewed_jwt(self):
        source = static_user_source(make_jwt(), 3, "a@example.com")
        renewed = make_jwt(expires_in=7200)

        await (await source()).on_new_jwt(renewed)

        assert (await source()).jwt == renewed


class FakeVerifier:
    async def verify_token(self, token):
        if token == "good":
            return AccessToken(token=token, client_id="pat", scopes=[])
        return None


@pytest.mark.integration
class TestHttpApp:
    @pytest.fixture
    def http(self, mock_wiki_config, user):
        async def source():
            return user

        server = WikiJSMCPServer(
            mock_wiki_config, user_source=source, token_verifier=FakeVerifier()
        )
        with TestClient(
            server.app.streamable_http_app(), base_url="https://wiki.example.com"
        ) as http:
            yield http

    def initialize(self, http, token, **headers):
        return http.post(
            "/mcp/",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                **headers,
            },
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"},
                },
            },
        )

    def test_requires_token(self, http):
        response = http.post("/mcp/", json={})

        assert response.status_code == 401
        assert response.headers["www-authenticate"].startswith("Bearer")
        assert (
            'resource_metadata="https://wiki.example.com/.well-known/'
            'oauth-protected-resource/mcp/"' in response.headers["www-authenticate"]
        )

    def test_rejects_unknown_token(self, http):
        assert self.initialize(http, "bad").status_code == 401

    def test_accepts_valid_token(self, http):
        response = self.initialize(http, "good")

        assert response.status_code == 200
        assert "wikijs-mcp-server" in response.text

    def test_rejects_other_host(self, http):
        response = self.initialize(http, "good", Host="evil.example")

        assert response.status_code == 421
