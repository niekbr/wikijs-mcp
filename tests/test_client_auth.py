"""Tests for per-user behaviour of WikiJSClient.

Covers what fase 0 found about Wiki.js 2.5: token renewal and silent Guest
fallback, error codes, the source view, and updates that must not wipe data.
"""

from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.helpers import make_jwt, make_response
from wikijs_mcp import client as client_module
from wikijs_mcp.client import WikiJSClient
from wikijs_mcp.errors import (
    WikiAuthError,
    WikiAuthExpired,
    WikiAuthRevoked,
    WikiError,
    WikiForbidden,
    WikiNotFound,
)

FIXTURES = Path(__file__).parent / "fixtures"


def graphql_error(message, code=None):
    error = {"message": message, "extensions": {"code": "INTERNAL_SERVER_ERROR"}}
    if code is not None:
        error["extensions"]["exception"] = {"code": code}
    return {"errors": [error], "data": None}


@pytest.fixture
def jwt():
    return make_jwt()


@pytest.fixture
def make_client(mock_wiki_config):
    def factory(token=None, on_new_jwt=None):
        return WikiJSClient(mock_wiki_config, token or make_jwt(), on_new_jwt)

    return factory


@pytest.mark.unit
class TestTransport:
    async def test_init(self, mock_wiki_config, jwt):
        client = WikiJSClient(mock_wiki_config, jwt)

        assert client.config == mock_wiki_config
        assert client.jwt == jwt
        assert isinstance(client.client, httpx.AsyncClient)

    async def test_context_manager(self, make_client):
        async with make_client() as client:
            assert isinstance(client, WikiJSClient)

    async def test_sends_user_jwt_and_exact_content_type(self, make_client, jwt):
        client = make_client(jwt)
        client.client.post = AsyncMock(return_value=make_response({"data": {"a": 1}}))

        result = await client._execute_query("query { a }", {"x": 1})

        assert result == {"a": 1}
        kwargs = client.client.post.call_args.kwargs
        assert kwargs["headers"]["Authorization"] == f"Bearer {jwt}"
        # Wiki.js only returns new-jwt for exactly this value
        assert kwargs["headers"]["Content-Type"] == "application/json"
        assert kwargs["json"] == {"query": "query { a }", "variables": {"x": 1}}

    async def test_omits_empty_variables(self, make_client):
        client = make_client()
        client.client.post = AsyncMock(return_value=make_response({"data": {}}))

        await client._execute_query("query { a }")

        assert client.client.post.call_args.kwargs["json"] == {"query": "query { a }"}

    @pytest.mark.parametrize("via", ["header", "cookie"])
    async def test_picks_up_renewed_jwt(self, make_client, via):
        old, new = make_jwt(expires_in=-60), make_jwt()
        on_new_jwt = AsyncMock()
        client = make_client(old, on_new_jwt)
        headers = (
            {"new-jwt": new}
            if via == "header"
            else {"set-cookie": f"jwt={new}; Path=/"}
        )
        client.client.post = AsyncMock(
            return_value=make_response({"data": {"a": 1}}, headers=headers)
        )

        assert await client._execute_query("query { a }") == {"a": 1}
        assert client.jwt == new
        on_new_jwt.assert_awaited_once_with(new)

        # Following requests use the renewed token
        await client._execute_query("query { a }")
        assert (
            client.client.post.call_args.kwargs["headers"]["Authorization"]
            == f"Bearer {new}"
        )

    async def test_unchanged_jwt_does_not_trigger_callback(self, make_client, jwt):
        on_new_jwt = AsyncMock()
        client = make_client(jwt, on_new_jwt)
        client.client.post = AsyncMock(
            return_value=make_response({"data": {}}, headers={"new-jwt": jwt})
        )

        await client._execute_query("query { a }")

        on_new_jwt.assert_not_awaited()

    async def test_expired_jwt_not_renewed_discards_guest_result(self, make_client):
        """Wiki.js answers as Guest if it did not accept the token."""
        client = make_client(make_jwt(expires_in=-60))
        client.client.post = AsyncMock(
            return_value=make_response(
                {"data": {"pages": {"list": [{"path": "publiek"}]}}}
            )
        )

        with pytest.raises(WikiAuthExpired):
            await client._execute_query("query { a }")

    async def test_jwt_past_renewal_period_is_not_sent(
        self, make_client, mock_wiki_config
    ):
        client = make_client(
            make_jwt(expires_in=-(mock_wiki_config.token_renewal + 60))
        )
        client.client.post = AsyncMock()

        with pytest.raises(WikiAuthExpired):
            await client._execute_query("query { a }")

        client.client.post.assert_not_called()

    async def test_malformed_jwt(self, make_client):
        client = make_client("not-a-jwt")
        client.client.post = AsyncMock()

        with pytest.raises(WikiAuthExpired):
            await client._execute_query("query { a }")

    @pytest.mark.parametrize(
        "status,exc",
        [
            (401, WikiAuthRevoked),
            (403, WikiForbidden),
            (500, WikiError),
            (502, WikiError),
        ],
    )
    async def test_http_errors(self, make_client, status, exc):
        client = make_client()
        client.client.post = AsyncMock(
            return_value=make_response(text="x", status_code=status)
        )

        with pytest.raises(exc, match=f"API request failed: {status}"):
            await client._execute_query("query { a }")

    async def test_network_error(self, make_client):
        client = make_client()
        client.client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with pytest.raises(WikiError, match="ConnectError"):
            await client._execute_query("query { a }")

    @pytest.mark.parametrize(
        "message,code,exc",
        [
            ("You are not authorized to view this page.", 6013, WikiForbidden),
            (
                "You are not authorized to view the history of this page.",
                6012,
                WikiForbidden,
            ),
            ("You are not authorized to move this page.", 6007, WikiForbidden),
            ("This page does not exist.", 6003, WikiNotFound),
            (
                "You must be authenticated to access this resource.",
                1019,
                WikiAuthRevoked,
            ),
            ("Your account has been disabled.", 1013, WikiAuthRevoked),
            ("Forbidden", None, WikiForbidden),
            ("Unauthorized", None, WikiAuthRevoked),
        ],
    )
    async def test_graphql_error_mapping(self, make_client, message, code, exc):
        client = make_client()
        client.client.post = AsyncMock(
            return_value=make_response(graphql_error(message, code))
        )

        with pytest.raises(exc, match=message):
            await client._execute_query("query { a }")

    async def test_unknown_graphql_error(self, make_client):
        client = make_client()
        client.client.post = AsyncMock(
            return_value=make_response(
                graphql_error("Cannot read properties of undefined")
            )
        )

        with pytest.raises(WikiError) as info:
            await client._execute_query("query { a }")
        assert type(info.value) is WikiError

    @pytest.mark.parametrize(
        "error_code,exc",
        [
            (6007, WikiForbidden),
            (6010, WikiForbidden),
            (6003, WikiNotFound),
            (1, WikiError),
        ],
    )
    async def test_mutation_error_codes(self, make_client, error_code, exc):
        client = make_client()
        client._execute_query = AsyncMock(
            return_value={
                "pages": {
                    "move": {
                        "responseResult": {
                            "succeeded": False,
                            "errorCode": error_code,
                            "message": "nope",
                        }
                    }
                }
            }
        )

        with pytest.raises(exc, match="Failed to move page: nope"):
            await client.move_page(3, "elders")


@pytest.mark.unit
class TestPageSource:
    def source_html(self):
        return (FIXTURES / "source_page.html").read_text()

    async def test_parses_source_view(self, make_client, jwt):
        client = make_client(jwt)
        client.client.get = AsyncMock(
            return_value=make_response(text=self.source_html(), method="GET")
        )

        page = await client.get_page_source("/test/speciaal/", "en")

        assert page["content"] == (FIXTURES / "source_page.md").read_text()
        assert page["page_id"] == 5
        assert page["path"] == "test/speciaal"
        assert page["locale"] == "en"
        assert page["effective_permissions"]["source"] == {"read": True}
        assert page["effective_permissions"]["pages"]["write"] is False

        args, kwargs = client.client.get.call_args
        assert args[0] == "https://test-wiki.example.com/s/en/test/speciaal"
        assert kwargs["headers"] == {"Authorization": f"Bearer {jwt}"}
        assert kwargs["follow_redirects"] is False
        assert kwargs["timeout"] == client.config.html_timeout
        assert kwargs["params"] is None

    async def test_version(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(
            return_value=make_response(text=self.source_html(), method="GET")
        )

        await client.get_page_source("test/speciaal", version_id=12)

        assert client.client.get.call_args.kwargs["params"] == {"v": 12}

    async def test_uses_default_locale(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(
            return_value=make_response(text=self.source_html(), method="GET")
        )

        await client.get_page_source("test/speciaal")

        assert client.client.get.call_args.args[0].endswith("/s/en/test/speciaal")

    @pytest.mark.parametrize(
        "path,locale", [("x/../../../login", "en"), ("docs/a", "../..")]
    )
    async def test_refuses_paths_outside_source_view(self, make_client, path, locale):
        """The user's token must not be sent to other Wiki.js URLs."""
        client = make_client()
        client.client.get = AsyncMock()

        with pytest.raises(ValueError):
            await client.get_page_source(path, locale)

        client.client.get.assert_not_called()

    async def test_renewed_jwt_from_cookie(self, make_client):
        new = make_jwt()
        on_new_jwt = AsyncMock()
        client = make_client(make_jwt(expires_in=-60), on_new_jwt)
        client.client.get = AsyncMock(
            return_value=make_response(
                text=self.source_html(),
                headers={"set-cookie": f"jwt={new}; Path=/"},
                method="GET",
            )
        )

        await client.get_page_source("test/speciaal", "en")

        on_new_jwt.assert_awaited_once_with(new)

    async def test_redirect_means_not_found(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(
            return_value=make_response(
                status_code=302, headers={"location": "/x"}, text="", method="GET"
            )
        )

        with pytest.raises(WikiNotFound):
            await client.get_page_source("x", "en")

    async def test_forbidden_mentions_read_source(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(
            return_value=make_response(
                status_code=403, text="Unauthorized", method="GET"
            )
        )

        with pytest.raises(WikiForbidden, match="read:source"):
            await client.get_page_source("geheim/plan", "en")

    @pytest.mark.parametrize(
        "failure",
        [
            {"side_effect": httpx.ReadTimeout("timeout")},
            {"return_value": make_response(status_code=500, text="", method="GET")},
        ],
    )
    async def test_hang_or_500_from_revoked_user(self, make_client, failure):
        """Wiki.js hangs (/s/) or fails (500) on HTML routes for deactivated users."""
        client = make_client()
        client.client.get = AsyncMock(**failure)
        client.get_profile = AsyncMock(side_effect=WikiAuthRevoked("Unauthorized"))

        with pytest.raises(WikiAuthRevoked):
            await client.get_page_source("docs/algemeen", "en")

    async def test_hang_with_valid_session(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(side_effect=httpx.ReadTimeout("timeout"))
        client.get_profile = AsyncMock(return_value={"id": 3})

        with pytest.raises(WikiError, match="did not return"):
            await client.get_page_source("docs/algemeen", "en")

    async def test_unexpected_format(self, make_client):
        client = make_client()
        client.client.get = AsyncMock(
            return_value=make_response(text="<html>login</html>", method="GET")
        )

        with pytest.raises(WikiError, match="Unexpected source view format"):
            await client.get_page_source("docs/algemeen", "en")


@pytest.mark.unit
class TestLocale:
    async def test_configured_default_locale(self, make_client):
        client = make_client()
        client._execute_query = AsyncMock()

        assert await client.get_default_locale() == "en"
        client._execute_query.assert_not_called()

    async def test_site_default_locale_cached(self, mock_wiki_config, monkeypatch):
        monkeypatch.setattr(client_module, "_default_locale_cache", {})
        config = mock_wiki_config.model_copy(update={"default_locale": ""})
        client = WikiJSClient(config, make_jwt())
        client._execute_query = AsyncMock(
            return_value={"localization": {"config": {"locale": "nl"}}}
        )

        assert await client.get_default_locale() == "nl"
        assert await WikiJSClient(config, make_jwt()).get_default_locale() == "nl"
        client._execute_query.assert_awaited_once()

    async def test_tree_create_and_move_use_default_locale(self, mock_wiki_config):
        config = mock_wiki_config.model_copy(update={"default_locale": "nl"})
        client = WikiJSClient(config, make_jwt())
        ok = {"responseResult": {"succeeded": True}}
        client._execute_query = AsyncMock(
            return_value={"pages": {"tree": [], "create": ok, "move": ok}}
        )

        await client.get_page_tree()
        assert client._execute_query.call_args.args[1]["locale"] == "nl"
        await client.create_page("a", "A", "x")
        assert client._execute_query.call_args.args[1]["locale"] == "nl"
        await client.move_page(1, "b")
        assert client._execute_query.call_args.args[1]["destinationLocale"] == "nl"


PAGES = [
    {
        "id": 3,
        "path": "docs/algemeen",
        "locale": "en",
        "title": "Algemene docs",
        "description": "Beschrijving",
        "isPublished": False,
        "isPrivate": False,
        "tags": ["algemeen", "docs"],
    },
    {"id": 4, "path": "geheim/plan", "locale": "en", "title": "Geheim"},
]


@pytest.mark.unit
class TestPageMeta:
    async def test_by_id_and_path_with_one_list_call(self, make_client):
        client = make_client()
        client.list_pages = AsyncMock(return_value=PAGES)

        assert (await client.get_page_meta(page_id=4))["path"] == "geheim/plan"
        assert (await client.get_page_meta(path="/docs/algemeen"))["id"] == 3
        assert await client.get_page_meta(path="docs/algemeen", locale="nl") is None
        assert await client.get_page_meta(page_id=99) is None
        client.list_pages.assert_awaited_once_with(limit=None)

    async def test_resolve_page_id(self, make_client):
        client = make_client()
        client.list_pages = AsyncMock(return_value=PAGES)

        assert await client.resolve_page_id("docs/algemeen") == 3
        with pytest.raises(WikiNotFound):
            await client.resolve_page_id("bestaat/niet")

    async def test_list_pages_unlimited(self, make_client):
        client = make_client()
        client._execute_query = AsyncMock(return_value={"pages": {"list": PAGES}})

        await client.list_pages(limit=None, locale="en")

        query, variables = client._execute_query.call_args.args
        assert "$limit: Int," in query
        assert "isPublished" in query
        assert variables["limit"] is None
        assert variables["locale"] == "en"


@pytest.mark.unit
class TestSafeUpdate:
    def make_update_client(self, make_client, page_rights=None, extras=None):
        client = make_client()
        client.list_pages = AsyncMock(return_value=PAGES)
        client.get_page_source = AsyncMock(
            return_value={
                "path": "docs/algemeen",
                "locale": "en",
                "page_id": 3,
                "content": "Huidige inhoud",
                "effective_permissions": {
                    "pages": page_rights or {"read": True, "write": True}
                },
            }
        )
        client._get_page_extras = AsyncMock(return_value=extras)
        client._execute_query = AsyncMock(
            return_value={
                "pages": {
                    "update": {
                        "responseResult": {"succeeded": True},
                        "page": {"id": 3},
                    }
                }
            }
        )
        return client

    async def test_keeps_current_values(self, make_client):
        client = self.make_update_client(make_client)

        await client.update_page(3, title="Nieuwe titel")

        variables = client._execute_query.call_args.args[1]
        assert variables == {
            "id": 3,
            "content": "Huidige inhoud",
            "title": "Nieuwe titel",
            "description": "Beschrijving",
            "tags": ["algemeen", "docs"],
            "isPublished": False,  # missing isPublished would unpublish
            "isPrivate": False,
            "locale": "en",
            "path": "docs/algemeen",
        }
        client.get_page_source.assert_awaited_once_with("docs/algemeen", "en")

    async def test_explicit_values_win(self, make_client):
        client = self.make_update_client(make_client)

        await client.update_page(
            3, content="Nieuw", description="", tags=[], is_published=True
        )

        variables = client._execute_query.call_args.args[1]
        assert variables["content"] == "Nieuw"
        assert variables["description"] == ""
        assert variables["tags"] == []
        assert variables["isPublished"] is True

    async def test_keeps_css_js_and_publish_window_with_manage_pages(self, make_client):
        extras = {
            "scriptCss": ".a{}",
            "scriptJs": "",
            "publishStartDate": "2026-01-01T00:00:00Z",
            "publishEndDate": "",
        }
        client = self.make_update_client(
            make_client, {"read": True, "write": True, "style": True}, extras
        )

        await client.update_page(3, content="Nieuw")

        variables = client._execute_query.call_args.args[1]
        assert variables["scriptCss"] == ".a{}"
        assert variables["scriptJs"] == ""
        assert variables["publishStartDate"] == "2026-01-01T00:00:00Z"
        assert variables["publishEndDate"] is None

    @pytest.mark.parametrize("right", ["style", "script"])
    async def test_refuses_when_css_js_would_be_erased(self, make_client, right):
        client = self.make_update_client(make_client, {"write": True, right: True})

        with pytest.raises(WikiForbidden, match="CSS/JS"):
            await client.update_page(3, content="Nieuw")

        client._execute_query.assert_not_called()

    async def test_without_extras_or_style_rights(self, make_client):
        client = self.make_update_client(make_client)

        await client.update_page(3, content="Nieuw")

        variables = client._execute_query.call_args.args[1]
        assert "scriptCss" not in variables
        assert "publishStartDate" not in variables

    async def test_not_found(self, make_client):
        client = self.make_update_client(make_client)

        with pytest.raises(WikiNotFound, match="Page with ID 999 not found"):
            await client.update_page(999, content="x")

    async def test_failure(self, make_client):
        client = self.make_update_client(make_client)
        client._execute_query.return_value = {
            "pages": {
                "update": {
                    "responseResult": {
                        "succeeded": False,
                        "errorCode": 6009,
                        "message": "You are not authorized to update this page.",
                    }
                }
            }
        }

        with pytest.raises(WikiForbidden, match="Failed to update page"):
            await client.update_page(3, content="x")

    async def test_page_extras_forbidden_returns_none(self, make_client):
        client = make_client()
        client._execute_query = AsyncMock(side_effect=WikiForbidden("6013"))

        assert await client._get_page_extras("docs/algemeen", "en") is None


@pytest.mark.unit
class TestSearch:
    async def test_strips_ids_and_counts(self, make_client):
        client = make_client()
        client._execute_query = AsyncMock(
            return_value={
                "pages": {
                    "search": {
                        "results": [
                            {
                                "id": "4",
                                "title": "T",
                                "description": "D",
                                "path": "p",
                                "locale": "en",
                            }
                        ],
                        "totalHits": 9,
                        "suggestions": ["zeppelin"],
                    }
                }
            }
        )

        results = await client.search_pages("x", locale="nl")

        assert results == [
            {"title": "T", "description": "D", "path": "p", "locale": "en"}
        ]
        query, variables = client._execute_query.call_args.args
        for leaky in ("totalHits", "suggestions", "id\n"):
            assert leaky not in query
        assert variables == {"query": "x", "locale": "nl"}


@pytest.mark.unit
def test_auth_errors_share_base_class():
    assert issubclass(WikiAuthExpired, WikiAuthError)
    assert issubclass(WikiAuthRevoked, WikiAuthError)
    assert issubclass(WikiAuthError, WikiError)
