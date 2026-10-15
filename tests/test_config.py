"""Tests for configuration management."""

import os
from unittest.mock import patch

import pytest

from tests.conftest import TEST_FERNET_KEY
from wikijs_mcp.config import WikiJSConfig, parse_duration

VALID = {
    "url": "http://wiki:3000",
    "public_url": "https://wiki.example.com",
    "strategy_key": "oidc",
    "db_path": "/data/mcp.sqlite",
    "encryption_key": TEST_FERNET_KEY,
}


@pytest.mark.unit
class TestWikiJSConfig:
    """Test cases for WikiJSConfig class."""

    def test_init_with_defaults(self):
        """Test WikiJSConfig initialization with defaults."""
        config = WikiJSConfig()

        assert config.url == ""
        assert config.graphql_endpoint == "/graphql"
        assert config.mcp_base_path == "/mcp"
        assert config.token_renewal == 14 * 86400
        assert config.session_max_age == 30 * 86400
        assert config.html_timeout == 10.0
        assert config.read_only is True
        assert config.debug is False

    def test_no_api_key(self):
        """The server never holds a Wiki.js API key, and has no personal tokens."""
        assert "api_key" not in WikiJSConfig.model_fields
        assert not {"pat_default_ttl", "pat_max_ttl", "oauth_enabled"} & set(
            WikiJSConfig.model_fields
        )
        assert not hasattr(WikiJSConfig(), "headers")

    def test_durations_accept_strings(self):
        config = WikiJSConfig(token_renewal="2m", session_max_age="1h")

        assert config.token_renewal == 120
        assert config.session_max_age == 3600

    @pytest.mark.parametrize(
        "value,expected",
        [
            ("30m", 1800),
            ("14d", 1209600),
            ("12h", 43200),
            ("45s", 45),
            ("90", 90),
            (7, 7),
        ],
    )
    def test_parse_duration(self, value, expected):
        assert parse_duration(value) == expected

    @pytest.mark.parametrize("value", ["", "14 days", "1w", "-5m", "m"])
    def test_parse_duration_invalid(self, value):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_duration(value)

    def test_graphql_url_property(self):
        """Test graphql_url property construction."""
        config = WikiJSConfig(url="https://test-wiki.com", graphql_endpoint="/graphql")

        assert config.graphql_url == "https://test-wiki.com/graphql"

    def test_graphql_url_property_trailing_slash(self):
        """Test graphql_url property with trailing slash in URL."""
        config = WikiJSConfig(url="https://test-wiki.com/", graphql_endpoint="/graphql")

        assert config.graphql_url == "https://test-wiki.com/graphql"

    def test_page_source_url(self):
        config = WikiJSConfig(url="http://wiki:3000/")

        assert (
            config.page_source_url("/docs/a/", "nl") == "http://wiki:3000/s/nl/docs/a"
        )

    def test_page_source_url_encodes_segments(self):
        config = WikiJSConfig(url="http://wiki:3000")

        assert (
            config.page_source_url("docs/a b?x=1#y/%2e%2e", "pt-br")
            == "http://wiki:3000/s/pt-br/docs/a%20b%3Fx=1%23y/%252e%252e"
        )

    @pytest.mark.parametrize(
        "path,locale",
        [
            ("../../graphql", "en"),
            ("docs/../../login", "en"),
            ("docs/./a", "en"),
            ("docs//a", "en"),
            ("", "en"),
            ("docs/a\nb", "en"),
            ("docs/a", "../.."),
            ("docs/a", "en/../admin"),
            ("docs/a", "en?x"),
        ],
    )
    def test_page_source_url_refuses_escapes(self, path, locale):
        """Dot segments would reach any Wiki.js URL with the user's token."""
        config = WikiJSConfig(url="http://wiki:3000")

        with pytest.raises(ValueError):
            config.page_source_url(path, locale)

    def test_validate_config_success(self):
        """Test validation passes with all required fields."""
        WikiJSConfig(**VALID).validate_config()

    @pytest.mark.parametrize(
        "field,env_name",
        [
            ("url", "WIKIJS_URL"),
            ("public_url", "WIKIJS_PUBLIC_URL"),
            ("strategy_key", "WIKIJS_STRATEGY_KEY"),
            ("db_path", "WIKIJS_MCP_DB_PATH"),
            ("encryption_key", "WIKIJS_MCP_ENCRYPTION_KEY"),
        ],
    )
    def test_validate_config_missing_field(self, field, env_name):
        config = WikiJSConfig(**{**VALID, field: ""})

        with pytest.raises(ValueError, match=env_name):
            config.validate_config()

    def test_validate_config_lists_all_missing(self):
        with pytest.raises(ValueError, match="WIKIJS_URL.*WIKIJS_PUBLIC_URL"):
            WikiJSConfig().validate_config()

    def test_validate_config_invalid_fernet_key(self):
        config = WikiJSConfig(**{**VALID, "encryption_key": "not-a-key"})

        with pytest.raises(ValueError, match="not a valid Fernet key"):
            config.validate_config()

    def test_validate_config_base_path_must_be_absolute(self):
        config = WikiJSConfig(**{**VALID, "mcp_base_path": "mcp"})

        with pytest.raises(ValueError, match="WIKIJS_MCP_BASE_PATH"):
            config.validate_config()

    def test_load_config_from_env_vars(self):
        """Test loading config from environment variables."""
        env_vars = {
            "WIKIJS_URL": "http://wiki:3000",
            "WIKIJS_GRAPHQL_ENDPOINT": "/api/graphql",
            "WIKIJS_PUBLIC_URL": "https://wiki.example.com",
            "WIKIJS_MCP_BASE_PATH": "/wiki-mcp",
            "WIKIJS_STRATEGY_KEY": "abc-123",
            "WIKIJS_MCP_DB_PATH": "/data/mcp.sqlite",
            "WIKIJS_MCP_ENCRYPTION_KEY": TEST_FERNET_KEY,
            "WIKIJS_DEFAULT_LOCALE": "nl",
            "WIKIJS_TOKEN_RENEWAL": "7d",
            "WIKIJS_MCP_SESSION_MAX_AGE": "10d",
            "WIKIJS_HTML_TIMEOUT": "5",
            "WIKIJS_MCP_READ_ONLY": "false",
            "DEBUG": "true",
        }

        with patch.dict(os.environ, env_vars):
            config = WikiJSConfig.load_config()

        assert config.url == "http://wiki:3000"
        assert config.graphql_endpoint == "/api/graphql"
        assert config.public_url == "https://wiki.example.com"
        assert config.mcp_base_path == "/wiki-mcp"
        assert config.strategy_key == "abc-123"
        assert config.db_path == "/data/mcp.sqlite"
        assert config.encryption_key == TEST_FERNET_KEY
        assert config.default_locale == "nl"
        assert config.token_renewal == 7 * 86400
        assert config.session_max_age == 10 * 86400
        assert config.html_timeout == 5.0
        assert config.read_only is False
        assert config.debug is True
        config.validate_config()

    def test_load_config_with_defaults(self):
        """Test that load_config uses defaults for missing env vars."""
        with patch.dict(os.environ, {"WIKIJS_URL": "https://test.com"}):
            config = WikiJSConfig.load_config()

        assert config.url == "https://test.com"
        assert config.graphql_endpoint == "/graphql"
        assert config.token_renewal == 14 * 86400
        assert config.read_only is True
        assert config.debug is False

    @pytest.mark.parametrize(
        "debug_value,expected",
        [
            ("true", True),
            ("TRUE", True),
            ("True", True),
            ("false", False),
            ("FALSE", False),
            ("False", False),
            ("", False),
            ("invalid", False),
        ],
    )
    def test_debug_flag_parsing(self, debug_value, expected):
        """Test debug flag parsing from environment."""
        env_vars = {"WIKIJS_URL": "https://test.com", "DEBUG": debug_value}

        with patch.dict(os.environ, env_vars):
            config = WikiJSConfig.load_config()

        assert config.debug is expected
