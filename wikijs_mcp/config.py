"""Configuration management for WikiJS MCP Server."""

import os
import re

from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, field_validator

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_duration(value: str | int) -> int:
    """Parse a duration like '30m', '14d' or a number of seconds into seconds."""
    if isinstance(value, int):
        return value
    match = re.fullmatch(r"\s*(\d+)\s*([smhd]?)\s*", str(value))
    if not match:
        raise ValueError(f"Invalid duration: {value!r} (use e.g. '30m', '14d')")
    amount, unit = match.groups()
    return int(amount) * _DURATION_UNITS[unit or "s"]


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() == "true"


class WikiJSConfig(BaseModel):
    """Site-wide settings. Credentials are per user and never part of the config."""

    url: str = Field(default="")
    graphql_endpoint: str = Field(default="/graphql")
    public_url: str = Field(default="")
    mcp_base_path: str = Field(default="/mcp")
    strategy_key: str = Field(default="")
    db_path: str = Field(default="")
    encryption_key: str = Field(default="")
    default_locale: str = Field(default="")
    token_renewal: int = Field(default=parse_duration("14d"))
    session_max_age: int = Field(default=parse_duration("30d"))
    pat_default_ttl: int = Field(default=parse_duration("90d"))
    pat_max_ttl: int = Field(default=parse_duration("365d"))
    html_timeout: float = Field(default=10.0)
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8000)
    forwarded_allow_ips: str = Field(default="127.0.0.1")
    read_only: bool = Field(default=True)
    debug: bool = Field(default=False)

    @field_validator(
        "token_renewal",
        "session_max_age",
        "pat_default_ttl",
        "pat_max_ttl",
        mode="before",
    )
    @classmethod
    def _parse_duration(cls, value):
        return parse_duration(value)

    @classmethod
    def load_config(cls) -> "WikiJSConfig":
        """Load configuration from environment variables."""
        values = {
            "url": os.getenv("WIKIJS_URL", ""),
            "graphql_endpoint": os.getenv("WIKIJS_GRAPHQL_ENDPOINT", "/graphql"),
            "public_url": os.getenv("WIKIJS_PUBLIC_URL", ""),
            "mcp_base_path": os.getenv("WIKIJS_MCP_BASE_PATH", "/mcp"),
            "strategy_key": os.getenv("WIKIJS_STRATEGY_KEY", ""),
            "db_path": os.getenv("WIKIJS_MCP_DB_PATH", ""),
            "encryption_key": os.getenv("WIKIJS_MCP_ENCRYPTION_KEY", ""),
            "default_locale": os.getenv("WIKIJS_DEFAULT_LOCALE", ""),
            "read_only": _env_bool("WIKIJS_MCP_READ_ONLY", True),
            "debug": _env_bool("DEBUG", False),
        }
        optional = {
            "token_renewal": "WIKIJS_TOKEN_RENEWAL",
            "session_max_age": "WIKIJS_MCP_SESSION_MAX_AGE",
            "pat_default_ttl": "WIKIJS_MCP_PAT_DEFAULT_TTL",
            "pat_max_ttl": "WIKIJS_MCP_PAT_MAX_TTL",
            "html_timeout": "WIKIJS_HTML_TIMEOUT",
            "host": "WIKIJS_MCP_HOST",
            "port": "WIKIJS_MCP_PORT",
            "forwarded_allow_ips": "WIKIJS_MCP_FORWARDED_ALLOW_IPS",
        }
        for field, env_name in optional.items():
            if os.getenv(env_name):
                values[field] = os.environ[env_name]
        return cls(**values)

    @property
    def graphql_url(self) -> str:
        """Get the full GraphQL endpoint URL."""
        return f"{self.url.rstrip('/')}{self.graphql_endpoint}"

    def page_source_url(self, path: str, locale: str) -> str:
        """URL of the Wiki.js source view of a page."""
        return f"{self.url.rstrip('/')}/s/{locale}/{path.strip('/')}"

    @property
    def mcp_url(self) -> str:
        """Public URL of the MCP endpoint."""
        return f"{self.public_url.rstrip('/')}{self.mcp_base_path.rstrip('/')}/"

    @property
    def login_url(self) -> str:
        """Public URL where users (re)connect their Wiki.js account."""
        return f"{self.public_url.rstrip('/')}{self.mcp_base_path.rstrip('/')}/login"

    def validate_config(self, only: list[str] | None = None) -> None:
        """Validate that required configuration is present.

        `only` limits the required fields, e.g. for the stdio development mode.
        """
        required = {
            "url": "WIKIJS_URL",
            "public_url": "WIKIJS_PUBLIC_URL",
            "strategy_key": "WIKIJS_STRATEGY_KEY",
            "db_path": "WIKIJS_MCP_DB_PATH",
            "encryption_key": "WIKIJS_MCP_ENCRYPTION_KEY",
        }
        if only is not None:
            required = {field: env for field, env in required.items() if field in only}
        missing = [env for field, env in required.items() if not getattr(self, field)]
        if missing:
            raise ValueError(
                f"Missing required environment variable(s): {', '.join(missing)}"
            )
        if "encryption_key" in required:
            try:
                Fernet(self.encryption_key)
            except ValueError as e:
                raise ValueError(
                    "WIKIJS_MCP_ENCRYPTION_KEY is not a valid Fernet key"
                ) from e
        if not self.mcp_base_path.startswith("/"):
            raise ValueError("WIKIJS_MCP_BASE_PATH must start with '/'")
        if self.pat_default_ttl > self.pat_max_ttl:
            raise ValueError(
                "WIKIJS_MCP_PAT_DEFAULT_TTL cannot exceed WIKIJS_MCP_PAT_MAX_TTL"
            )
