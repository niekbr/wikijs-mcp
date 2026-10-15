"""Helpers for building Wiki.js tokens and responses in tests."""

import base64
import json
import time
from typing import Any

import httpx


def _b64(data: dict[str, Any]) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(expires_in: int = 1800, **claims: Any) -> str:
    """An unsigned JWT shaped like the ones Wiki.js issues."""
    now = int(time.time())
    payload = {
        "id": 3,
        "email": "user@example.com",
        "name": "Test User",
        "groups": [3],
        "permissions": ["read:pages", "read:source"],
        "iat": now - 60,
        "exp": now + expires_in,
        **claims,
    }
    return f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}.{_b64(payload)}.sig"


def make_response(
    json_body: Any = None,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    text: str | None = None,
    method: str = "POST",
    url: str = "https://test-wiki.example.com/graphql",
) -> httpx.Response:
    """A real httpx.Response, so header and cookie handling is exercised."""
    kwargs: dict[str, Any] = {"headers": headers or {}}
    if json_body is not None:
        kwargs["json"] = json_body
    elif text is not None:
        kwargs["text"] = text
    return httpx.Response(status_code, request=httpx.Request(method, url), **kwargs)
