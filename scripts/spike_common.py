"""Gedeelde hulpfuncties voor de spikes van fase 0.

Leest instellingen en testaccounts uit scripts/.env.spike (staat in .gitignore).
Print nooit volledige tokens: gebruik `redact()`.
"""

import base64
import json
import os
import sys
import time
from pathlib import Path

import httpx

HERE = Path(__file__).parent
ENV_FILE = HERE / ".env.spike"


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    env.update({k: v for k, v in os.environ.items() if k.startswith("SPIKE_")})
    return env


ENV = load_env()
WIKI_URL = ENV.get("SPIKE_WIKI_URL", "http://127.0.0.1:3080").rstrip("/")


def redact(token: str | None) -> str:
    if not token:
        return "<geen>"
    return f"{token[:6]}…{token[-4:]} ({len(token)} tekens)"


def jwt_payload(token: str) -> dict:
    """Payload van een JWT, zonder handtekeningcontrole."""
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def gql(
    query: str,
    variables: dict | None = None,
    jwt: str | None = None,
    content_type: str = "application/json",
) -> httpx.Response:
    headers = {"Content-Type": content_type}
    if jwt:
        headers["Authorization"] = f"Bearer {jwt}"
    body = json.dumps({"query": query, "variables": variables or {}})
    return httpx.post(f"{WIKI_URL}/graphql", content=body, headers=headers, timeout=30)


def gql_data(query: str, variables: dict | None = None, jwt: str | None = None) -> dict:
    """Voer een query uit en stop bij GraphQL-fouten."""
    resp = gql(query, variables, jwt)
    resp.raise_for_status()
    result = resp.json()
    if result.get("errors"):
        sys.exit(f"GraphQL-fout: {json.dumps(result['errors'], indent=2)}")
    return result["data"]


LOGIN = """
mutation Login($u: String!, $p: String!) {
  authentication {
    login(username: $u, password: $p, strategy: "local") {
      responseResult { succeeded errorCode message }
      jwt
    }
  }
}
"""


_JWT_CACHE: dict[str, str] = {}


def login(username: str, password: str) -> str:
    """Log in via de local strategy. Wiki.js staat 5 logins per minuut toe."""
    if username in _JWT_CACHE and seconds_left(_JWT_CACHE[username]) > 60:
        return _JWT_CACHE[username]
    for _ in range(5):
        result = gql(LOGIN, {"u": username, "p": password}).json()
        errors = result.get("errors") or []
        if errors and "Too many requests" in errors[0]["message"]:
            print("  (login-rate-limit van Wiki.js, 20 s wachten)", file=sys.stderr)
            time.sleep(20)
            continue
        break
    if errors:
        sys.exit(f"Login-fout voor {username}: {errors[0]['message']}")
    res = result["data"]["authentication"]["login"]
    if not res["responseResult"]["succeeded"]:
        sys.exit(f"Login mislukt voor {username}: {res['responseResult']['message']}")
    _JWT_CACHE[username] = res["jwt"]
    return res["jwt"]


def login_as(role: str) -> str:
    """Log in als testaccount uit .env.spike, bijvoorbeeld role='LEZER_A'."""
    return login(ENV[f"SPIKE_{role}_EMAIL"], ENV[f"SPIKE_{role}_PASSWORD"])


def seconds_left(token: str) -> int:
    return int(jwt_payload(token)["exp"] - time.time())
