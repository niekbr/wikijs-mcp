"""Reading Wiki.js JWT payloads.

Signatures are not verified here: Wiki.js verifies every token it receives. The
payload is only used to decide whether a token is still worth sending, and for
display and audit purposes.
"""

import base64
import json
from typing import Any

from .errors import WikiAuthExpired


def payload(jwt: str) -> dict[str, Any]:
    """Decode the payload of a JWT without verifying it."""
    try:
        part = jwt.split(".")[1]
        part += "=" * (-len(part) % 4)
        data = json.loads(base64.urlsafe_b64decode(part))
    except (IndexError, ValueError) as e:
        raise WikiAuthExpired("Malformed Wiki.js token") from e
    if not isinstance(data, dict) or "exp" not in data or "id" not in data:
        raise WikiAuthExpired("Malformed Wiki.js token")
    return data


def expires_at(jwt: str) -> int:
    """Unix timestamp at which the JWT expires."""
    return int(payload(jwt)["exp"])


def is_renewable(jwt: str, renewal_seconds: int, now: float) -> bool:
    """Whether Wiki.js will still accept (and if needed renew) this JWT."""
    return expires_at(jwt) + renewal_seconds > now
