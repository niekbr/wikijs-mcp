"""SQLite storage for users, MCP tokens, web sessions and login states.

- A user's Wiki.js JWT is stored per Wiki.js user (not per login), encrypted with
  Fernet. Logging in again replaces the JWT; existing MCP tokens keep working.
- MCP tokens, web session ids and login-state bindings are random secrets and are
  stored only as SHA-256 hashes.
- Two lifetimes apply to a user: the JWT dies when unused for longer than Wiki.js's
  renewal period (the client detects that), and `session_max_age` after the last
  SSO login a new login is required regardless of use.
"""

import hashlib
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import aiosqlite
from cryptography.fernet import Fernet, InvalidToken

from . import wiki_jwt

TOKEN_PREFIX = "wikimcp_"
LOGIN_STATE_TTL = 600

SCHEMA_VERSION = 1
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    wiki_user_id INTEGER PRIMARY KEY,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    jwt_encrypted BLOB,
    jwt_exp INTEGER NOT NULL,
    login_at INTEGER NOT NULL,
    last_used_at INTEGER
);

CREATE TABLE IF NOT EXISTS mcp_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    wiki_user_id INTEGER NOT NULL REFERENCES users(wiki_user_id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('pat', 'oauth')),
    client_id TEXT,
    scopes TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS mcp_tokens_user ON mcp_tokens(wiki_user_id);

CREATE TABLE IF NOT EXISTS web_sessions (
    id_hash TEXT PRIMARY KEY,
    wiki_user_id INTEGER NOT NULL REFERENCES users(wiki_user_id) ON DELETE CASCADE,
    csrf_secret TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_states (
    state TEXT PRIMARY KEY,
    browser_binding_hash TEXT NOT NULL,
    next TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
"""


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


@dataclass(frozen=True)
class TokenUser:
    """A user authenticated by an MCP token."""

    wiki_user_id: int
    email: str
    name: str
    jwt: str | None  # None if purged or no longer decryptable (key changed)
    login_at: int
    token_id: int
    token_kind: str
    client_id: str | None
    scopes: list[str]
    token_expires_at: int


@dataclass(frozen=True)
class WebSession:
    wiki_user_id: int
    email: str
    name: str
    csrf_secret: str
    expires_at: int


class Store:
    """Async SQLite store. Use `async with Store(...) as store:` or open()/close()."""

    def __init__(
        self,
        db_path: str,
        encryption_key: str,
        session_max_age: int,
        clock: Callable[[], float] = time.time,
    ):
        self._db_path = db_path
        self._fernet = Fernet(encryption_key)
        self._session_max_age = session_max_age
        self._clock = clock
        self._db: aiosqlite.Connection | None = None

    def _now(self) -> int:
        return int(self._clock())

    async def open(self) -> None:
        self._db = await aiosqlite.connect(self._db_path)
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA foreign_keys = ON")
        await self._db.execute("PRAGMA journal_mode = WAL")
        async with self._db.execute("PRAGMA user_version") as cursor:
            version = (await cursor.fetchone())[0]
        if version > SCHEMA_VERSION:
            raise RuntimeError(
                f"Database schema version {version} is newer than supported "
                f"({SCHEMA_VERSION})"
            )
        await self._db.executescript(SCHEMA)
        await self._db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        await self._db.commit()

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None

    async def __aenter__(self) -> "Store":
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.close()

    @property
    def db(self) -> aiosqlite.Connection:
        if self._db is None:
            raise RuntimeError("Store is not open")
        return self._db

    # ------------------------------------------------------------------
    # Users and their Wiki.js JWT
    # ------------------------------------------------------------------

    def _encrypt(self, jwt: str) -> bytes:
        return self._fernet.encrypt(jwt.encode())

    def _decrypt(self, data: bytes | None) -> str | None:
        if data is None:
            return None
        try:
            return self._fernet.decrypt(data).decode()
        except InvalidToken:
            return None

    async def upsert_login(self, jwt: str, profile: dict[str, Any]) -> int:
        """Store the JWT of a fresh SSO login; returns the Wiki.js user id.

        `profile` is the result of `users.profile` for this JWT, which proves
        Wiki.js accepted it. Name and email are kept for display and auditing.
        """
        claims = wiki_jwt.payload(jwt)
        user_id = int(claims["id"])
        if int(profile.get("id", -1)) != user_id:
            raise ValueError("Profile does not belong to the JWT's user")
        now = self._now()
        await self.db.execute(
            """
            INSERT INTO users (wiki_user_id, email, name, jwt_encrypted, jwt_exp, login_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (wiki_user_id) DO UPDATE SET
                email = excluded.email,
                name = excluded.name,
                jwt_encrypted = excluded.jwt_encrypted,
                jwt_exp = excluded.jwt_exp,
                login_at = excluded.login_at
            """,
            (
                user_id,
                profile.get("email") or claims.get("email", ""),
                profile.get("name") or claims.get("name", ""),
                self._encrypt(jwt),
                int(claims["exp"]),
                now,
            ),
        )
        await self.db.commit()
        return user_id

    async def update_jwt(self, wiki_user_id: int, jwt: str) -> bool:
        """Store a renewed JWT, unless a later-expiring one is already stored.

        Parallel requests can each receive a renewed token; this keeps the newest.
        Returns whether the stored JWT was replaced.
        """
        claims = wiki_jwt.payload(jwt)
        if int(claims["id"]) != wiki_user_id:
            raise ValueError("JWT does not belong to this user")
        cursor = await self.db.execute(
            """
            UPDATE users SET jwt_encrypted = ?, jwt_exp = ?
            WHERE wiki_user_id = ? AND jwt_exp < ?
            """,
            (self._encrypt(jwt), int(claims["exp"]), wiki_user_id, int(claims["exp"])),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def delete_user(self, wiki_user_id: int) -> None:
        """Forget a user, their JWT, tokens and web sessions."""
        await self.db.execute(
            "DELETE FROM users WHERE wiki_user_id = ?", (wiki_user_id,)
        )
        await self.db.commit()

    # ------------------------------------------------------------------
    # MCP tokens
    # ------------------------------------------------------------------

    async def create_token(
        self,
        wiki_user_id: int,
        name: str,
        ttl: int,
        kind: str = "pat",
        client_id: str | None = None,
        scopes: list[str] | None = None,
    ) -> tuple[int, str]:
        """Create a token; returns (token id, token). The token is shown only once."""
        if ttl <= 0:
            raise ValueError("Tokens must expire")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        now = self._now()
        cursor = await self.db.execute(
            """
            INSERT INTO mcp_tokens
                (token_hash, wiki_user_id, name, kind, client_id, scopes,
                 created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                hash_secret(token),
                wiki_user_id,
                name,
                kind,
                client_id,
                " ".join(scopes or []),
                now,
                now + ttl,
            ),
        )
        await self.db.commit()
        return cursor.lastrowid, token

    async def get_user_for_token(self, token: str) -> TokenUser | None:
        """The user behind a token, or None if the token is unknown, revoked,
        expired, or the user's last SSO login is older than session_max_age."""
        now = self._now()
        async with self.db.execute(
            """
            SELECT t.id, t.kind, t.client_id, t.scopes, t.expires_at,
                   u.wiki_user_id, u.email, u.name, u.jwt_encrypted, u.login_at
            FROM mcp_tokens t JOIN users u USING (wiki_user_id)
            WHERE t.token_hash = ?
              AND t.revoked_at IS NULL
              AND t.expires_at > ?
              AND u.login_at > ?
            """,
            (hash_secret(token), now, now - self._session_max_age),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return TokenUser(
            wiki_user_id=row["wiki_user_id"],
            email=row["email"],
            name=row["name"],
            jwt=self._decrypt(row["jwt_encrypted"]),
            login_at=row["login_at"],
            token_id=row["id"],
            token_kind=row["kind"],
            client_id=row["client_id"],
            scopes=row["scopes"].split(),
            token_expires_at=row["expires_at"],
        )

    async def touch(self, token_id: int) -> None:
        """Record that a token (and its user) was just used."""
        now = self._now()
        await self.db.execute(
            "UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?", (now, token_id)
        )
        await self.db.execute(
            """
            UPDATE users SET last_used_at = ?
            WHERE wiki_user_id = (SELECT wiki_user_id FROM mcp_tokens WHERE id = ?)
            """,
            (now, token_id),
        )
        await self.db.commit()

    async def list_tokens(self, wiki_user_id: int) -> list[dict[str, Any]]:
        """A user's tokens that are neither revoked nor expired, newest first."""
        async with self.db.execute(
            """
            SELECT id, name, kind, client_id, created_at, expires_at, last_used_at
            FROM mcp_tokens
            WHERE wiki_user_id = ? AND revoked_at IS NULL AND expires_at > ?
            ORDER BY created_at DESC, id DESC
            """,
            (wiki_user_id, self._now()),
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

    async def revoke_token(self, wiki_user_id: int, token_id: int) -> bool:
        """Revoke one of the user's own tokens; returns whether one was revoked."""
        cursor = await self.db.execute(
            """
            UPDATE mcp_tokens SET revoked_at = ?
            WHERE id = ? AND wiki_user_id = ? AND revoked_at IS NULL
            """,
            (self._now(), token_id, wiki_user_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def revoke_all_tokens(self, wiki_user_id: int) -> int:
        cursor = await self.db.execute(
            """
            UPDATE mcp_tokens SET revoked_at = ?
            WHERE wiki_user_id = ? AND revoked_at IS NULL
            """,
            (self._now(), wiki_user_id),
        )
        await self.db.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Web sessions (management pages) and login states
    # ------------------------------------------------------------------

    async def create_web_session(self, wiki_user_id: int, ttl: int) -> str:
        """Create a web session; returns the session id for the cookie."""
        session_id = secrets.token_urlsafe(32)
        await self.db.execute(
            """
            INSERT INTO web_sessions (id_hash, wiki_user_id, csrf_secret, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                hash_secret(session_id),
                wiki_user_id,
                secrets.token_urlsafe(32),
                self._now() + ttl,
            ),
        )
        await self.db.commit()
        return session_id

    async def get_web_session(self, session_id: str) -> WebSession | None:
        now = self._now()
        async with self.db.execute(
            """
            SELECT s.wiki_user_id, s.csrf_secret, s.expires_at, u.email, u.name
            FROM web_sessions s JOIN users u USING (wiki_user_id)
            WHERE s.id_hash = ? AND s.expires_at > ? AND u.login_at > ?
            """,
            (hash_secret(session_id), now, now - self._session_max_age),
        ) as cursor:
            row = await cursor.fetchone()
        return WebSession(**dict(row)) if row else None

    async def delete_web_session(self, session_id: str) -> None:
        await self.db.execute(
            "DELETE FROM web_sessions WHERE id_hash = ?", (hash_secret(session_id),)
        )
        await self.db.commit()

    async def create_login_state(self, next_path: str) -> tuple[str, str]:
        """Start a login; returns (state, browser binding for a cookie)."""
        state = secrets.token_urlsafe(32)
        binding = secrets.token_urlsafe(32)
        await self.db.execute(
            """
            INSERT INTO login_states (state, browser_binding_hash, next, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (state, hash_secret(binding), next_path, self._now()),
        )
        await self.db.commit()
        return state, binding

    async def consume_login_state(self, state: str, binding: str) -> str | None:
        """Use a login state once; returns its `next` path if state and browser match."""
        async with self.db.execute(
            "DELETE FROM login_states WHERE state = ? RETURNING browser_binding_hash, next, created_at",
            (state,),
        ) as cursor:
            row = await cursor.fetchone()
        await self.db.commit()
        if row is None or row["created_at"] + LOGIN_STATE_TTL <= self._now():
            return None
        if not secrets.compare_digest(
            row["browser_binding_hash"], hash_secret(binding)
        ):
            return None
        return row["next"]

    # ------------------------------------------------------------------
    # Housekeeping
    # ------------------------------------------------------------------

    async def purge_expired(self, revoked_retention: int = 30 * 86400) -> None:
        """Remove what can no longer be used.

        For users whose last SSO login is older than session_max_age the JWT is
        wiped: it may not be used anyway until they log in again, after which their
        tokens work again. Users without usable tokens are then deleted entirely.
        Revoked and expired tokens are kept for `revoked_retention` for auditing.
        """
        now = self._now()
        stale_login = now - self._session_max_age
        await self.db.execute(
            "UPDATE users SET jwt_encrypted = NULL WHERE login_at <= ?", (stale_login,)
        )
        await self.db.execute(
            """
            DELETE FROM mcp_tokens
            WHERE expires_at <= ? OR revoked_at <= ?
            """,
            (now - revoked_retention, now - revoked_retention),
        )
        await self.db.execute(
            """
            DELETE FROM users
            WHERE login_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM mcp_tokens t
                  WHERE t.wiki_user_id = users.wiki_user_id
                    AND t.revoked_at IS NULL AND t.expires_at > ?
              )
            """,
            (stale_login, now),
        )
        await self.db.execute("DELETE FROM web_sessions WHERE expires_at <= ?", (now,))
        await self.db.execute(
            "DELETE FROM login_states WHERE created_at <= ?", (now - LOGIN_STATE_TTL,)
        )
        await self.db.commit()
