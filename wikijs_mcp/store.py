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

SCHEMA_VERSION = 2
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

-- Schema version 2: OAuth (fase 5)
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_info TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_pending (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    params TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    wiki_user_id INTEGER NOT NULL REFERENCES users(wiki_user_id) ON DELETE CASCADE,
    params TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    wiki_user_id INTEGER NOT NULL REFERENCES users(wiki_user_id) ON DELETE CASCADE,
    scopes TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS oauth_refresh_user ON oauth_refresh_tokens(wiki_user_id, client_id);
"""

OAUTH_PENDING_TTL = 600
OAUTH_CODE_TTL = 300


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
    login_at: int
    jwt_exp: int


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

    async def forget_jwt(self, wiki_user_id: int) -> None:
        """Drop a JWT Wiki.js no longer accepts; the user must sign in again."""
        await self.db.execute(
            "UPDATE users SET jwt_encrypted = NULL WHERE wiki_user_id = ?",
            (wiki_user_id,),
        )
        await self.db.commit()

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

    async def list_tokens(
        self, wiki_user_id: int, kind: str | None = None
    ) -> list[dict[str, Any]]:
        """A user's tokens that are neither revoked nor expired, newest first."""
        async with self.db.execute(
            """
            SELECT id, name, kind, client_id, created_at, expires_at, last_used_at
            FROM mcp_tokens
            WHERE wiki_user_id = ? AND revoked_at IS NULL AND expires_at > ?
              AND (? IS NULL OR kind = ?)
            ORDER BY created_at DESC, id DESC
            """,
            (wiki_user_id, self._now(), kind, kind),
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
            SELECT s.wiki_user_id, s.csrf_secret, s.expires_at, u.email, u.name,
                   u.login_at, u.jwt_exp
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
    # OAuth (fase 5)
    # ------------------------------------------------------------------

    async def save_oauth_client(self, client_id: str, client_info: str) -> None:
        await self.db.execute(
            "INSERT INTO oauth_clients (client_id, client_info, created_at) VALUES (?, ?, ?)",
            (client_id, client_info, self._now()),
        )
        await self.db.commit()

    async def get_oauth_client(self, client_id: str) -> str | None:
        async with self.db.execute(
            "SELECT client_info FROM oauth_clients WHERE client_id = ?", (client_id,)
        ) as cursor:
            row = await cursor.fetchone()
        return row["client_info"] if row else None

    async def create_oauth_pending(self, client_id: str, params: str) -> str:
        """Park an authorization request until the user consents; returns its id."""
        pending_id = secrets.token_urlsafe(32)
        await self.db.execute(
            "INSERT INTO oauth_pending (id, client_id, params, created_at) VALUES (?, ?, ?, ?)",
            (pending_id, client_id, params, self._now()),
        )
        await self.db.commit()
        return pending_id

    async def get_oauth_pending(self, pending_id: str) -> tuple[str, str] | None:
        """(client_id, params) of a pending request that has not expired."""
        async with self.db.execute(
            """
            SELECT client_id, params FROM oauth_pending
            WHERE id = ? AND created_at > ?
            """,
            (pending_id, self._now() - OAUTH_PENDING_TTL),
        ) as cursor:
            row = await cursor.fetchone()
        return (row["client_id"], row["params"]) if row else None

    async def delete_oauth_pending(self, pending_id: str) -> bool:
        cursor = await self.db.execute(
            "DELETE FROM oauth_pending WHERE id = ?", (pending_id,)
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def create_oauth_code(
        self, client_id: str, wiki_user_id: int, params: str
    ) -> tuple[str, int]:
        """Issue an authorization code; returns (code, expires_at)."""
        code = secrets.token_urlsafe(32)
        expires_at = self._now() + OAUTH_CODE_TTL
        await self.db.execute(
            """
            INSERT INTO oauth_codes (code_hash, client_id, wiki_user_id, params, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (hash_secret(code), client_id, wiki_user_id, params, expires_at),
        )
        await self.db.commit()
        return code, expires_at

    async def get_oauth_code(
        self, client_id: str, code: str
    ) -> tuple[int, str, int] | None:
        """(wiki_user_id, params, expires_at) of a code issued to this client."""
        async with self.db.execute(
            """
            SELECT wiki_user_id, params, expires_at FROM oauth_codes
            WHERE code_hash = ? AND client_id = ? AND expires_at > ?
            """,
            (hash_secret(code), client_id, self._now()),
        ) as cursor:
            row = await cursor.fetchone()
        return (row["wiki_user_id"], row["params"], row["expires_at"]) if row else None

    async def consume_oauth_code(self, client_id: str, code: str) -> bool:
        """Use a code once; returns False if it was already used."""
        cursor = await self.db.execute(
            "DELETE FROM oauth_codes WHERE code_hash = ? AND client_id = ?",
            (hash_secret(code), client_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def user_login_is_current(self, wiki_user_id: int, jwt_renewal: int) -> bool:
        """Whether the user's last SSO login is within session_max_age and the stored
        Wiki.js JWT can still be renewed (it lapses after `jwt_renewal` unused)."""
        now = self._now()
        async with self.db.execute(
            """
            SELECT 1 FROM users
            WHERE wiki_user_id = ? AND login_at > ? AND jwt_encrypted IS NOT NULL
              AND jwt_exp + ? > ?
            """,
            (wiki_user_id, now - self._session_max_age, jwt_renewal, now),
        ) as cursor:
            return await cursor.fetchone() is not None

    async def create_refresh_token(
        self, client_id: str, wiki_user_id: int, scopes: list[str]
    ) -> tuple[str, int]:
        """Issue a refresh token, valid until the user's login must be renewed."""
        async with self.db.execute(
            "SELECT login_at FROM users WHERE wiki_user_id = ?", (wiki_user_id,)
        ) as cursor:
            login_at = (await cursor.fetchone())["login_at"]
        token = "wikimcp_rt_" + secrets.token_urlsafe(32)
        expires_at = login_at + self._session_max_age
        await self.db.execute(
            """
            INSERT INTO oauth_refresh_tokens
                (token_hash, client_id, wiki_user_id, scopes, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                hash_secret(token),
                client_id,
                wiki_user_id,
                " ".join(scopes),
                self._now(),
                expires_at,
            ),
        )
        await self.db.commit()
        return token, expires_at

    async def get_refresh_token(
        self, client_id: str, token: str
    ) -> tuple[int, list[str], int] | None:
        """(wiki_user_id, scopes, expires_at) of a usable refresh token."""
        now = self._now()
        async with self.db.execute(
            """
            SELECT r.wiki_user_id, r.scopes, r.expires_at
            FROM oauth_refresh_tokens r JOIN users u USING (wiki_user_id)
            WHERE r.token_hash = ? AND r.client_id = ? AND r.revoked_at IS NULL
              AND r.expires_at > ? AND u.login_at > ?
            """,
            (hash_secret(token), client_id, now, now - self._session_max_age),
        ) as cursor:
            row = await cursor.fetchone()
        if row is None:
            return None
        return row["wiki_user_id"], row["scopes"].split(), row["expires_at"]

    async def revoke_refresh_token(self, client_id: str, token: str) -> bool:
        """Revoke one refresh token (rotation); False if it was not usable."""
        cursor = await self.db.execute(
            """
            UPDATE oauth_refresh_tokens SET revoked_at = ?
            WHERE token_hash = ? AND client_id = ? AND revoked_at IS NULL
            """,
            (self._now(), hash_secret(token), client_id),
        )
        await self.db.commit()
        return cursor.rowcount == 1

    async def revoke_oauth_grant(self, wiki_user_id: int, client_id: str) -> None:
        """Revoke all access and refresh tokens of one app for one user."""
        now = self._now()
        await self.db.execute(
            """
            UPDATE oauth_refresh_tokens SET revoked_at = ?
            WHERE wiki_user_id = ? AND client_id = ? AND revoked_at IS NULL
            """,
            (now, wiki_user_id, client_id),
        )
        await self.db.execute(
            """
            UPDATE mcp_tokens SET revoked_at = ?
            WHERE wiki_user_id = ? AND client_id = ? AND kind = 'oauth'
              AND revoked_at IS NULL
            """,
            (now, wiki_user_id, client_id),
        )
        await self.db.commit()

    async def list_oauth_grants(self, wiki_user_id: int) -> list[dict[str, Any]]:
        """Apps holding a usable refresh token for this user."""
        async with self.db.execute(
            """
            SELECT r.client_id, c.client_info, MIN(r.created_at) AS since,
                   MAX(r.created_at) AS last_refresh
            FROM oauth_refresh_tokens r JOIN oauth_clients c USING (client_id)
            WHERE r.wiki_user_id = ? AND r.revoked_at IS NULL AND r.expires_at > ?
            GROUP BY r.client_id
            ORDER BY last_refresh DESC
            """,
            (wiki_user_id, self._now()),
        ) as cursor:
            return [dict(row) for row in await cursor.fetchall()]

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
        await self.db.execute(
            "DELETE FROM oauth_pending WHERE created_at <= ?",
            (now - OAUTH_PENDING_TTL,),
        )
        await self.db.execute("DELETE FROM oauth_codes WHERE expires_at <= ?", (now,))
        await self.db.execute(
            """
            DELETE FROM oauth_refresh_tokens
            WHERE expires_at <= ? OR revoked_at <= ?
            """,
            (now - revoked_retention, now - revoked_retention),
        )
        # Registrations nobody completed a login with (dynamic registration is open)
        await self.db.execute(
            """
            DELETE FROM oauth_clients
            WHERE created_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM oauth_refresh_tokens r
                  WHERE r.client_id = oauth_clients.client_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM mcp_tokens t WHERE t.client_id = oauth_clients.client_id
              )
            """,
            (now - 86400,),
        )
        await self.db.commit()
