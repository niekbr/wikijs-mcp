"""Tests for the SQLite store of users, tokens, web sessions and login states."""

import sqlite3
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from tests.conftest import TEST_FERNET_KEY
from tests.helpers import make_jwt
from wikijs_mcp.store import LOGIN_STATE_TTL, TOKEN_PREFIX, Store, hash_secret

DAY = 86400
MAX_AGE = 30 * DAY


class Clock:
    def __init__(self, now: float = 1_800_000_000):
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def profile(user_id=3, email="a@example.com", name="Lezer A"):
    return {"id": user_id, "email": email, "name": name, "groups": ["lezers"]}


def jwt_for(user_id=3, exp=None):
    """A JWT expiring at an absolute time (default: in 30 minutes)."""
    token = make_jwt(id=user_id)
    if exp is not None:
        token = make_jwt(id=user_id, exp=exp)
    return token


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "mcp.sqlite")


@pytest.fixture
async def store(db_path, clock):
    async with Store(db_path, TEST_FERNET_KEY, MAX_AGE, clock) as store:
        yield store


async def login(store, user_id=3, exp=2_000_000_000):
    jwt = jwt_for(user_id, exp)
    await store.upsert_login(jwt, profile(user_id))
    return jwt


@pytest.mark.unit
class TestUsersAndTokens:
    async def test_token_resolves_to_user_and_jwt(self, store, clock):
        jwt = await login(store)
        token_id, token = await store.create_token(3, "laptop", ttl=90 * DAY)

        user = await store.get_user_for_token(token)

        assert token.startswith(TOKEN_PREFIX)
        assert user.wiki_user_id == 3
        assert user.email == "a@example.com"
        assert user.name == "Lezer A"
        assert user.jwt == jwt
        assert user.token_id == token_id
        assert user.token_kind == "pat"
        assert user.token_expires_at == clock.now + 90 * DAY
        assert user.login_at == clock.now

    async def test_secrets_are_not_stored_readably(self, store, db_path):
        jwt = await login(store)
        _, token = await store.create_token(3, "laptop", ttl=DAY)
        session_id = await store.create_web_session(3, ttl=DAY)

        raw = b"".join(
            Path(f).read_bytes()
            for f in (db_path, db_path + "-wal")
            if Path(f).exists()
        )
        assert hash_secret(token).encode() in raw  # the check below is not vacuous
        with sqlite3.connect(db_path) as conn:
            dump = "\n".join(conn.iterdump())
        for secret in (jwt, token, session_id):
            assert secret not in dump
            assert secret.encode() not in raw
        assert hash_secret(token) in dump

    async def test_profile_must_match_jwt(self, store):
        with pytest.raises(ValueError, match="Profile"):
            await store.upsert_login(jwt_for(3), profile(user_id=4))

    async def test_unknown_token(self, store):
        await login(store)

        assert await store.get_user_for_token("wikimcp_nope") is None

    async def test_tokens_must_expire(self, store):
        await login(store)

        with pytest.raises(ValueError, match="expire"):
            await store.create_token(3, "forever", ttl=0)

    async def test_expired_token(self, store, clock):
        await login(store)
        _, token = await store.create_token(3, "kort", ttl=DAY)

        clock.advance(DAY)

        assert await store.get_user_for_token(token) is None

    async def test_revoked_token(self, store):
        await login(store)
        token_id, token = await store.create_token(3, "laptop", ttl=DAY)

        assert await store.revoke_token(3, token_id) is True
        assert await store.revoke_token(3, token_id) is False
        assert await store.get_user_for_token(token) is None

    async def test_cannot_revoke_someone_elses_token(self, store):
        await login(store, user_id=3)
        await login(store, user_id=4)
        token_id, token = await store.create_token(3, "laptop", ttl=DAY)

        assert await store.revoke_token(4, token_id) is False
        assert await store.get_user_for_token(token) is not None

    async def test_revoke_all_tokens(self, store):
        await login(store)
        _, t1 = await store.create_token(3, "a", ttl=DAY)
        _, t2 = await store.create_token(3, "b", ttl=DAY)

        assert await store.revoke_all_tokens(3) == 2
        assert await store.get_user_for_token(t1) is None
        assert await store.get_user_for_token(t2) is None

    async def test_session_max_age_requires_new_login(self, store, clock):
        await login(store)
        _, token = await store.create_token(3, "laptop", ttl=90 * DAY)

        clock.advance(MAX_AGE)
        assert await store.get_user_for_token(token) is None

        # Logging in again revives the same token, with the new JWT
        new_jwt = await login(store, exp=2_100_000_000)
        user = await store.get_user_for_token(token)
        assert user is not None
        assert user.jwt == new_jwt

    async def test_tokens_survive_login_with_new_jwt(self, store):
        await login(store, exp=2_000_000_000)
        _, token = await store.create_token(3, "laptop", ttl=DAY)

        new_jwt = await login(store, exp=1_900_000_000)  # a login always wins

        assert (await store.get_user_for_token(token)).jwt == new_jwt

    async def test_list_tokens(self, store, clock):
        await login(store)
        await store.create_token(3, "oud", ttl=10 * DAY)
        clock.advance(1)
        revoked_id, _ = await store.create_token(3, "ingetrokken", ttl=10 * DAY)
        await store.revoke_token(3, revoked_id)
        await store.create_token(3, "verlopen", ttl=1)
        clock.advance(1)
        await store.create_token(3, "nieuw", ttl=10 * DAY)

        tokens = await store.list_tokens(3)

        assert [t["name"] for t in tokens] == ["nieuw", "oud"]
        assert set(tokens[0]) == {
            "id",
            "name",
            "kind",
            "client_id",
            "created_at",
            "expires_at",
            "last_used_at",
        }

    async def test_touch(self, store, clock):
        await login(store)
        token_id, _ = await store.create_token(3, "laptop", ttl=DAY)
        clock.advance(60)

        await store.touch(token_id)

        assert (await store.list_tokens(3))[0]["last_used_at"] == clock.now
        async with store.db.execute("SELECT last_used_at FROM users") as cursor:
            assert (await cursor.fetchone())[0] == clock.now

    async def test_oauth_token_fields(self, store):
        await login(store)
        _, token = await store.create_token(
            3, "claude.ai", ttl=3600, kind="oauth", client_id="abc", scopes=["read"]
        )

        user = await store.get_user_for_token(token)

        assert user.token_kind == "oauth"
        assert user.client_id == "abc"
        assert user.scopes == ["read"]

    async def test_other_encryption_key_loses_jwt_not_token(self, db_path, clock):
        async with Store(db_path, TEST_FERNET_KEY, MAX_AGE, clock) as store:
            await login(store)
            _, token = await store.create_token(3, "laptop", ttl=DAY)

        other_key = Fernet.generate_key().decode()
        async with Store(db_path, other_key, MAX_AGE, clock) as store:
            user = await store.get_user_for_token(token)

        assert user is not None
        assert user.jwt is None

    async def test_delete_user_cascades(self, store):
        await login(store)
        _, token = await store.create_token(3, "laptop", ttl=DAY)
        session_id = await store.create_web_session(3, ttl=DAY)

        await store.delete_user(3)

        assert await store.get_user_for_token(token) is None
        assert await store.get_web_session(session_id) is None


@pytest.mark.unit
class TestUpdateJwt:
    async def test_only_later_expiry_wins(self, store):
        await login(store, exp=2_000_000_000)
        _, token = await store.create_token(3, "laptop", ttl=DAY)

        newer = jwt_for(3, exp=2_000_000_100)
        older = jwt_for(3, exp=2_000_000_050)
        assert await store.update_jwt(3, newer) is True
        assert await store.update_jwt(3, older) is False
        assert await store.update_jwt(3, newer) is False

        assert (await store.get_user_for_token(token)).jwt == newer

    async def test_rejects_other_users_jwt(self, store):
        await login(store, user_id=3)

        with pytest.raises(ValueError, match="does not belong"):
            await store.update_jwt(3, jwt_for(4, exp=2_100_000_000))

    async def test_does_not_extend_login(self, store, clock):
        await login(store, exp=2_000_000_000)
        _, token = await store.create_token(3, "laptop", ttl=90 * DAY)
        clock.advance(MAX_AGE - 10)

        await store.update_jwt(3, jwt_for(3, exp=2_100_000_000))
        clock.advance(10)

        assert await store.get_user_for_token(token) is None


@pytest.mark.unit
class TestWebSessionsAndLoginStates:
    async def test_web_session(self, store, clock):
        await login(store)
        session_id = await store.create_web_session(3, ttl=3600)

        session = await store.get_web_session(session_id)
        assert session.wiki_user_id == 3
        assert session.email == "a@example.com"
        assert len(session.csrf_secret) >= 32

        clock.advance(3600)
        assert await store.get_web_session(session_id) is None

    async def test_web_session_logout(self, store):
        await login(store)
        session_id = await store.create_web_session(3, ttl=3600)

        await store.delete_web_session(session_id)

        assert await store.get_web_session(session_id) is None

    async def test_web_session_respects_session_max_age(self, store, clock):
        await login(store)
        session_id = await store.create_web_session(3, ttl=60 * DAY)

        clock.advance(MAX_AGE)

        assert await store.get_web_session(session_id) is None

    async def test_login_state_single_use(self, store):
        state, binding = await store.create_login_state("/mcp/token")

        assert await store.consume_login_state(state, binding) == "/mcp/token"
        assert await store.consume_login_state(state, binding) is None

    async def test_login_state_bound_to_browser(self, store):
        state, _ = await store.create_login_state("/mcp/token")

        assert await store.consume_login_state(state, "other-browser") is None

    async def test_login_state_expires(self, store, clock):
        state, binding = await store.create_login_state("/mcp/token")

        clock.advance(LOGIN_STATE_TTL)

        assert await store.consume_login_state(state, binding) is None


@pytest.mark.unit
class TestPurge:
    async def test_stale_login_wipes_jwt_but_keeps_tokens(self, store, clock):
        await login(store)
        _, token = await store.create_token(3, "laptop", ttl=90 * DAY)
        clock.advance(MAX_AGE)

        await store.purge_expired()

        async with store.db.execute("SELECT jwt_encrypted FROM users") as cursor:
            assert (await cursor.fetchone())[0] is None
        new_jwt = await login(store)
        assert (await store.get_user_for_token(token)).jwt == new_jwt

    async def test_stale_user_without_tokens_is_deleted(self, store, clock):
        await login(store, user_id=3)
        await login(store, user_id=4)
        await store.create_token(4, "laptop", ttl=90 * DAY)
        clock.advance(MAX_AGE)

        await store.purge_expired()

        async with store.db.execute("SELECT wiki_user_id FROM users") as cursor:
            assert [row[0] for row in await cursor.fetchall()] == [4]

    async def test_old_revoked_and_expired_tokens_removed(self, store, clock):
        await login(store)
        old_revoked, _ = await store.create_token(3, "a", ttl=90 * DAY)
        await store.revoke_token(3, old_revoked)
        await store.create_token(3, "b", ttl=DAY)
        clock.advance(31 * DAY)
        recent_revoked, _ = await store.create_token(3, "c", ttl=90 * DAY)
        await store.revoke_token(3, recent_revoked)
        await login(store)  # keep the user

        await store.purge_expired(revoked_retention=30 * DAY)

        async with store.db.execute("SELECT name FROM mcp_tokens") as cursor:
            assert [row[0] for row in await cursor.fetchall()] == ["c"]

    async def test_expired_sessions_and_states_removed(self, store, clock):
        await login(store)
        await store.create_web_session(3, ttl=60)
        await store.create_login_state("/mcp/token")
        clock.advance(LOGIN_STATE_TTL)

        await store.purge_expired()

        for table in ("web_sessions", "login_states"):
            async with store.db.execute(f"SELECT COUNT(*) FROM {table}") as cursor:
                assert (await cursor.fetchone())[0] == 0


@pytest.mark.unit
class TestSchema:
    async def test_persists_across_reopen(self, db_path, clock):
        async with Store(db_path, TEST_FERNET_KEY, MAX_AGE, clock) as store:
            await login(store)
            _, token = await store.create_token(3, "laptop", ttl=DAY)

        async with Store(db_path, TEST_FERNET_KEY, MAX_AGE, clock) as store:
            assert await store.get_user_for_token(token) is not None

    async def test_refuses_newer_schema(self, db_path, clock):
        with sqlite3.connect(db_path) as conn:
            conn.execute("PRAGMA user_version = 99")

        with pytest.raises(RuntimeError, match="newer"):
            async with Store(db_path, TEST_FERNET_KEY, MAX_AGE, clock):
                pass

    async def test_not_open(self):
        store = Store(":memory:", TEST_FERNET_KEY, MAX_AGE)

        with pytest.raises(RuntimeError, match="not open"):
            await store.list_tokens(3)
