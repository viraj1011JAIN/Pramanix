# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Comprehensive tests for PostgresExecutionTokenVerifier.

Uses a proper in-memory fake asyncpg connection — NOT mocks.  The fake
implements the real asyncpg interface with actual logic (dict-backed storage,
real UniqueViolationError on duplicate PK, real connection lifecycle).

Coverage targets:
  execution_token.py lines 130, 781, 884, 898-919, 921-922, 926-932,
  964-984, 1002-1015, 1023, 1026-1037, 1045, 1080-1117
"""
from __future__ import annotations

import sys
import threading
import time
from typing import Any

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.execution_token import ExecutionTokenSigner

_SECRET = b"test_secret_key_32_bytes_exact!!"


# ── Proper fake asyncpg (NOT a mock — real logic, real exceptions) ─────────────


class _FakeUniqueViolationError(Exception):
    """Real exception class for duplicate primary-key inserts."""


# Shared in-memory databases keyed by DSN string.
_FAKE_DBS: dict[str, dict[str, Any]] = {}


class _FakeAsyncpgConnection:
    """Asyncpg-compatible connection backed by an in-memory dict.

    Implements execute() / fetchrow() / close() with real SQL-like logic.
    Parameters use asyncpg's $1/$2 positional syntax.
    """

    def __init__(self, db: dict[str, Any]) -> None:
        self._db = db

    async def execute(self, query: str, *args: Any) -> str:
        q = query.strip().upper()
        if "CREATE TABLE IF NOT EXISTS CONSUMED_TOKENS" in q:
            self._db.setdefault("consumed_tokens", {})
            return "CREATE TABLE"
        if "CREATE INDEX IF NOT EXISTS" in q:
            return "CREATE INDEX"
        if q.startswith("INSERT INTO CONSUMED_TOKENS"):
            table: dict[str, float] = self._db.setdefault("consumed_tokens", {})
            token_id = str(args[0])
            if token_id in table:
                raise _FakeUniqueViolationError(f"duplicate key value: {token_id!r}")
            table[token_id] = float(args[1])
            return "INSERT 0 1"
        if "DELETE FROM CONSUMED_TOKENS WHERE EXPIRES_AT" in q:
            table = self._db.get("consumed_tokens", {})
            cutoff = float(args[0])
            expired = [k for k, exp in table.items() if exp < cutoff]
            for k in expired:
                del table[k]
            return f"DELETE {len(expired)}"
        return ""

    async def fetchrow(self, query: str, *args: Any) -> dict[str, Any] | None:
        if "COUNT(*)" in query.upper():
            table = self._db.get("consumed_tokens", {})
            cutoff = float(args[0])
            return {"n": sum(1 for exp in table.values() if exp >= cutoff)}
        return None

    async def close(self) -> None:
        pass


class _FakeAsyncpgModule:
    """Drop-in replacement for the asyncpg package.

    Exposes UniqueViolationError and a connect() coroutine that returns
    a _FakeAsyncpgConnection backed by the module-level _FAKE_DBS store.
    """

    UniqueViolationError = _FakeUniqueViolationError

    @staticmethod
    async def connect(dsn: str) -> _FakeAsyncpgConnection:
        db = _FAKE_DBS.setdefault(dsn, {})
        return _FakeAsyncpgConnection(db)


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _fake_asyncpg_in_sys_modules() -> Any:
    """Inject fake asyncpg into sys.modules for every test in this module.

    Methods inside PostgresExecutionTokenVerifier do `import asyncpg` at
    call time — not at class definition time — so patching sys.modules before
    each call is sufficient.  No module deletion/reimport required.
    """
    prev = sys.modules.get("asyncpg")
    sys.modules["asyncpg"] = _FakeAsyncpgModule()  # type: ignore[assignment]
    yield
    if prev is None:
        sys.modules.pop("asyncpg", None)
    else:
        sys.modules["asyncpg"] = prev


@pytest.fixture()
def signer() -> ExecutionTokenSigner:
    return ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)


@pytest.fixture()
def verifier() -> Any:
    """Return a fresh PostgresExecutionTokenVerifier with an isolated in-memory DB."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    dsn = f"fake://testdb_{id(object())}"
    v = PostgresExecutionTokenVerifier(_SECRET, dsn)
    yield v
    _FAKE_DBS.pop(dsn, None)


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed",
    )


# ── ExecutionToken.is_allowed() ───────────────────────────────────────────────


def test_is_allowed_returns_true_for_allowed_token(signer: ExecutionTokenSigner) -> None:
    token = signer.mint(_allowed_decision())
    assert token.is_allowed() is True


def test_is_allowed_returns_false_for_denied_token() -> None:
    from pramanix.execution_token import ExecutionToken

    token = ExecutionToken(
        decision_id="x",
        allowed=False,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() + 60,
        token_id="t1",
        signature="",
    )
    assert token.is_allowed() is False


# ── Constructor validation ────────────────────────────────────────────────────


def test_init_raises_value_error_for_short_key() -> None:
    """Line 884: ValueError when secret_key < 16 bytes."""
    from pramanix.execution_token import PostgresExecutionTokenVerifier

    with pytest.raises(ValueError, match="at least 16 bytes"):
        PostgresExecutionTokenVerifier(b"tooshort", "postgresql://test/db")


def test_init_succeeds_with_valid_key(verifier: Any) -> None:
    assert verifier._key == _SECRET


def test_init_stores_dsn(verifier: Any) -> None:
    assert "fake://" in verifier._dsn


# ── consume() — happy path ────────────────────────────────────────────────────


def test_consume_valid_token_returns_true(signer: ExecutionTokenSigner, verifier: Any) -> None:
    token = signer.mint(_allowed_decision())
    assert verifier.consume(token) is True


def test_consume_second_call_returns_false(signer: ExecutionTokenSigner, verifier: Any) -> None:
    token = signer.mint(_allowed_decision())
    assert verifier.consume(token) is True
    assert verifier.consume(token) is False


# ── consume() — rejection paths ──────────────────────────────────────────────


def test_consume_rejects_tampered_signature(signer: ExecutionTokenSigner, verifier: Any) -> None:
    from dataclasses import replace

    token = signer.mint(_allowed_decision())
    bad = replace(token, signature="deadbeef" * 8)
    assert verifier.consume(bad) is False


def test_consume_rejects_expired_token(verifier: Any) -> None:
    import hashlib
    import hmac

    from pramanix.execution_token import ExecutionToken, _token_body

    token = ExecutionToken(
        decision_id="d1",
        allowed=True,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() - 10.0,
        token_id="expired_token",
        signature="",
    )
    sig = hmac.new(_SECRET, _token_body(token), hashlib.sha256).hexdigest()
    expired = __import__("dataclasses").replace(token, signature=sig)
    assert verifier.consume(expired) is False


def test_consume_rejects_state_version_mismatch(signer: ExecutionTokenSigner, verifier: Any) -> None:
    token = signer.mint(_allowed_decision(), state_version="v1")
    assert verifier.consume(token, expected_state_version="v2") is False


def test_consume_accepts_matching_state_version(signer: ExecutionTokenSigner, verifier: Any) -> None:
    token = signer.mint(_allowed_decision(), state_version="v1")
    assert verifier.consume(token, expected_state_version="v1") is True


def test_consume_token_version_none_expected_version_set(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    """Token without state_version but caller passes expected_state_version → reject."""
    token = signer.mint(_allowed_decision())
    assert token.state_version is None
    assert verifier.consume(token, expected_state_version="v1") is False


# ── _run() with running event loop (lines 898-919) ───────────────────────────


@pytest.mark.asyncio
async def test_consume_from_async_context(signer: ExecutionTokenSigner, verifier: Any) -> None:
    """_run() dispatches to a new thread when the event loop is already running.

    When called from an async context (pytest-asyncio's event loop IS running),
    _run() detects loop.is_running() == True and executes the coroutine in a
    fresh thread with its own event loop.  Lines 898-919 are covered here.
    """
    token = signer.mint(_allowed_decision())
    result = verifier.consume(token)
    assert result is True


@pytest.mark.asyncio
async def test_consume_replay_prevented_from_async_context(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    token = signer.mint(_allowed_decision())
    assert verifier.consume(token) is True
    assert verifier.consume(token) is False


# ── _run() fallback via asyncio.run() (lines 921-922) ────────────────────────


def test_consume_from_non_main_thread(signer: ExecutionTokenSigner, verifier: Any) -> None:
    """_run() calls asyncio.run() when no event loop exists in a worker thread.

    Python 3.12+: asyncio.get_event_loop() in a thread without an explicit
    event loop raises RuntimeError, triggering the except branch (lines 921-922).
    """
    token = signer.mint(_allowed_decision())
    result_container: list[bool] = []

    def _thread_body() -> None:
        result_container.append(verifier.consume(token))

    t = threading.Thread(target=_thread_body)
    t.start()
    t.join()
    assert result_container == [True]


def test_consume_thread_replay_prevention(signer: ExecutionTokenSigner, verifier: Any) -> None:
    """Single-use enforcement works consistently across thread-based _run() paths."""
    token = signer.mint(_allowed_decision())
    outcomes: list[bool] = []

    def _thread_body() -> None:
        outcomes.append(verifier.consume(token))
        outcomes.append(verifier.consume(token))

    t = threading.Thread(target=_thread_body)
    t.start()
    t.join()
    assert outcomes == [True, False]


# ── evict_expired() (lines 1002-1015, 1023) ──────────────────────────────────


def test_evict_expired_removes_stale_tokens(signer: ExecutionTokenSigner, verifier: Any) -> None:
    """evict_expired() deletes expired rows and returns the count.

    consume() refuses expired tokens (expiry check fires before INSERT), so we
    seed the fake DB directly — the same row the verifier would have written had
    the token been accepted before it aged out.
    """
    # Ensure the table exists in the fake DB by triggering a real consume first
    valid = signer.mint(_allowed_decision())
    verifier.consume(valid)

    # Directly seed one row with a past expiry into the shared fake DB
    db = _FAKE_DBS[verifier._dsn]
    db.setdefault("consumed_tokens", {})["stale_id"] = time.time() - 100.0

    deleted = verifier.evict_expired()
    assert deleted == 1


def test_evict_expired_returns_zero_when_nothing_stale(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    token = signer.mint(_allowed_decision())
    verifier.consume(token)
    assert verifier.evict_expired() == 0


def test_evict_expired_on_empty_db(verifier: Any) -> None:
    assert verifier.evict_expired() == 0


# ── consumed_count() (lines 1026-1037, 1045) ─────────────────────────────────


def test_consumed_count_zero_on_empty(verifier: Any) -> None:
    assert verifier.consumed_count() == 0


def test_consumed_count_reflects_active_tokens(signer: ExecutionTokenSigner, verifier: Any) -> None:
    token1 = signer.mint(_allowed_decision())
    token2 = signer.mint(_allowed_decision())
    verifier.consume(token1)
    verifier.consume(token2)
    assert verifier.consumed_count() == 2


def test_consumed_count_excludes_expired(signer: ExecutionTokenSigner, verifier: Any) -> None:
    """consumed_count() counts only non-expired entries."""
    import hashlib
    import hmac

    from pramanix.execution_token import ExecutionToken, _token_body

    expired = ExecutionToken(
        decision_id="d-exp2",
        allowed=True,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() - 200.0,
        token_id="exp_count_tk",
        signature="",
    )
    sig = hmac.new(_SECRET, _token_body(expired), hashlib.sha256).hexdigest()
    expired = __import__("dataclasses").replace(expired, signature=sig)

    valid = signer.mint(_allowed_decision())
    verifier.consume(expired)
    verifier.consume(valid)
    assert verifier.consumed_count() == 1


# ── consume_within() (lines 1080-1117) ───────────────────────────────────────


@pytest.mark.asyncio
async def test_consume_within_returns_true_for_valid_token(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    """consume_within() inserts within caller's conn — returns True on first call."""
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    token = signer.mint(_allowed_decision())
    result = await verifier.consume_within(conn, token)
    assert result is True


@pytest.mark.asyncio
async def test_consume_within_duplicate_returns_false(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    """Second consume_within call for same token returns False."""
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    token = signer.mint(_allowed_decision())
    assert await verifier.consume_within(conn, token) is True
    assert await verifier.consume_within(conn, token) is False


@pytest.mark.asyncio
async def test_consume_within_rejects_tampered_signature(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    from dataclasses import replace

    token = signer.mint(_allowed_decision())
    bad = replace(token, signature="badbad" * 8)
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn, bad) is False


@pytest.mark.asyncio
async def test_consume_within_rejects_expired(verifier: Any) -> None:
    import hashlib
    import hmac

    from pramanix.execution_token import ExecutionToken, _token_body

    token = ExecutionToken(
        decision_id="d-e",
        allowed=True,
        intent_dump={},
        policy_hash=None,
        expires_at=time.time() - 1.0,
        token_id="w-expired",
        signature="",
    )
    sig = hmac.new(_SECRET, _token_body(token), hashlib.sha256).hexdigest()
    token = __import__("dataclasses").replace(token, signature=sig)
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn, token) is False


@pytest.mark.asyncio
async def test_consume_within_rejects_wrong_state_version(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    token = signer.mint(_allowed_decision(), state_version="v1")
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn, token, expected_state_version="v2") is False


@pytest.mark.asyncio
async def test_consume_within_accepts_correct_state_version(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    token = signer.mint(_allowed_decision(), state_version="v1")
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn, token, expected_state_version="v1") is True


@pytest.mark.asyncio
async def test_consume_within_token_no_version_expected_version_set(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    token = signer.mint(_allowed_decision())
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn, token, expected_state_version="v1") is False


@pytest.mark.asyncio
async def test_consume_within_creates_table_if_absent(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    token = signer.mint(_allowed_decision())
    await verifier.consume_within(conn, token)
    assert "consumed_tokens" in db


@pytest.mark.asyncio
async def test_consume_within_rollback_semantics(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    """consume_within does NOT commit — caller controls the transaction boundary.

    Verify: after a 'rollback' (clearing the db dict manually to simulate), the
    same token can be consumed again.
    """
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    token = signer.mint(_allowed_decision())

    assert await verifier.consume_within(conn, token) is True
    db.clear()

    conn2 = _FakeAsyncpgConnection(db)
    assert await verifier.consume_within(conn2, token) is True


# ── _ensure_table() (lines 926-932) via consume_within ───────────────────────


@pytest.mark.asyncio
async def test_ensure_table_called_via_consume_within(
    signer: ExecutionTokenSigner, verifier: Any
) -> None:
    """_ensure_table() is invoked before INSERT; creates table and index."""
    db: dict[str, Any] = {}
    conn = _FakeAsyncpgConnection(db)
    token = signer.mint(_allowed_decision())
    await verifier.consume_within(conn, token)
    assert "consumed_tokens" in db


# ── Redis verifier state_version mismatch (line 781) ─────────────────────────


def test_redis_verifier_rejects_token_with_state_version_mismatch() -> None:
    """RedisExecutionTokenVerifier line 781: returns False when state_version != expected."""
    import fakeredis

    from pramanix.execution_token import ExecutionTokenSigner, RedisExecutionTokenVerifier

    signer = ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)
    redis = fakeredis.FakeRedis()
    verifier = RedisExecutionTokenVerifier(_SECRET, redis)

    token = signer.mint(_allowed_decision(), state_version="v1")
    assert verifier.consume(token, expected_state_version="v2") is False
    assert verifier.consume(token, expected_state_version="v1") is True
