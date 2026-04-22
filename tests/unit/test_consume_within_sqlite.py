# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for SQLiteExecutionTokenVerifier.consume_within (TOCTOU gap closure)."""
from __future__ import annotations

import sqlite3
import time

import pytest

from pramanix.decision import Decision, SolverStatus
from pramanix.execution_token import ExecutionTokenSigner, SQLiteExecutionTokenVerifier

_SECRET = b"test_secret_key_16bytes!"


def _allowed_decision() -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        violated_invariants=(),
        explanation="allowed",
    )


@pytest.fixture()
def signer() -> ExecutionTokenSigner:
    return ExecutionTokenSigner(_SECRET, ttl_seconds=60.0)


@pytest.fixture()
def verifier() -> SQLiteExecutionTokenVerifier:
    return SQLiteExecutionTokenVerifier(_SECRET, ":memory:")


# ── Basic happy-path ──────────────────────────────────────────────────────────


def test_consume_within_returns_true_on_valid_token(signer, verifier) -> None:
    token = signer.mint(_allowed_decision())
    conn = sqlite3.connect(":memory:")
    try:
        result = verifier.consume_within(conn, token)
        assert result is True
    finally:
        conn.close()


def test_consume_within_second_call_returns_false(signer, verifier) -> None:
    """Token is single-use — second consume_within on same conn returns False."""
    token = signer.mint(_allowed_decision())
    conn = sqlite3.connect(":memory:")
    try:
        assert verifier.consume_within(conn, token) is True
        assert verifier.consume_within(conn, token) is False
    finally:
        conn.close()


def test_consume_within_different_conns_second_fails(signer, verifier) -> None:
    """Two separate connections that share underlying DB — second must fail."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        token = signer.mint(_allowed_decision())
        conn1 = sqlite3.connect(db_path)
        conn2 = sqlite3.connect(db_path)
        try:
            assert verifier.consume_within(conn1, token) is True
            conn1.commit()
            assert verifier.consume_within(conn2, token) is False
        finally:
            conn1.close()
            conn2.close()
    finally:
        os.unlink(db_path)


# ── Rejection cases ───────────────────────────────────────────────────────────


def test_consume_within_rejects_tampered_signature(signer, verifier) -> None:
    from dataclasses import replace

    token = signer.mint(_allowed_decision())
    bad_token = replace(token, signature="deadbeef" * 8)
    conn = sqlite3.connect(":memory:")
    try:
        assert verifier.consume_within(conn, bad_token) is False
    finally:
        conn.close()


def test_consume_within_rejects_expired_token(signer, verifier) -> None:
    from dataclasses import replace
    import hmac as _hmac, hashlib as _hashlib
    from pramanix.execution_token import _token_body  # type: ignore[attr-defined]

    token = signer.mint(_allowed_decision())
    # Force expiry by replacing expires_at with the past and re-signing.
    expired = replace(token, expires_at=time.time() - 1.0, signature="")
    body = _token_body(expired)
    sig = _hmac.new(_SECRET, body, _hashlib.sha256).hexdigest()
    expired_signed = replace(expired, signature=sig)

    conn = sqlite3.connect(":memory:")
    try:
        assert verifier.consume_within(conn, expired_signed) is False
    finally:
        conn.close()


def test_consume_within_rejects_wrong_state_version(signer, verifier) -> None:
    token = signer.mint(_allowed_decision(), state_version="v1")
    conn = sqlite3.connect(":memory:")
    try:
        assert verifier.consume_within(conn, token, expected_state_version="v2") is False
        assert verifier.consume_within(conn, token, expected_state_version="v1") is True
    finally:
        conn.close()


# ── Transactional atomicity ───────────────────────────────────────────────────


def test_consume_within_rollback_allows_replay(signer, verifier) -> None:
    """If the caller rolls back, consume_within rollback also undoes token consumption."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        token = signer.mint(_allowed_decision())
        conn = sqlite3.connect(db_path)
        try:
            assert verifier.consume_within(conn, token) is True
            # Simulate business failure — roll back without committing.
            conn.rollback()
        finally:
            conn.close()

        # After rollback the token should still be consumable.
        conn2 = sqlite3.connect(db_path)
        try:
            assert verifier.consume_within(conn2, token) is True
            conn2.commit()
        finally:
            conn2.close()
    finally:
        os.unlink(db_path)


def test_consume_within_commit_prevents_replay(signer, verifier) -> None:
    """After a successful commit, the same token must not be accepted again."""
    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    try:
        token = signer.mint(_allowed_decision())
        conn = sqlite3.connect(db_path)
        try:
            assert verifier.consume_within(conn, token) is True
            conn.commit()
        finally:
            conn.close()

        conn2 = sqlite3.connect(db_path)
        try:
            assert verifier.consume_within(conn2, token) is False
        finally:
            conn2.close()
    finally:
        os.unlink(db_path)


# ── Table auto-creation ───────────────────────────────────────────────────────


def test_consume_within_creates_table_on_new_connection(signer, verifier) -> None:
    """consume_within must create the consumed_tokens table if absent."""
    conn = sqlite3.connect(":memory:")
    try:
        # Table should not exist yet.
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='consumed_tokens'"
        ).fetchall()
        assert tables == []

        token = signer.mint(_allowed_decision())
        verifier.consume_within(conn, token)

        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='consumed_tokens'"
        ).fetchall()
        assert len(tables) == 1
    finally:
        conn.close()
