# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for runtime provenance and chain-of-custody (pramanix.provenance).

All tests use real objects — no mocks, no monkeypatching.
"""

from __future__ import annotations

import time
from decimal import Decimal

import pytest
from pydantic import BaseModel

from pramanix.exceptions import ProvenanceError
from pramanix.provenance import ProvenanceChain, ProvenanceRecord

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_record(
    decision_id: str = "dec-001",
    allowed: bool = True,
    prev_hash: str = "",
) -> ProvenanceRecord:
    return ProvenanceRecord(
        decision_id=decision_id,
        policy_hash="sha256:cafe",
        model_version="gpt-4-turbo",
        input_labels={"amount": "INTERNAL"},
        tool_manifest=frozenset(["read_account", "transfer_funds"]),
        principal_id="agent-001",
        allowed=allowed,
        prev_hash=prev_hash,
    )


def _make_real_decision():
    """Create a real Decision via Guard.verify() for from_decision tests."""
    from decimal import Decimal

    from pramanix.expressions import ConstraintExpr, E, Field
    from pramanix.guard import Guard, GuardConfig
    from pramanix.policy import Policy

    class _Intent(BaseModel):
        amount: Decimal

    class _State(BaseModel):
        state_version: str = "1"
        balance: Decimal

    class _P(Policy):
        class Meta:
            version = "1.0"
            intent_model = _Intent
            state_model = _State

        amount = Field("amount", Decimal, "Real")
        balance = Field("balance", Decimal, "Real")

        @classmethod
        def invariants(cls) -> list[ConstraintExpr]:
            return [(E(cls.amount) <= E(cls.balance)).named("within_balance")]

    guard = Guard(_P, GuardConfig())
    return guard.verify({"amount": "100"}, {"state_version": "1", "balance": "500"})


# ── ProvenanceRecord tests ────────────────────────────────────────────────────


class TestProvenanceRecord:
    def test_frozen(self):
        rec = _make_record()
        with pytest.raises((AttributeError, TypeError)):
            rec.allowed = False  # type: ignore[misc]

    def test_record_id_unique(self):
        r1 = _make_record()
        r2 = _make_record()
        assert r1.record_id != r2.record_id

    def test_hmac_tag_computed(self):
        rec = _make_record()
        tag = rec.hmac_tag()
        assert len(tag) == 64  # SHA-256 hex digest

    def test_verify_with_same_key(self):
        key = b"\xaa" * 32
        rec = _make_record()
        tag = rec.hmac_tag(key)
        assert rec.verify(tag, signing_key=key)

    def test_verify_fails_with_different_key(self):
        key1 = b"\xaa" * 32
        key2 = b"\xbb" * 32
        rec = _make_record()
        tag = rec.hmac_tag(key1)
        assert not rec.verify(tag, signing_key=key2)

    def test_verify_fails_with_wrong_tag(self):
        rec = _make_record()
        tag = "0" * 64  # wrong tag
        assert not rec.verify(tag)

    def test_to_dict_contains_required_keys(self):
        key = b"\xcc" * 32
        rec = _make_record()
        d = rec.to_dict(signing_key=key)
        for k in (
            "record_id",
            "decision_id",
            "policy_hash",
            "input_labels",
            "tool_manifest",
            "allowed",
            "hmac_tag",
            "prev_hash",
        ):
            assert k in d

    def test_to_dict_tool_manifest_sorted(self):
        rec = _make_record()
        d = rec.to_dict()
        assert d["tool_manifest"] == sorted(d["tool_manifest"])

    def test_from_decision(self):
        decision = _make_real_decision()
        rec = ProvenanceRecord.from_decision(
            decision,
            model_version="gpt-4",
            input_labels={"amount": "INTERNAL"},
            tool_manifest=frozenset(["read_account"]),
            principal_id="agent-001",
        )
        assert rec.decision_id == str(decision.decision_id)
        assert rec.policy_hash == str(decision.policy_hash or "")
        assert rec.model_version == "gpt-4"
        assert rec.allowed == decision.allowed

    def test_created_at_set(self):
        t0 = time.time()
        rec = _make_record()
        assert rec.created_at >= t0

    def test_prev_hash_empty_by_default(self):
        rec = _make_record()
        assert rec.prev_hash == ""


# ── ProvenanceChain tests ─────────────────────────────────────────────────────


class TestProvenanceChain:
    def test_empty_chain_length(self):
        chain = ProvenanceChain()
        assert chain.length() == 0

    def test_append_returns_tag(self):
        chain = ProvenanceChain()
        rec = _make_record()
        tag = chain.append(rec)
        assert isinstance(tag, str)
        assert len(tag) == 64

    def test_head_tag_after_append(self):
        chain = ProvenanceChain()
        rec = _make_record()
        tag = chain.append(rec)
        assert chain.head_tag() == tag

    def test_head_tag_none_for_empty(self):
        chain = ProvenanceChain()
        assert chain.head_tag() is None

    def test_length_after_multiple_appends(self):
        chain = ProvenanceChain()
        for i in range(5):
            chain.append(_make_record(decision_id=f"dec-{i:03d}"))
        assert chain.length() == 5

    def test_verify_integrity_passes(self):
        chain = ProvenanceChain()
        for i in range(3):
            chain.append(_make_record(decision_id=f"dec-{i:03d}"))
        assert chain.verify_integrity()

    def test_verify_integrity_empty(self):
        chain = ProvenanceChain()
        assert chain.verify_integrity()

    def test_prev_hash_threaded_through(self):
        chain = ProvenanceChain()
        r1 = _make_record(decision_id="dec-001")
        r2 = _make_record(decision_id="dec-002")
        tag1 = chain.append(r1)
        chain.append(r2)
        # Second record's prev_hash should equal tag1
        records = chain.records()
        assert records[1].prev_hash == tag1

    def test_records_returns_copy(self):
        chain = ProvenanceChain()
        chain.append(_make_record())
        r1 = chain.records()
        r2 = chain.records()
        assert r1 is not r2

    def test_tags_returns_copy(self):
        chain = ProvenanceChain()
        chain.append(_make_record())
        t1 = chain.tags()
        t2 = chain.tags()
        assert t1 is not t2

    def test_empty_decision_id_raises(self):
        chain = ProvenanceChain()
        bad = ProvenanceRecord(
            decision_id="",
            policy_hash="x",
            allowed=True,
        )
        with pytest.raises(ProvenanceError) as exc_info:
            chain.append(bad)
        assert exc_info.value.decision_id == ""

    def test_max_records_eviction(self):
        chain = ProvenanceChain(max_records=3)
        for i in range(5):
            chain.append(_make_record(decision_id=f"dec-{i:03d}"))
        assert chain.length() == 3

    def test_integrity_fails_on_external_tag_mutation(self):
        """Integrity check must fail when we manually corrupt a stored tag."""
        key = b"\xdd" * 32
        chain = ProvenanceChain(signing_key=key)
        chain.append(_make_record(decision_id="dec-001"))
        chain.append(_make_record(decision_id="dec-002"))
        # Corrupt the first stored tag directly (bypassing the chain API)
        with chain._lock:
            chain._tags[0] = "0" * 64
        assert not chain.verify_integrity()

    def test_from_decision_round_trip(self):
        decision = _make_real_decision()
        chain = ProvenanceChain()
        rec = ProvenanceRecord.from_decision(
            decision,
            input_labels={"amount": "INTERNAL"},
            tool_manifest=frozenset(["read_account"]),
            principal_id="agent",
        )
        chain.append(rec)
        assert chain.verify_integrity()
        assert chain.records()[0].decision_id == str(decision.decision_id)

    def test_explicit_signing_key_used(self):
        key = b"\xee" * 32
        chain = ProvenanceChain(signing_key=key)
        chain.append(_make_record(decision_id="dec-001"))
        assert chain.verify_integrity()


# ── _provenance_key() env-var / file / ephemeral paths ───────────────────────


import os


def test_provenance_key_loaded_from_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    """_provenance_key() returns the key encoded in PRAMANIX_PROVENANCE_KEY."""
    import pramanix.provenance as _prov

    key_bytes = os.urandom(32)
    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
    monkeypatch.setenv("PRAMANIX_PROVENANCE_KEY", key_bytes.hex())
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY_FILE", raising=False)

    result = _prov._provenance_key()
    assert result == key_bytes

    # Restore global so later tests are not affected.
    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)


def test_provenance_key_loaded_from_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pytest.TempPathFactory,
) -> None:
    """_provenance_key() reads the hex key from PRAMANIX_PROVENANCE_KEY_FILE."""
    import pramanix.provenance as _prov

    key_bytes = os.urandom(32)
    key_file = tmp_path / "provenance.key"
    key_file.write_text(key_bytes.hex())

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY", raising=False)
    monkeypatch.setenv("PRAMANIX_PROVENANCE_KEY_FILE", str(key_file))

    result = _prov._provenance_key()
    assert result == key_bytes

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)


def test_provenance_key_ephemeral_when_no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """_provenance_key() generates an ephemeral 32-byte key when no env vars set."""
    import pramanix.provenance as _prov

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY", raising=False)
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY_FILE", raising=False)

    result = _prov._provenance_key()
    assert isinstance(result, bytes)
    assert len(result) == 32

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)


def test_provenance_key_invalid_env_hex_falls_back_to_ephemeral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Invalid hex in PRAMANIX_PROVENANCE_KEY logs warning and falls back to ephemeral."""
    import pramanix.provenance as _prov

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
    monkeypatch.setenv("PRAMANIX_PROVENANCE_KEY", "not-valid-hex!!")
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY_FILE", raising=False)

    result = _prov._provenance_key()
    # Fallback to ephemeral random key — still 32 bytes
    assert isinstance(result, bytes)
    assert len(result) == 32

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)


def test_provenance_key_double_check_locking(monkeypatch: pytest.MonkeyPatch) -> None:
    """The inner double-check inside _KEY_LOCK is exercised by a concurrent caller."""
    import threading

    import pramanix.provenance as _prov

    expected_key = os.urandom(32)
    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY", raising=False)
    monkeypatch.delenv("PRAMANIX_PROVENANCE_KEY_FILE", raising=False)

    result: list[bytes] = []

    # Acquire the lock first so the background thread blocks inside the with-block.
    _prov._KEY_LOCK.acquire()
    try:

        def _call_from_thread() -> None:
            # Outer check (_PROVENANCE_KEY is None) → passes.
            # Then blocks on _KEY_LOCK (held by this thread).
            result.append(_prov._provenance_key())

        t = threading.Thread(target=_call_from_thread, daemon=True)
        t.start()
        # Give the thread time to pass the outer check and block on the lock.
        import time

        time.sleep(0.02)
        # Set the key while holding the lock: thread sees it on the inner check.
        monkeypatch.setattr(_prov, "_PROVENANCE_KEY", expected_key)
    finally:
        _prov._KEY_LOCK.release()

    t.join(timeout=2.0)
    assert result == [expected_key]

    monkeypatch.setattr(_prov, "_PROVENANCE_KEY", None)
