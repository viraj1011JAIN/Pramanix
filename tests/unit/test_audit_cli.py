# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for pramanix audit verify CLI (Phase 11.3).

Tests:
1. Valid JSONL file → exit 0, all [VALID]
2. Tampered record (amount changed) → exit 1, [TAMPERED]
3. Tampered allowed field → exit 1, [TAMPERED]
4. Wrong public key → exit 1, [INVALID_SIG]
5. Missing signature → [MISSING_SIG]
6. Malformed JSON line → [ERROR]
7. JSON output format is correct
8. Mixed file: valid + tampered → exit 1
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

pytest.importorskip("cryptography", reason="cryptography not installed")

from pramanix.crypto import PramanixSigner
from pramanix.decision import Decision


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_audit_record(decision: Decision, signer: PramanixSigner) -> dict:
    sig = signer.sign(decision)
    return {
        "decision_id": decision.decision_id,
        "decision_hash": decision.decision_hash,
        "signature": sig,
        "public_key_id": signer.key_id(),
        "allowed": decision.allowed,
        "status": str(decision.status.value if hasattr(decision.status, "value") else decision.status),
        "violated_invariants": list(decision.violated_invariants or []),
        "explanation": decision.explanation or "",
        "policy": str(decision.metadata.get("policy", "") if decision.metadata else ""),
        "intent_dump": decision.intent_dump or {},
        "state_dump": decision.state_dump or {},
    }


def _write_jsonl(records: list[dict], path: Path) -> None:
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _write_public_key(signer: PramanixSigner, path: Path) -> None:
    path.write_bytes(signer.public_key_pem())


def _run_audit_cli(
    log_path: Path, key_path: Path, extra_args: list | None = None
) -> tuple[int, str]:
    from pramanix.cli import main as cli_main

    args = ["pramanix", "audit", "verify", str(log_path), "--public-key", str(key_path)]
    if extra_args:
        args.extend(extra_args)

    old_argv = sys.argv
    old_stdout = sys.stdout
    sys.argv = args
    sys.stdout = io.StringIO()
    try:
        exit_code = cli_main()
        output = sys.stdout.getvalue()
    finally:
        sys.argv = old_argv
        sys.stdout = old_stdout

    return exit_code or 0, output


# ── Valid records ─────────────────────────────────────────────────────────────


class TestAuditCLIValid:
    def test_valid_log_exits_0(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([_make_audit_record(d, signer)], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 0
        assert "[VALID]" in output

    def test_multiple_valid_records_exits_0(self, tmp_path):
        signer = PramanixSigner.generate()
        records = []
        for i in range(10):
            d = Decision.safe(
                intent_dump={"amount": str(i * 100)},
                state_dump={"state_version": "v1"},
            )
            records.append(_make_audit_record(d, signer))

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl(records, log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 0
        assert output.count("[VALID]") == 10


# ── Tampered records ──────────────────────────────────────────────────────────


class TestAuditCLITampered:
    def test_tampered_amount_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"balance": "5000", "state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        record["intent_dump"]["amount"] = "999999"  # tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output

    def test_tampered_allowed_field_exits_1(self, tmp_path):
        """CRITICAL: flipping allowed=False to allowed=True must be detected."""
        signer = PramanixSigner.generate()
        d = Decision.unsafe(
            violated_invariants=("overdraft",),
            explanation="Insufficient balance",
            intent_dump={"amount": "9999"},
            state_dump={"balance": "100", "state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        assert record["allowed"] is False
        record["allowed"] = True  # tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output

    def test_tampered_violated_invariants_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.unsafe(
            violated_invariants=("rule_a",),
            explanation="Rule A violated",
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        record["violated_invariants"] = []  # tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[TAMPERED]" in output


# ── Invalid signature ─────────────────────────────────────────────────────────


class TestAuditCLIInvalidSig:
    def test_wrong_public_key_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([_make_audit_record(d, signer)], log_path)
        _write_public_key(wrong_signer, key_path)  # wrong key

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[INVALID_SIG]" in output

    def test_missing_signature_field_reports_missing(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        del record["signature"]

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[MISSING_SIG]" in output


# ── Edge cases ────────────────────────────────────────────────────────────────


class TestAuditCLIEdgeCases:
    def test_malformed_json_line_reports_error(self, tmp_path):
        signer = PramanixSigner.generate()
        key_path = tmp_path / "key.pem"
        _write_public_key(signer, key_path)

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{ this is not valid json {\n")

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[ERROR]" in output

    def test_mixed_valid_and_tampered_exits_1(self, tmp_path):
        signer = PramanixSigner.generate()
        d_valid = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        d_tampered = Decision.safe(
            intent_dump={"amount": "200"},
            state_dump={"state_version": "v1"},
        )
        r_valid = _make_audit_record(d_valid, signer)
        r_tampered = _make_audit_record(d_tampered, signer)
        r_tampered["intent_dump"]["amount"] = "999"  # tamper

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([r_valid, r_tampered], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path)
        assert code == 1
        assert "[VALID]" in output
        assert "[TAMPERED]" in output

    def test_json_output_is_parseable(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([_make_audit_record(d, signer)], log_path)
        _write_public_key(signer, key_path)

        _code, output = _run_audit_cli(log_path, key_path, ["--json"])
        parsed = json.loads(output)
        assert parsed["total"] == 1
        assert parsed["valid"] == 1
        assert parsed["all_valid"] is True

    def test_json_output_tampered_has_correct_fields(self, tmp_path):
        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        record = _make_audit_record(d, signer)
        record["allowed"] = True  # tamper (it was already True for safe(), so let's use unsafe)

        # Use a blocked decision and flip it
        d2 = Decision.unsafe(
            violated_invariants=("overdraft",),
            explanation="blocked",
            intent_dump={"amount": "9999"},
            state_dump={"state_version": "v1"},
        )
        record2 = _make_audit_record(d2, signer)
        record2["allowed"] = True  # tamper: flip blocked → allowed

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([record2], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path, ["--json"])
        parsed = json.loads(output)
        assert parsed["tampered"] == 1
        assert parsed["all_valid"] is False
        assert code == 1

    def test_fail_fast_stops_after_first_failure(self, tmp_path):
        """--fail-fast must stop at the first failure, not process remaining records."""
        signer = PramanixSigner.generate()

        # 10 records: first is tampered, rest are valid
        d_tampered = Decision.safe(
            intent_dump={"amount": "100"},
            state_dump={"state_version": "v1"},
        )
        tampered_record = _make_audit_record(d_tampered, signer)
        tampered_record["intent_dump"]["amount"] = "TAMPERED"  # break hash

        valid_records = []
        for i in range(9):
            d = Decision.safe(
                intent_dump={"amount": str(i + 200)},
                state_dump={"state_version": "v1"},
            )
            valid_records.append(_make_audit_record(d, signer))

        log_path = tmp_path / "audit.jsonl"
        key_path = tmp_path / "key.pem"
        _write_jsonl([tampered_record, *valid_records], log_path)
        _write_public_key(signer, key_path)

        code, output = _run_audit_cli(log_path, key_path, ["--fail-fast"])
        assert code == 1
        assert "[TAMPERED]" in output
        # With fail-fast, only 1 line processed — none of the 9 valid records should appear
        assert output.count("[VALID]") == 0


# ── Hash determinism ──────────────────────────────────────────────────────────


class TestHashDeterminism:
    def test_recompute_hash_matches_decision_compute_hash(self):
        """_recompute_hash() must produce the same value as Decision._compute_hash().

        This is the critical property that prevents false-TAMPERED reports when
        orjson is or isn't installed — both must use _canonical_bytes().
        """
        from pramanix.cli import _recompute_hash

        signer = PramanixSigner.generate()
        d = Decision.safe(
            intent_dump={"amount": "500", "currency": "USD"},
            state_dump={"balance": "10000", "state_version": "v1"},
        )
        record = _make_audit_record(d, signer)

        # The CLI must recompute the same hash as Decision._compute_hash()
        assert _recompute_hash(record) == d.decision_hash

    def test_recompute_hash_matches_unsafe_decision(self):
        """_recompute_hash() must match for BLOCK decisions too."""
        from pramanix.cli import _recompute_hash

        signer = PramanixSigner.generate()
        d = Decision.unsafe(
            violated_invariants=("overdraft", "daily_limit"),
            explanation="Insufficient balance",
            intent_dump={"amount": "9999"},
            state_dump={"balance": "100", "state_version": "v2"},
        )
        record = _make_audit_record(d, signer)
        assert _recompute_hash(record) == d.decision_hash
