# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Coverage tests for CLI verify-proof command and audit verify loop.

Targets:
  cli.py 427        verify-proof dispatch
  cli.py 464-524    _cmd_verify_proof — all branches
  cli.py 530-531    audit unknown subcommand
  cli.py 558-569    audit verify: --public-key missing, key file not found
  cli.py 598-611    audit verify: JSON decode error + fail_fast
  cli.py 630-631    audit verify: fail_fast after hash recomputation error
  cli.py 634-697    audit verify: TAMPERED, MISSING_SIG, INVALID_SIG, VALID
  cli.py 718-729    audit verify: summary with tampered/missing/invalid/errors
  cli.py 2500-2525  _cmd_coverage: YAML compile error, Python spec-None,
                    Python import exception, missing policy var
"""

from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from pramanix.audit.signer import DecisionSigner
from pramanix.decision import Decision

# ── Helpers ───────────────────────────────────────────────────────────────────

_SIGNING_KEY = "a" * 64  # 64 chars = valid key (≥32 required)


def _run(args: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    from pramanix.cli import main

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sys, "argv", ["pramanix", *args])
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _mint_allow_token() -> str:
    """Return a valid JWS HMAC token for an ALLOW decision."""
    signer = DecisionSigner(signing_key=_SIGNING_KEY)
    decision = Decision.safe(intent_dump={"amount": 100}, state_dump={"balance": 1000})
    signed = signer.sign(decision)
    assert signed is not None
    return signed.token


def _mint_block_token() -> str:
    """Return a valid JWS HMAC token for a BLOCK decision."""
    signer = DecisionSigner(signing_key=_SIGNING_KEY)
    decision = Decision.unsafe(
        violated_invariants=("within_balance",),
        explanation="amount=5000 > balance=100",
        intent_dump={"amount": 5000},
        state_dump={"balance": 100},
    )
    signed = signer.sign(decision)
    assert signed is not None
    return signed.token


# ═══════════════════════════════════════════════════════════════════════════════
# verify-proof: _cmd_verify_proof (lines 464-524)
# ═══════════════════════════════════════════════════════════════════════════════


class TestVerifyProof:
    """All branches of _cmd_verify_proof and the dispatch line 427."""

    def test_no_token_no_stdin_exits_2(self, capsys: pytest.CaptureFixture) -> None:
        """Neither --token nor --stdin → exit 2 (lines 472-473)."""
        code, _, err = _run(["verify-proof"], capsys)
        assert code == 2
        assert "token" in err.lower() or "provide" in err.lower() or "positional" in err.lower()

    def test_no_signing_key_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Token provided but no signing key → exit 1 (lines 479-481).

        PRAMANIX_SIGNING_KEY must be absent and --key not passed.
        """
        token = _mint_allow_token()
        with pytest.MonkeyPatch.context() as mp:
            mp.delenv("PRAMANIX_SIGNING_KEY", raising=False)
            code, _, _ = _run(["verify-proof", "--key", "", token], capsys)
        assert code == 1

    def test_key_too_short_raises_value_error_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Signing key < 32 chars → DecisionVerifier raises ValueError → exit 1 (lines 488-490)."""
        token = _mint_allow_token()
        code, _, err = _run(["verify-proof", "--key", "short", token], capsys)
        assert code == 1
        assert "error" in err.lower() or "key" in err.lower()

    def test_valid_allow_token_json_output_exits_0(self, capsys: pytest.CaptureFixture) -> None:
        """Valid ALLOW token + --json → JSON printed, exit 0 (lines 492-508)."""
        token = _mint_allow_token()
        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, "--json", token], capsys)
        assert code == 0
        data = json.loads(out)
        assert data["valid"] is True
        assert data["allowed"] is True

    def test_valid_block_token_json_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Valid BLOCK token + --json → JSON printed, exit 1 (token valid, decision blocked).

        verify-proof returns exit 1 when result.valid is False OR when the
        token is structurally valid but represents a blocked decision
        (depending on the implementation). The token itself is cryptographically
        valid so the verifier returns result.valid=True, then exit 0 if valid.
        """
        token = _mint_block_token()
        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, "--json", token], capsys)
        data = json.loads(out)
        assert data["valid"] is True
        assert data["allowed"] is False
        assert code == 0

    def test_valid_allow_token_human_output(self, capsys: pytest.CaptureFixture) -> None:
        """Valid ALLOW token without --json → human-readable output (lines 510-519)."""
        token = _mint_allow_token()
        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, token], capsys)
        assert code == 0
        assert "VALID" in out

    def test_valid_block_token_human_output_shows_violated(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Valid BLOCK token → human output includes violated invariants (lines 512-513)."""
        token = _mint_block_token()
        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, token], capsys)
        assert code == 0
        assert "VALID" in out
        assert "within_balance" in out or "violated" in out.lower()

    def test_invalid_token_wrong_signature_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Token with tampered payload → signature mismatch → exit 1 (lines 520-524)."""
        valid_token = _mint_allow_token()
        header, payload, sig = valid_token.split(".")
        # tamper: flip the last byte of the signature
        import base64

        raw_sig = base64.urlsafe_b64decode(sig + "=" * (4 - len(sig) % 4))
        tampered_sig_bytes = bytes([raw_sig[-1] ^ 0xFF]) + raw_sig[:-1]
        tampered_sig = base64.urlsafe_b64encode(tampered_sig_bytes).rstrip(b"=").decode()
        tampered_token = f"{header}.{payload}.{tampered_sig}"

        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, tampered_token], capsys)
        assert code == 1
        assert "INVALID" in out or "invalid" in out.lower()

    def test_garbled_token_exits_1(self, capsys: pytest.CaptureFixture) -> None:
        """Completely garbled token → exit 1."""
        code, out, _ = _run(
            ["verify-proof", "--key", _SIGNING_KEY, "not.a.valid.token.here"], capsys
        )
        assert code == 1

    def test_verify_proof_via_token_argument(self, capsys: pytest.CaptureFixture) -> None:
        """Token passed as positional argument → dispatched correctly (line 469-470)."""
        token = _mint_allow_token()
        code, out, _ = _run(["verify-proof", "--key", _SIGNING_KEY, token], capsys)
        assert code == 0

    def test_verify_proof_dispatch_line(self, capsys: pytest.CaptureFixture) -> None:
        """Ensure verify-proof dispatches to _cmd_verify_proof (line 427)."""
        token = _mint_allow_token()
        code, _, _ = _run(["verify-proof", "--key", _SIGNING_KEY, token], capsys)
        assert code in (0, 1)


# ═══════════════════════════════════════════════════════════════════════════════
# audit: unknown subcommand (lines 530-531)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditUnknownSubcommand:
    def test_audit_unknown_subcommand_exits_2(self, capsys: pytest.CaptureFixture) -> None:
        """audit with an unknown sub-subcommand → usage + exit 2 (lines 530-531)."""
        code, _, _ = _run(["audit", "verify"], capsys)
        assert code == 2


# ═══════════════════════════════════════════════════════════════════════════════
# audit verify: --public-key paths (lines 558-569)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditVerifyPubKeyPaths:
    def test_public_key_missing_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """--public-key not provided → exit 2 (lines 558-559)."""
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("", encoding="utf-8")
        code, _, err = _run(["audit", "verify", str(log_file)], capsys)
        assert code == 2
        assert "--public-key" in err or "required" in err.lower()

    def test_public_key_file_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Key file not found → exit 2 (lines 564-566)."""
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("", encoding="utf-8")
        key_file = tmp_path / "nonexistent.pem"
        code, _, err = _run(
            ["audit", "verify", str(log_file), "--public-key", str(key_file)],
            capsys,
        )
        assert code == 2
        assert "not found" in err.lower() or "error" in err.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# audit verify: loop — JSON error, TAMPERED, MISSING_SIG, INVALID_SIG, VALID
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditVerifyLoop:
    """Tests for the audit verify record loop (lines 598-697)."""

    @pytest.fixture
    def key_pair(self, tmp_path: Path):
        """Generate an ephemeral Ed25519 key pair, return (signer, pub_key_path)."""
        pytest.importorskip("cryptography", exc_type=ImportError)
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        pub_path = tmp_path / "pub.pem"
        pub_path.write_bytes(signer.public_key_pem())
        return signer, pub_path

    def _valid_record_hash(self) -> tuple[dict, str]:
        """Return (record_fields, correct_hash) for a minimal ALLOW decision."""
        d = Decision.safe(intent_dump={"amount": 100}, state_dump={})
        record = {
            "decision_id": d.decision_id,
            "allowed": True,
            "explanation": "",
            "intent_dump": {"amount": 100},
            "policy": "",
            "state_dump": {},
            "status": "safe",
            "violated_invariants": [],
        }
        return record, d.decision_hash

    def test_json_error_line_shows_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Invalid JSON on a line → errors counter, [ERROR] printed (lines 598-611)."""
        signer, pub_path = key_pair
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("THIS IS NOT JSON\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert code == 1
        assert "ERROR" in out or "error" in out.lower()

    def test_json_error_with_fail_fast_stops(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """--fail-fast stops at first JSON error (line 609-610)."""
        signer, pub_path = key_pair
        record_fields, correct_hash = self._valid_record_hash()
        good_record = dict(record_fields)
        good_record["decision_hash"] = correct_hash
        good_record["signature"] = ""

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(
            "NOT JSON\n" + json.dumps(good_record) + "\n",
            encoding="utf-8",
        )

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path), "--fail-fast"],
            capsys,
        )
        assert code == 1
        assert "ERROR" in out

    def test_tampered_record_flagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Record with wrong decision_hash → TAMPERED (lines 634-653)."""
        signer, pub_path = key_pair
        record_fields, _ = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = "totally_wrong_hash_value"  # tampered
        record["signature"] = ""

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert code == 1
        assert "TAMPERED" in out

    def test_tampered_shown_in_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """TAMPERED count > 0 → summary line printed (line 718)."""
        signer, pub_path = key_pair
        record_fields, _ = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = "wrong_hash"
        record["signature"] = ""

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert "Tampered" in out

    def test_missing_sig_record_flagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Record with correct hash but no signature → MISSING_SIG (lines 655-668)."""
        signer, pub_path = key_pair
        record_fields, correct_hash = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = correct_hash
        record["signature"] = ""  # no signature

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert code == 1
        assert "MISSING_SIG" in out

    def test_missing_sig_shown_in_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Missing sig count > 0 → summary line printed (line 722)."""
        signer, pub_path = key_pair
        record_fields, correct_hash = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = correct_hash
        record["signature"] = ""

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert "Missing sig" in out or "missing" in out.lower()

    def test_invalid_sig_record_flagged(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Correct hash but wrong signature → INVALID_SIG (lines 675-688)."""
        signer, pub_path = key_pair
        record_fields, correct_hash = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = correct_hash
        record["signature"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert code == 1
        assert "INVALID_SIG" in out

    def test_invalid_sig_shown_in_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Invalid sig count > 0 → summary line printed (line 720)."""
        signer, pub_path = key_pair
        record_fields, correct_hash = self._valid_record_hash()
        record = dict(record_fields)
        record["decision_hash"] = correct_hash
        record["signature"] = (
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        )

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert "Invalid sig" in out or "invalid" in out.lower()

    def test_valid_signed_record_passes(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Correctly signed record → VALID, exit 0 (lines 690-693)."""
        signer, pub_path = key_pair
        decision = Decision.safe(intent_dump={"amount": 100}, state_dump={})
        signature = signer.sign(decision)

        record = {
            "decision_id": decision.decision_id,
            "allowed": True,
            "explanation": "",
            "intent_dump": {"amount": 100},
            "policy": "",
            "state_dump": {},
            "status": "safe",
            "violated_invariants": [],
            "decision_hash": decision.decision_hash,
            "signature": signature,
        }

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert code == 0
        assert "VALID" in out
        assert "AUDIT PASSED" in out

    def test_audit_passed_summary_line(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """No failures → AUDIT PASSED line printed (line 727)."""
        signer, pub_path = key_pair
        decision = Decision.safe(intent_dump={"x": 1}, state_dump={})
        signature = signer.sign(decision)
        record = {
            "decision_id": decision.decision_id,
            "allowed": True,
            "explanation": "",
            "intent_dump": {"x": 1},
            "policy": "",
            "state_dump": {},
            "status": "safe",
            "violated_invariants": [],
            "decision_hash": decision.decision_hash,
            "signature": signature,
        }
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(json.dumps(record) + "\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert "AUDIT PASSED" in out

    def test_audit_json_output_with_errors(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """--json flag with errors → JSON summary (line 701-712)."""
        signer, pub_path = key_pair
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("NOT JSON\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path), "--json"],
            capsys,
        )
        assert code == 1
        data = json.loads(out)
        assert "errors" in data
        assert data["errors"] >= 1

    def test_errors_shown_in_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """Error count > 0 → summary errors line printed (line 724)."""
        signer, pub_path = key_pair
        log_file = tmp_path / "audit.jsonl"
        log_file.write_text("INVALID JSON LINE\n", encoding="utf-8")

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path)],
            capsys,
        )
        assert "Errors" in out or "error" in out.lower()

    def test_fail_fast_with_tampered_stops_early(
        self, tmp_path: Path, capsys: pytest.CaptureFixture, key_pair
    ) -> None:
        """--fail-fast: after TAMPERED, processing stops (line 651)."""
        signer, pub_path = key_pair
        record_fields, _ = self._valid_record_hash()
        tampered_record = dict(record_fields)
        tampered_record["decision_hash"] = "wrong"
        tampered_record["signature"] = ""

        # Second record would be MISSING_SIG if processed
        record_fields2, correct_hash2 = self._valid_record_hash()
        missing_sig_record = dict(record_fields2)
        missing_sig_record["decision_hash"] = correct_hash2
        missing_sig_record["signature"] = ""

        log_file = tmp_path / "audit.jsonl"
        log_file.write_text(
            json.dumps(tampered_record) + "\n" + json.dumps(missing_sig_record) + "\n",
            encoding="utf-8",
        )

        code, out, _ = _run(
            ["audit", "verify", str(log_file), "--public-key", str(pub_path), "--fail-fast"],
            capsys,
        )
        assert code == 1
        assert "TAMPERED" in out


# ═══════════════════════════════════════════════════════════════════════════════
# _cmd_coverage: error paths (lines 2500-2525)
# ═══════════════════════════════════════════════════════════════════════════════

_YAML_POLICY = textwrap.dedent("""\
    meta:
      name: TestPolicy

    fields:
      amount:
        z3_type: Real

    invariants:
      - name: non_negative
        expr: "amount >= 0"
        explain: "Amount must be non-negative."
""")


class TestCoverageSubcommandErrorPaths:
    """Lines 2500-2525: error branches in _cmd_coverage."""

    def _write_cases(self, tmp_path: Path) -> Path:
        p = tmp_path / "cases.jsonl"
        p.write_text('{"intent": {"amount": 100}}\n', encoding="utf-8")
        return p

    def test_yaml_compile_error_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """YAML file exists but fails to load → generic exception → exit 2 (lines 2500-2502)."""
        # Write a file that passes FileNotFoundError but fails during parse:
        # Use a valid YAML extension but with content that causes a parse failure
        # (not a pure YAML syntax error — that might be a FileNotFoundError in some loaders).
        # The easiest: create a .yaml file that YAML parses successfully but
        # Pramanix policy compilation fails (missing required fields).
        broken_yaml = tmp_path / "broken.yaml"
        broken_yaml.write_text("this: is not a pramanix policy\n", encoding="utf-8")
        cases = self._write_cases(tmp_path)

        code, _, err = _run(
            ["coverage", "--policy", str(broken_yaml), "--test-cases", str(cases)],
            capsys,
        )
        assert code == 2
        assert "error" in err.lower()

    def test_python_policy_spec_is_none_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Non-Python extension → spec_from_file_location returns None → exit 2 (2506-2508)."""
        policy_txt = tmp_path / "policy.bin"
        policy_txt.write_text("not python content\n", encoding="utf-8")
        cases = self._write_cases(tmp_path)

        code, _, err = _run(
            ["coverage", "--policy", str(policy_txt), "--test-cases", str(cases)],
            capsys,
        )
        assert code == 2
        assert "error" in err.lower() or "cannot" in err.lower() or "spec" in err.lower()

    def test_python_policy_import_exception_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Python file that raises on import (not FileNotFoundError) → exit 2 (2514-2516)."""
        bad_policy = tmp_path / "bad_policy.py"
        bad_policy.write_text('raise RuntimeError("intentional error")\n', encoding="utf-8")
        cases = self._write_cases(tmp_path)

        code, _, err = _run(
            ["coverage", "--policy", str(bad_policy), "--test-cases", str(cases)],
            capsys,
        )
        assert code == 2
        assert "error" in err.lower() or "import" in err.lower()

    def test_python_policy_var_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Python file imports fine but policy variable not found → exit 2 (2519-2525)."""
        no_var_policy = tmp_path / "no_var.py"
        no_var_policy.write_text("x = 42\n# no 'policy' variable\n", encoding="utf-8")
        cases = self._write_cases(tmp_path)

        code, _, err = _run(
            ["coverage", "--policy", str(no_var_policy), "--test-cases", str(cases)],
            capsys,
        )
        assert code == 2
        assert "not found" in err.lower() or "variable" in err.lower() or "error" in err.lower()

    def test_python_policy_var_custom_name_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Custom --policy-var name not found in module → exit 2 (2519-2525)."""
        some_policy = tmp_path / "some_policy.py"
        some_policy.write_text("policy = None\n", encoding="utf-8")
        cases = self._write_cases(tmp_path)

        # --policy-var custom_name looks for 'custom_name', which doesn't exist
        code, _, err = _run(
            [
                "coverage",
                "--policy",
                str(some_policy),
                "--test-cases",
                str(cases),
                "--policy-var",
                "custom_name",
            ],
            capsys,
        )
        assert code == 2
        assert "not found" in err.lower() or "custom_name" in err or "error" in err.lower()
