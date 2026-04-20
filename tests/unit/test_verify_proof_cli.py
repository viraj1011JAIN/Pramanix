# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for pramanix verify-proof CLI command.

Covers all branches of _cmd_verify_proof and the main() dispatcher
that were not exercised by test_audit_cli.py.
"""
from __future__ import annotations

import io
import json
import sys

import pytest

from pramanix.audit.signer import DecisionSigner
from pramanix.decision import Decision

_KEY = "k" * 64  # 64-char key — passes min-length check


def _sign_decision(decision: Decision | None = None) -> str:
    d = decision or Decision.safe(solver_time_ms=1.0)
    result = DecisionSigner(signing_key=_KEY).sign(d)
    assert result is not None
    return result.token


def _run_cli(argv: list[str], stdin_data: str | None = None) -> tuple[int, str, str]:
    """Run CLI main() with controlled argv/stdin, capture stdout+stderr."""
    from pramanix.cli import main

    old_argv, old_stdin, old_stdout, old_stderr = (
        sys.argv,
        sys.stdin,
        sys.stdout,
        sys.stderr,
    )
    sys.argv = argv
    if stdin_data is not None:
        sys.stdin = io.StringIO(stdin_data)
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        code = main()
        return (code or 0), sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.argv = old_argv
        sys.stdin = old_stdin
        sys.stdout = old_stdout
        sys.stderr = old_stderr


# ── main() dispatcher ─────────────────────────────────────────────────────────


class TestMainDispatcher:
    def test_no_command_prints_help_and_returns_2(self) -> None:
        code, out, _ = _run_cli(["pramanix"])
        assert code == 2
        assert "pramanix" in out.lower() or "usage" in out.lower() or out == ""

    def test_no_command_exits_with_2(self) -> None:
        code, _, _ = _run_cli(["pramanix"])
        assert code == 2

    def test_audit_with_no_subcommand_prints_usage(self) -> None:
        """audit with no subcommand — _cmd_audit falls to the help branch."""
        code, _, _ = _run_cli(["pramanix", "audit"])
        assert code == 2


# ── verify-proof: argument parsing ────────────────────────────────────────────


class TestVerifyProofArgParsing:
    def test_no_token_and_no_stdin_returns_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, _, err = _run_cli(["pramanix", "verify-proof"])
        assert code == 2
        assert "token" in err.lower() or "argument" in err.lower() or err != ""

    def test_empty_stdin_returns_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, _, err = _run_cli(["pramanix", "verify-proof", "--stdin"], stdin_data="")
        assert code == 2
        assert err != ""

    def test_whitespace_only_stdin_returns_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, _, err = _run_cli(
            ["pramanix", "verify-proof", "--stdin"], stdin_data="   \n\t  "
        )
        assert code == 2

    def test_missing_key_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No --key flag and PRAMANIX_SIGNING_KEY unset → exit 1."""
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        token = _sign_decision()
        code, _, _ = _run_cli(["pramanix", "verify-proof", token])
        assert code == 1

    def test_key_too_short_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Signing key shorter than 32 chars raises ValueError → exit 1."""
        token = _sign_decision()
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        code, _, err = _run_cli(["pramanix", "verify-proof", token, "--key", "short"])
        assert code == 1
        assert "error" in err.lower() or err != ""


# ── verify-proof: valid token, human-readable output ─────────────────────────


class TestVerifyProofValidHuman:
    def test_valid_safe_decision_exits_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision(Decision.safe())
        code, out, _ = _run_cli(["pramanix", "verify-proof", token])
        assert code == 0
        assert "VALID" in out

    def test_valid_token_via_key_flag(self) -> None:
        token = _sign_decision()
        code, out, _ = _run_cli(["pramanix", "verify-proof", token, "--key", _KEY])
        assert code == 0
        assert "VALID" in out

    def test_valid_token_via_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        code, out, _ = _run_cli(
            ["pramanix", "verify-proof", "--stdin"], stdin_data=token
        )
        assert code == 0
        assert "VALID" in out

    def test_output_contains_decision_id(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        d = Decision.safe()
        token = _sign_decision(d)
        code, out, _ = _run_cli(["pramanix", "verify-proof", token])
        assert code == 0
        assert str(d.decision_id) in out

    def test_valid_unsafe_decision_exits_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A blocked decision with a valid token is still cryptographically verified → exit 0.

        exit code reflects signature validity, not ALLOW/BLOCK outcome.
        """
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        d = Decision.unsafe(
            violated_invariants=("balance_check",),
            explanation="Overdraft blocked",
        )
        token = _sign_decision(d)
        code, out, _ = _run_cli(["pramanix", "verify-proof", token])
        assert code == 0
        assert "VALID" in out
        assert "status=" in out

    def test_invalid_token_exits_1_human(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, out, _ = _run_cli(
            ["pramanix", "verify-proof", "completely.invalid.token"]
        )
        assert code == 1
        assert "INVALID" in out

    def test_tampered_token_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        parts = token.split(".")
        parts[2] = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        tampered = ".".join(parts)
        code, out, _ = _run_cli(["pramanix", "verify-proof", tampered])
        assert code == 1
        assert "INVALID" in out

    def test_human_output_contains_status(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision(Decision.safe())
        _, out, _ = _run_cli(["pramanix", "verify-proof", token])
        assert "status=" in out

    def test_human_output_shows_violated_invariants_when_present(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Human output includes violated= when invariants are present."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        d = Decision.unsafe(
            violated_invariants=("daily_limit",),
            explanation="Limit exceeded",
        )
        token = _sign_decision(d)
        _, out, _ = _run_cli(["pramanix", "verify-proof", token])
        assert "violated=" in out


# ── verify-proof: JSON output ─────────────────────────────────────────────────


class TestVerifyProofJsonOutput:
    def test_json_flag_produces_valid_json(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        code, out, _ = _run_cli(["pramanix", "verify-proof", token, "--json"])
        assert code == 0
        parsed = json.loads(out)
        assert parsed["valid"] is True
        assert parsed["allowed"] is True

    def test_json_output_has_all_required_fields(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        _, out, _ = _run_cli(["pramanix", "verify-proof", token, "--json"])
        parsed = json.loads(out)
        for field in (
            "valid",
            "decision_id",
            "allowed",
            "status",
            "violated_invariants",
            "explanation",
            "policy_hash",
            "issued_at",
        ):
            assert field in parsed, f"Missing field: {field!r}"

    def test_json_invalid_token_has_error_field(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, out, _ = _run_cli(
            ["pramanix", "verify-proof", "bad.token.here", "--json"]
        )
        assert code == 1
        parsed = json.loads(out)
        assert parsed["valid"] is False
        assert "error" in parsed

    def test_json_blocked_decision_exits_0_with_allowed_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Blocked decision with valid token: exit 0 (signature valid), allowed=False."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        d = Decision.unsafe(
            violated_invariants=("max_exposure",),
            explanation="Position limit exceeded",
        )
        token = _sign_decision(d)
        code, out, _ = _run_cli(["pramanix", "verify-proof", token, "--json"])
        assert code == 0
        parsed = json.loads(out)
        assert parsed["valid"] is True
        assert parsed["allowed"] is False
        assert "max_exposure" in parsed["violated_invariants"]

    def test_json_issued_at_is_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """iat is not in the signed payload — issued_at must be 0."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        _, out, _ = _run_cli(["pramanix", "verify-proof", token, "--json"])
        parsed = json.loads(out)
        assert parsed["issued_at"] == 0

    def test_json_via_stdin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        token = _sign_decision()
        code, out, _ = _run_cli(
            ["pramanix", "verify-proof", "--stdin", "--json"], stdin_data=token
        )
        assert code == 0
        parsed = json.loads(out)
        assert parsed["valid"] is True


# ── audit command edge cases ──────────────────────────────────────────────────


class TestAuditCLIExtras:
    def test_missing_public_key_flag_returns_2(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner
        from pramanix.decision import Decision

        signer = PramanixSigner.generate()
        d = Decision.safe()
        rec = {
            "decision_id": str(d.decision_id),
            "decision_hash": d.decision_hash,
            "signature": signer.sign(d),
            "allowed": d.allowed,
            "status": str(d.status.value),
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        import json

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(json.dumps(rec) + "\n")

        code, _, err = _run_cli(
            ["pramanix", "audit", "verify", str(log_path), "--public-key", ""]
        )
        assert code == 2
        assert err != ""

    def test_missing_log_file_returns_2(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, _, err = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(tmp_path / "nonexistent.jsonl"),
                "--public-key",
                str(key_path),
            ]
        )
        assert code == 2
        assert "not found" in err.lower()

    def test_missing_public_key_file_returns_2(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("")

        code, _, err = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(tmp_path / "no_such_key.pem"),
            ]
        )
        assert code == 2
        assert "not found" in err.lower()

    def test_invalid_public_key_returns_2(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("")
        key_path = tmp_path / "bad.pem"
        key_path.write_bytes(b"this is not a valid PEM key")

        code, _, err = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
            ]
        )
        assert code == 2
        assert err != ""

    def test_whitespace_only_positional_token_returns_2(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Whitespace-only positional token hits the empty-after-strip check."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY)
        code, _, err = _run_cli(["pramanix", "verify-proof", "   "])
        assert code == 2
        assert err != ""

    def test_directory_as_public_key_path_returns_2(self, tmp_path) -> None:
        """Passing a directory instead of a file triggers the generic Exception handler."""
        pytest.importorskip("cryptography")
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("")
        # A directory path causes open(path, "rb") to raise PermissionError/IsADirectoryError
        # which is caught by the generic `except Exception` handler (lines 174-176).
        key_dir = tmp_path / "not_a_key"
        key_dir.mkdir()

        code, _, err = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_dir),
            ]
        )
        assert code == 2
        assert err != ""

    def test_malformed_json_with_json_flag(self, tmp_path) -> None:
        """Malformed JSON line with --json flag: JSON summary shows errors=1."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{ NOT VALID JSON\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--json",
            ]
        )
        assert code == 1
        parsed = json.loads(out)
        assert parsed["errors"] == 1

    def test_missing_signature_with_json_flag(self, tmp_path) -> None:
        """Missing signature + --json flag: JSON summary shows missing_sig=1."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner
        from pramanix.decision import Decision

        signer = PramanixSigner.generate()
        d = Decision.safe()
        rec = {
            "decision_id": str(d.decision_id),
            "decision_hash": d.decision_hash,
            "allowed": d.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(json.dumps(rec) + "\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--json",
            ]
        )
        assert code == 1
        parsed = json.loads(out)
        assert parsed["missing_sig"] == 1

    def test_invalid_sig_with_json_flag(self, tmp_path) -> None:
        """Invalid signature + --json flag: JSON summary shows invalid_sig=1."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner
        from pramanix.decision import Decision

        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        d = Decision.safe()
        sig = signer.sign(d)
        rec = {
            "decision_id": str(d.decision_id),
            "decision_hash": d.decision_hash,
            "signature": sig,
            "allowed": d.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(json.dumps(rec) + "\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(wrong_signer.public_key_pem())  # wrong key

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--json",
            ]
        )
        assert code == 1
        parsed = json.loads(out)
        assert parsed["invalid_sig"] == 1

    def test_empty_log_file_exits_0(self, tmp_path) -> None:
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("\n\n")  # blank lines only
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, _, _ = _run_cli(
            ["pramanix", "audit", "verify", str(log_path), "--public-key", str(key_path)]
        )
        assert code == 0

    def test_fail_fast_stops_on_malformed_json(self, tmp_path) -> None:
        """--fail-fast exits after the first malformed JSON line."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        d = Decision.safe()
        sig = signer.sign(d)
        good_rec = {
            "decision_id": str(d.decision_id),
            "decision_hash": d.decision_hash,
            "signature": sig,
            "allowed": d.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("{ BAD\n" + json.dumps(good_rec) + "\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--fail-fast",
            ]
        )
        assert code == 1
        assert "[VALID]" not in out

    def test_fail_fast_stops_on_missing_signature(self, tmp_path) -> None:
        """--fail-fast exits after the first missing-signature record."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        d1 = Decision.safe()
        d2 = Decision.safe()
        sig2 = signer.sign(d2)
        no_sig_rec = {
            "decision_id": str(d1.decision_id),
            "decision_hash": d1.decision_hash,
            "allowed": d1.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        good_rec = {
            "decision_id": str(d2.decision_id),
            "decision_hash": d2.decision_hash,
            "signature": sig2,
            "allowed": d2.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(json.dumps(no_sig_rec) + "\n" + json.dumps(good_rec) + "\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(signer.public_key_pem())

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--fail-fast",
            ]
        )
        assert code == 1
        assert "[MISSING_SIG]" in out
        assert "[VALID]" not in out

    def test_fail_fast_stops_on_invalid_signature(self, tmp_path) -> None:
        """--fail-fast exits after the first invalid-signature record."""
        pytest.importorskip("cryptography")
        from pramanix.crypto import PramanixSigner

        signer = PramanixSigner.generate()
        wrong_signer = PramanixSigner.generate()
        d1 = Decision.safe()
        d2 = Decision.safe()
        sig1 = signer.sign(d1)
        sig2 = signer.sign(d2)
        inv_rec = {
            "decision_id": str(d1.decision_id),
            "decision_hash": d1.decision_hash,
            "signature": sig1,
            "allowed": d1.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        good_rec = {
            "decision_id": str(d2.decision_id),
            "decision_hash": d2.decision_hash,
            "signature": sig2,
            "allowed": d2.allowed,
            "status": "safe",
            "violated_invariants": [],
            "explanation": "",
            "policy": "",
            "intent_dump": {},
            "state_dump": {},
        }
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(json.dumps(inv_rec) + "\n" + json.dumps(good_rec) + "\n")
        key_path = tmp_path / "key.pem"
        key_path.write_bytes(wrong_signer.public_key_pem())  # wrong key

        code, out, _ = _run_cli(
            [
                "pramanix",
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(key_path),
                "--fail-fast",
            ]
        )
        assert code == 1
        assert "[INVALID_SIG]" in out
        assert "[VALID]" not in out
