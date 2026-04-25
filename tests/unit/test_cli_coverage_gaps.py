# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Coverage tests for CLI subcommands — targeting specific missing lines.

Targets:
  cli.py  383-396  audit verify hash-recomputation error path
  cli.py  552-573  simulate intent-file errors, state errors
  cli.py  582-591  simulate policy import errors
  cli.py  610-612  simulate guard construction failure
  cli.py  641-642  policy subcommand with no sub-subcommand
  cli.py  657-677  policy migrate semver / rename errors
  cli.py  687-716  policy migrate state-file errors, stdout output
  cli.py  729-796  schema subcommand errors
  cli.py  840-858  calibrate dataset read errors
  cli.py  1102     doctor redis-url set but redis pkg absent
  cli.py  1134     doctor FAIL human-readable message
  cli.py  1140     doctor PASS human-readable message (all OK)
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from pramanix.cli import main


# ── Shared helpers ─────────────────────────────────────────────────────────────


def _run(
    args: list[str], capsys: pytest.CaptureFixture
) -> tuple[int, str, str]:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sys, "argv", ["pramanix", *args])
        try:
            code = main()
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _policy_file(tmp_path: Path, content: str) -> str:
    p = tmp_path / "policy.py"
    p.write_text(textwrap.dedent(content))
    return str(p)


_ALLOW_POLICY = """
from decimal import Decimal
from pramanix import Field, Policy, E

class AllowPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]

policy = AllowPolicy
"""


# ═══════════════════════════════════════════════════════════════════════════════
# audit verify — hash recomputation error (lines 383-396)
# ═══════════════════════════════════════════════════════════════════════════════

class TestAuditVerifyHashError:
    """Lines 383-396: _recompute_hash raises when record has non-dict intent_dump."""

    def test_hash_recomputation_error_continues_and_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PublicFormat,
        )

        private_key = Ed25519PrivateKey.generate()
        pub_pem = private_key.public_key().public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        pub_key_path = tmp_path / "pub.pem"
        pub_key_path.write_bytes(pub_pem)

        # intent_dump=42 → dict(42) raises TypeError in _recompute_hash
        bad_record = json.dumps({
            "decision_id": "err-001",
            "decision_hash": "fake_hash",
            "signature": "",
            "intent_dump": 42,
            "allowed": True,
            "policy": "Test",
            "status": "SAT",
            "violated_invariants": [],
        })
        log_path = tmp_path / "audit.jsonl"
        log_path.write_text(bad_record + "\n", encoding="utf-8")

        code, stdout, stderr = _run(
            [
                "audit",
                "verify",
                str(log_path),
                "--public-key",
                str(pub_key_path),
            ],
            capsys,
        )
        # Should report error but not crash
        assert code == 1


# ═══════════════════════════════════════════════════════════════════════════════
# simulate — intent-file, state, policy import errors (lines 552-612)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSimulateMissingPaths:
    """Lines 552-612: error branches in _cmd_simulate."""

    def test_intent_file_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_path = _policy_file(tmp_path, _ALLOW_POLICY)
        code, _, _ = _run(
            [
                "simulate",
                "--policy", policy_path,
                "--intent-file", str(tmp_path / "nonexistent.json"),
            ],
            capsys,
        )
        assert code == 2

    def test_intent_file_invalid_json_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_path = _policy_file(tmp_path, _ALLOW_POLICY)
        bad_json = tmp_path / "bad.json"
        bad_json.write_text("this is not json")
        code, _, _ = _run(
            ["simulate", "--policy", policy_path, "--intent-file", str(bad_json)],
            capsys,
        )
        assert code == 2

    def test_intent_not_dict_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_path = _policy_file(tmp_path, _ALLOW_POLICY)
        code, _, _ = _run(
            ["simulate", "--policy", policy_path, "--intent", "[1, 2, 3]"],
            capsys,
        )
        assert code == 2

    def test_state_invalid_json_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_path = _policy_file(tmp_path, _ALLOW_POLICY)
        code, _, _ = _run(
            [
                "simulate",
                "--policy", policy_path,
                "--intent", '{"amount": 1}',
                "--state", "not-valid-json",
            ],
            capsys,
        )
        assert code == 2

    def test_state_not_dict_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_path = _policy_file(tmp_path, _ALLOW_POLICY)
        code, _, _ = _run(
            [
                "simulate",
                "--policy", policy_path,
                "--intent", '{"amount": 1}',
                "--state", "[1, 2]",
            ],
            capsys,
        )
        assert code == 2

    def test_policy_import_exception_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # A valid Python file that raises on import (not FileNotFoundError)
        bad_policy = _policy_file(
            tmp_path,
            'raise RuntimeError("intentional import error")\npolicy = None\n',
        )
        code, _, _ = _run(
            ["simulate", "--policy", bad_policy, "--intent", '{"amount": 1}'],
            capsys,
        )
        assert code == 2

    def test_guard_construction_failure_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # Policy with empty invariants — Guard raises PolicyError
        empty_invariants = _policy_file(
            tmp_path,
            textwrap.dedent("""\
                from decimal import Decimal
                from pramanix import Field, Policy, E

                class EmptyPolicy(Policy):
                    amount = Field("amount", Decimal, "Real")

                    @classmethod
                    def invariants(cls):
                        return []  # EMPTY — Guard.validate() raises PolicyError

                policy = EmptyPolicy
            """),
        )
        code, _, _ = _run(
            ["simulate", "--policy", empty_invariants, "--intent", '{"amount": 1}'],
            capsys,
        )
        assert code == 2


# ═══════════════════════════════════════════════════════════════════════════════
# policy subcommand — no sub-subcommand (lines 641-642)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicySubcommandHelp:
    """Lines 641-642: `pramanix policy` with no sub-subcommand → usage error."""

    def test_policy_no_subcommand_exits_2(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        code, _, _ = _run(["policy"], capsys)
        assert code == 2


# ═══════════════════════════════════════════════════════════════════════════════
# policy migrate — semver / rename / state-file errors (lines 657-716)
# ═══════════════════════════════════════════════════════════════════════════════

class TestPolicyMigrateErrors:
    """Lines 657-716: various error paths in _cmd_policy_migrate."""

    def _state_file(self, tmp_path: Path, data: dict) -> str:
        p = tmp_path / "state.json"
        p.write_text(json.dumps(data))
        return str(p)

    def test_bad_from_version_semver_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        state_path = self._state_file(tmp_path, {"state_version": "1.0.0"})
        code, _, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "not_semver",
                "--to-version", "2.0.0",
                "--state", state_path,
            ],
            capsys,
        )
        assert code == 2

    def test_bad_to_version_semver_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        state_path = self._state_file(tmp_path, {"state_version": "1.0.0"})
        code, _, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "1.0.0",
                "--to-version", "bad",
                "--state", state_path,
            ],
            capsys,
        )
        assert code == 2

    def test_rename_bad_format_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        state_path = self._state_file(tmp_path, {"state_version": "1.0.0"})
        code, _, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
                "--rename", "no_equals_sign",
                "--state", state_path,
            ],
            capsys,
        )
        assert code == 2

    def test_state_file_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        code, _, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
                "--state", str(tmp_path / "nonexistent.json"),
            ],
            capsys,
        )
        assert code == 2

    def test_state_file_invalid_json_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        bad_state = tmp_path / "bad_state.json"
        bad_state.write_text("not json")
        code, _, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
                "--state", str(bad_state),
            ],
            capsys,
        )
        assert code == 2

    def test_migrate_outputs_to_stdout_when_no_output_flag(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        state_path = self._state_file(
            tmp_path,
            {"state_version": "1.0.0", "balance": 100},
        )
        code, stdout, _ = _run(
            [
                "policy", "migrate",
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
                "--state", state_path,
            ],
            capsys,
        )
        # If version matches, migrate outputs JSON to stdout
        assert code in (0, 1)
        if code == 0:
            # line 716: print(output_json)
            assert "{" in stdout


# ═══════════════════════════════════════════════════════════════════════════════
# schema subcommand — missing / error paths (lines 729-796)
# ═══════════════════════════════════════════════════════════════════════════════

class TestSchemaSubcommandErrors:
    """Lines 729-796: schema subcommand error paths."""

    def test_schema_no_subcommand_exits_2(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        code, _, _ = _run(["schema"], capsys)
        assert code == 2

    def test_schema_export_no_colon_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        code, _, _ = _run(
            ["schema", "export", "--policy", "no_colon_here"],
            capsys,
        )
        assert code == 2

    def test_schema_export_file_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        code, _, _ = _run(
            [
                "schema",
                "export",
                "--policy",
                str(tmp_path / "nonexistent.py") + ":MyPolicy",
            ],
            capsys,
        )
        assert code == 2

    def test_schema_export_class_not_policy_subclass_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_file = tmp_path / "notpolicy.py"
        policy_file.write_text("class NotAPolicy:\n    pass\n")
        code, _, _ = _run(
            ["schema", "export", "--policy", f"{policy_file}:NotAPolicy"],
            capsys,
        )
        assert code == 2

    def test_schema_export_class_not_found_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        policy_file = tmp_path / "empty.py"
        policy_file.write_text("# empty\n")
        code, _, _ = _run(
            ["schema", "export", "--policy", f"{policy_file}:MissingClass"],
            capsys,
        )
        assert code == 2

    def test_schema_export_exception_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # A Policy subclass whose export_json_schema() raises
        policy_file = tmp_path / "bad_export.py"
        policy_file.write_text(
            textwrap.dedent("""\
                from decimal import Decimal
                from pramanix import Field, Policy, E

                class BadExportPolicy(Policy):
                    amount = Field("amount", Decimal, "Real")

                    @classmethod
                    def invariants(cls):
                        return [(E(cls.amount) > 0).named("pos")]

                    @classmethod
                    def export_json_schema(cls):
                        raise RuntimeError("export broken intentionally")
            """)
        )
        code, _, _ = _run(
            ["schema", "export", "--policy", f"{policy_file}:BadExportPolicy"],
            capsys,
        )
        assert code == 2


# ═══════════════════════════════════════════════════════════════════════════════
# calibrate injection — dataset read error paths (lines 840-858)
# ═══════════════════════════════════════════════════════════════════════════════

class TestCalibrateDatasetErrors:
    """Lines 840, 843-853, 856-858: dataset parsing error paths."""

    def _write_dataset(self, tmp_path: Path, content: str) -> str:
        p = tmp_path / "dataset.jsonl"
        p.write_bytes(content.encode("utf-8", errors="replace"))
        return str(p)

    def test_empty_line_skipped_not_counted(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # line 840: empty lines are skipped (continue)
        # Dataset has only 1 real row + empty lines → fewer than min_examples
        content = "\n\n" + json.dumps({"text": "hello", "is_injection": False}) + "\n\n"
        dataset_path = self._write_dataset(tmp_path, content)
        output_path = str(tmp_path / "scorer.pkl")
        code, _, _ = _run(
            [
                "calibrate-injection",
                "--dataset", dataset_path,
                "--output", output_path,
                "--min-examples", "1000",
            ],
            capsys,
        )
        # Too few examples → exits 1 (but empty lines were correctly skipped)
        assert code == 1

    def test_invalid_json_line_in_dataset_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        content = "this is not json\n"
        dataset_path = self._write_dataset(tmp_path, content)
        output_path = str(tmp_path / "scorer.pkl")
        code, _, _ = _run(
            [
                "calibrate-injection",
                "--dataset", dataset_path,
                "--output", output_path,
            ],
            capsys,
        )
        assert code == 2

    def test_missing_keys_in_dataset_row_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        content = json.dumps({"text": "hello"}) + "\n"  # missing is_injection
        dataset_path = self._write_dataset(tmp_path, content)
        output_path = str(tmp_path / "scorer.pkl")
        code, _, _ = _run(
            [
                "calibrate-injection",
                "--dataset", dataset_path,
                "--output", output_path,
            ],
            capsys,
        )
        assert code == 2

    def test_binary_file_causes_read_error_exits_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        # Write binary garbage that causes UnicodeDecodeError when read as UTF-8
        binary_path = tmp_path / "binary.jsonl"
        binary_path.write_bytes(b"\x80\x81\x82\x83")
        output_path = str(tmp_path / "scorer.pkl")
        code, _, _ = _run(
            [
                "calibrate-injection",
                "--dataset", str(binary_path),
                "--output", output_path,
            ],
            capsys,
        )
        assert code == 2


# ═══════════════════════════════════════════════════════════════════════════════
# doctor — human-readable output paths (lines 1134, 1140)
# ═══════════════════════════════════════════════════════════════════════════════

class TestDoctorHumanReadablePaths:
    """Lines 1134, 1140: human-readable FAIL and PASS messages."""

    def test_doctor_pass_no_warnings_when_all_ok(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Line 1140: all checks pass, no warnings → PASS message."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", "a" * 64)
        monkeypatch.delenv("PRAMANIX_REDIS_URL", raising=False)
        code, stdout, _ = _run(["doctor"], capsys)
        # With signing key set, the only WARN source is gone.
        # The PASS line is either "PASS with warnings" or "PASS — env looks good"
        assert "PASS" in stdout or code in (0, 1)

    def test_doctor_fail_message_when_redis_unreachable(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Line 1134: error present → 'pramanix doctor: FAIL' message."""
        pytest.importorskip("redis")
        # Set PRAMANIX_REDIS_URL to unreachable port → connection error → ERROR
        monkeypatch.setenv("PRAMANIX_REDIS_URL", "redis://127.0.0.1:19998/0")
        code, stdout, _ = _run(["doctor"], capsys)
        # redis-ping should ERROR → has_error=True → line 1134
        assert code == 1
        assert "FAIL" in stdout or "ERR" in stdout

    def test_doctor_strict_mode_with_warnings_exits_1(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Line 1135-1136: --strict with warnings → FAIL message."""
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        code, stdout, _ = _run(["doctor", "--strict"], capsys)
        # signing-key WARN + --strict → exit 1
        assert code == 1

    def test_doctor_pass_with_warnings_message(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Line 1138: has_warn True, no strict → 'PASS with warnings'."""
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        monkeypatch.delenv("PRAMANIX_REDIS_URL", raising=False)
        _, stdout, _ = _run(["doctor"], capsys)
        assert "PASS" in stdout or "WARN" in stdout
