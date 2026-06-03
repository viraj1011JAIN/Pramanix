# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for two CLI additions:

1. ``simulate`` — YAML/TOML policy file support (GA-3 wired to CLI)
2. ``coverage`` — new subcommand exposing Guard.coverage_report() (GA-13)

All tests use real file I/O and the real CLI entry-point (no mocks).
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest

from pramanix.cli import main

# ── Shared helpers ─────────────────────────────────────────────────────────────

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

_TOML_POLICY = textwrap.dedent("""\
    [meta]
    name = "TestPolicy"

    [fields.amount]
    z3_type = "Real"

    [[invariants]]
    name = "non_negative"
    expr = "amount >= 0"
    explain = "Amount must be non-negative."
""")


def _run(args: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(sys, "argv", ["pramanix", *args])
        try:
            rc = main()
        except SystemExit as exc:
            rc = int(exc.code) if exc.code is not None else 0
    out, err = capsys.readouterr()
    return rc, out, err


# ── simulate: YAML policy ──────────────────────────────────────────────────────


class TestSimulateYamlPolicy:
    def test_yaml_allow(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate with a .yaml policy file returns 0 (ALLOW) for a valid intent."""
        policy_file = tmp_path / "policy.yaml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text(_YAML_POLICY, encoding="utf-8")
        intent_file.write_text('{"amount": 100}', encoding="utf-8")

        rc, out, _ = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file)],
            capsys,
        )
        assert rc == 0
        assert "ALLOW" in out

    def test_yaml_block(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate with a .yaml policy file returns 1 (BLOCK) for an invalid intent."""
        policy_file = tmp_path / "policy.yaml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text(_YAML_POLICY, encoding="utf-8")
        intent_file.write_text('{"amount": -5}', encoding="utf-8")

        rc, out, _ = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file)],
            capsys,
        )
        assert rc == 1
        assert "BLOCK" in out

    def test_yaml_json_output(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate --json produces parseable JSON with 'allowed' key."""
        import json

        policy_file = tmp_path / "policy.yaml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text(_YAML_POLICY, encoding="utf-8")
        intent_file.write_text('{"amount": 50}', encoding="utf-8")

        rc, out, _ = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file), "--json"],
            capsys,
        )
        assert rc == 0
        data = json.loads(out)
        assert data["allowed"] is True

    def test_yaml_missing_file(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate with a missing .yaml file returns exit code 2."""
        intent_file = tmp_path / "intent.json"
        intent_file.write_text('{"amount": 100}', encoding="utf-8")

        rc, _, err = _run(
            [
                "simulate",
                "--policy",
                str(tmp_path / "nonexistent.yaml"),
                "--intent-file",
                str(intent_file),
            ],
            capsys,
        )
        assert rc == 2
        assert "not found" in err.lower() or "error" in err.lower()

    def test_yaml_bad_syntax_returns_2(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """simulate with a malformed .yaml file returns exit code 2."""
        policy_file = tmp_path / "bad.yaml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text("meta:\n  name: !!INVALID YAML {{{", encoding="utf-8")
        intent_file.write_text('{"amount": 100}', encoding="utf-8")

        rc, _, err = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file)],
            capsys,
        )
        assert rc == 2
        assert "error" in err.lower()


class TestSimulateTomlPolicy:
    def test_toml_allow(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate with a .toml policy file returns 0 (ALLOW) for a valid intent."""
        policy_file = tmp_path / "policy.toml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text(_TOML_POLICY, encoding="utf-8")
        intent_file.write_text('{"amount": 200}', encoding="utf-8")

        rc, out, _ = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file)],
            capsys,
        )
        assert rc == 0
        assert "ALLOW" in out

    def test_toml_block(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """simulate with a .toml policy file returns 1 (BLOCK) for a negative amount."""
        policy_file = tmp_path / "policy.toml"
        intent_file = tmp_path / "intent.json"
        policy_file.write_text(_TOML_POLICY, encoding="utf-8")
        intent_file.write_text('{"amount": -1}', encoding="utf-8")

        rc, out, _ = _run(
            ["simulate", "--policy", str(policy_file), "--intent-file", str(intent_file)],
            capsys,
        )
        assert rc == 1
        assert "BLOCK" in out


# ── coverage subcommand ────────────────────────────────────────────────────────


class TestCoverageSubcommand:
    def _write_policy(self, tmp_path: Path) -> Path:
        p = tmp_path / "policy.yaml"
        p.write_text(_YAML_POLICY, encoding="utf-8")
        return p

    def _write_cases(self, tmp_path: Path, lines: list[str]) -> Path:
        p = tmp_path / "cases.jsonl"
        p.write_text("\n".join(lines), encoding="utf-8")
        return p

    def test_basic_report(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage prints verifications and coverage percentage."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(
            tmp_path,
            ['{"intent": {"amount": 100}}', '{"intent": {"amount": -5}}'],
        )

        rc, out, _ = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 0
        assert "Verifications:   2" in out
        assert "100.0%" in out

    def test_json_output(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage --json produces parseable JSON with expected keys."""
        import json

        policy = self._write_policy(tmp_path)
        cases = self._write_cases(
            tmp_path,
            ['{"intent": {"amount": 100}}', '{"intent": {"amount": -1}}'],
        )

        rc, out, _ = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases), "--json"],
            capsys,
        )
        assert rc == 0
        data = json.loads(out)
        assert data["total_verifications"] == 2
        assert "coverage_pct" in data
        assert "invariants_hit" in data

    def test_invariants_hit_and_missed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """coverage correctly classifies invariants as hit or missed."""
        import json

        policy = self._write_policy(tmp_path)
        # Only allow cases — the non_negative invariant is never violated
        cases = self._write_cases(
            tmp_path,
            ['{"intent": {"amount": 100}}', '{"intent": {"amount": 0}}'],
        )

        rc, out, _ = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases), "--json"],
            capsys,
        )
        assert rc == 0
        data = json.loads(out)
        assert "non_negative" in data["invariants_missed"]
        assert data["invariants_hit"] == []

    def test_fail_under_passes(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """--fail-under exits 0 when verifications >= threshold."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(
            tmp_path,
            ['{"intent": {"amount": 100}}', '{"intent": {"amount": -5}}'],
        )

        rc, _, _ = _run(
            [
                "coverage",
                "--policy",
                str(policy),
                "--test-cases",
                str(cases),
                "--fail-under",
                "2",
            ],
            capsys,
        )
        assert rc == 0

    def test_fail_under_fails(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """--fail-under exits 1 when verifications < threshold."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(tmp_path, ['{"intent": {"amount": 100}}'])

        rc, _, err = _run(
            [
                "coverage",
                "--policy",
                str(policy),
                "--test-cases",
                str(cases),
                "--fail-under",
                "10",
            ],
            capsys,
        )
        assert rc == 1
        assert "fail-under" in err.lower()

    def test_missing_policy_file(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage exits 2 when --policy file does not exist."""
        cases = self._write_cases(tmp_path, ['{"intent": {"amount": 1}}'])

        rc, _, err = _run(
            [
                "coverage",
                "--policy",
                str(tmp_path / "missing.yaml"),
                "--test-cases",
                str(cases),
            ],
            capsys,
        )
        assert rc == 2
        assert "not found" in err.lower() or "error" in err.lower()

    def test_missing_test_cases_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """coverage exits 2 when --test-cases file does not exist."""
        policy = self._write_policy(tmp_path)

        rc, _, err = _run(
            [
                "coverage",
                "--policy",
                str(policy),
                "--test-cases",
                str(tmp_path / "missing.jsonl"),
            ],
            capsys,
        )
        assert rc == 2
        assert "not found" in err.lower() or "error" in err.lower()

    def test_malformed_jsonl_line(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage exits 2 when a JSONL line is not valid JSON."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(tmp_path, ["not valid json"])

        rc, _, err = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 2
        assert "error" in err.lower()

    def test_jsonl_missing_intent_key(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """coverage exits 2 when a JSONL line has no 'intent' key."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(tmp_path, ['{"state": {"x": 1}}'])

        rc, _, err = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 2

    def test_empty_jsonl_file(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage exits 2 when JSONL file is empty."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(tmp_path, [])

        rc, _, err = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 2
        assert "no test cases" in err.lower()

    def test_toml_policy(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        """coverage works with a .toml policy file."""
        policy = tmp_path / "policy.toml"
        policy.write_text(_TOML_POLICY, encoding="utf-8")
        cases = self._write_cases(tmp_path, ['{"intent": {"amount": 100}}'])

        rc, out, _ = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 0
        assert "Verifications:   1" in out

    def test_comments_and_blank_lines_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """JSONL lines starting with # or blank lines are ignored."""
        policy = self._write_policy(tmp_path)
        cases = self._write_cases(
            tmp_path,
            [
                "# this is a comment",
                "",
                '{"intent": {"amount": 100}}',
            ],
        )

        rc, out, _ = _run(
            ["coverage", "--policy", str(policy), "--test-cases", str(cases)],
            capsys,
        )
        assert rc == 0
        assert "Verifications:   1" in out
