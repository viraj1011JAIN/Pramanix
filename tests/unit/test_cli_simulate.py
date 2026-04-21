# SPDX-License-Identifier: AGPL-3.0-only
# Phase G-2: Tests for the `pramanix simulate` CLI subcommand
"""Unit tests for the 'pramanix simulate' CLI subcommand."""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from pramanix.cli import main

# ── Helpers ───────────────────────────────────────────────────────────────────


def _policy_file(tmp_path: Path, content: str) -> str:
    """Write a temporary policy Python file and return its path."""
    p = tmp_path / "policy.py"
    p.write_text(textwrap.dedent(content))
    return str(p)


def _intent_file(tmp_path: Path, data: dict) -> str:
    p = tmp_path / "intent.json"
    p.write_text(json.dumps(data))
    return str(p)


ALLOW_POLICY = """
from decimal import Decimal
from pramanix import Field, Policy, E

class AllowPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]

policy = AllowPolicy
"""

BLOCK_POLICY = """
from decimal import Decimal
from pramanix import Field, Policy, E

class BlockPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 1000).named("min_threshold")]

policy = BlockPolicy
"""


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestSimulateSubcommand:
    def test_allow_decision_exits_0(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Policy that allows the intent → exit code 0."""
        policy_path = _policy_file(tmp_path, ALLOW_POLICY)
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", '{"amount": 500}'],
        )
        assert main() == 0

    def test_block_decision_exits_1(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Policy that blocks the intent → exit code 1."""
        policy_path = _policy_file(tmp_path, BLOCK_POLICY)
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", '{"amount": 500}'],
        )
        assert main() == 1

    def test_json_flag_output_parseable(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
        """--json flag produces valid JSON with required fields."""
        policy_path = _policy_file(tmp_path, ALLOW_POLICY)
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", '{"amount": 500}', "--json"],
        )
        main()
        out = capsys.readouterr().out
        # Extract the first JSON object from output (there may be log lines)
        json_line = next((ln for ln in out.splitlines() if ln.strip().startswith("{")), None)
        assert json_line is not None, f"No JSON object found in output:\n{out}"
        data = json.loads(json_line)
        assert "allowed" in data
        assert "status" in data
        assert "decision_id" in data
        assert data["allowed"] is True

    def test_intent_file_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--intent-file loads intent from a JSON file."""
        policy_path = _policy_file(tmp_path, ALLOW_POLICY)
        intent_path = _intent_file(tmp_path, {"amount": 500})
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent-file", intent_path],
        )
        assert main() == 0

    def test_missing_policy_file_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Non-existent policy file → exit code 2."""
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", "/nonexistent/policy.py", "--intent", '{"amount": 1}'],
        )
        assert main() == 2

    def test_invalid_intent_json_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Malformed --intent JSON → exit code 2."""
        policy_path = _policy_file(tmp_path, ALLOW_POLICY)
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", "not-json"],
        )
        assert main() == 2

    def test_missing_policy_var_exits_2(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Policy file that defines a wrong variable name → exit code 2."""
        policy_path = _policy_file(tmp_path, "x = 1  # no 'policy' variable here\n")
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", '{"amount": 1}'],
        )
        assert main() == 2

    def test_custom_policy_var(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """--policy-var selects a non-default variable name."""
        custom_policy_src = ALLOW_POLICY.replace("policy = AllowPolicy", "my_guard = AllowPolicy")
        policy_path = _policy_file(tmp_path, custom_policy_src)
        monkeypatch.setattr(
            sys, "argv",
            [
                "pramanix", "simulate",
                "--policy", policy_path,
                "--intent", '{"amount": 500}',
                "--policy-var", "my_guard",
            ],
        )
        assert main() == 0

    def test_block_output_shows_block(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture,
    ) -> None:
        """Human-readable output for a blocked decision says BLOCK."""
        policy_path = _policy_file(tmp_path, BLOCK_POLICY)
        monkeypatch.setattr(
            sys, "argv",
            ["pramanix", "simulate", "--policy", policy_path, "--intent", '{"amount": 500}'],
        )
        main()
        out = capsys.readouterr().out
        assert "BLOCK" in out
