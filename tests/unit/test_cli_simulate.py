# SPDX-License-Identifier: AGPL-3.0-only
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for the 'pramanix simulate' CLI subcommand."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from pramanix.cli import main

EXAMPLE_POLICY = Path(__file__).resolve().parents[2] / "examples" / "cloud_infra.py"
BANKING_POLICY = Path(__file__).resolve().parents[2] / "examples" / "banking_transfer.py"


def _intent_json(replicas: int, cpu_request: int, mem_request: int) -> str:
    return json.dumps(
        {
            "replicas": replicas,
            "cpu_request": cpu_request,
            "mem_request": mem_request,
        }
    )


def _state_json(min_r: int = 2, max_r: int = 20) -> str:
    return json.dumps(
        {
            "state_version": "1.0",
            "min_r": min_r,
            "max_r": max_r,
            "cpu_budget": 4000,
            "mem_budget": 8192,
        }
    )


class TestSimulateSubcommand:
    def test_allow_decision_exits_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(5, 1000, 2048),
                "--state",
                _state_json(),
            ],
        )
        assert main() == 0

    def test_block_decision_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(50, 500, 512),
                "--state",
                _state_json(),
            ],
        )
        assert main() == 1

    def test_json_flag_output_parseable(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(5, 1000, 2048),
                "--state",
                _state_json(),
                "--json",
            ],
        )
        main()
        out = capsys.readouterr().out
        json_line = next(
            (ln for ln in out.splitlines() if ln.strip().startswith("{")),
            None,
        )
        assert json_line is not None, f"No JSON object found in output:\n{out}"
        data = json.loads(json_line)
        assert data["allowed"] is True
        assert "plain_reason" in data
        assert "next_step" in data

    def test_explain_alias_maps_to_simulate(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "explain",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(5, 1000, 2048),
                "--state",
                _state_json(),
            ],
        )
        assert main() == 0
        out = capsys.readouterr().out
        assert "Safety verdict: ALLOW" in out

    def test_intent_file_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        intent_path = tmp_path / "intent.json"
        intent_path.write_text(_intent_json(5, 1000, 2048), encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent-file",
                str(intent_path),
                "--state",
                _state_json(),
            ],
        )
        assert main() == 0

    def test_state_file_flag(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        state_path = tmp_path / "state.json"
        state_path.write_text(_state_json(), encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(5, 1000, 2048),
                "--state-file",
                str(state_path),
            ],
        )
        assert main() == 0

    def test_decimal_policy_coerces_json_numbers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(BANKING_POLICY),
                "--policy-var",
                "BankingPolicy",
                "--intent",
                '{"amount": 500}',
                "--state",
                '{"state_version":"1.0","balance":1000,"daily_limit":5000,"is_frozen":false}',
            ],
        )
        assert main() == 0

    def test_missing_policy_file_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                "/nonexistent/policy.py",
                "--intent",
                _intent_json(1, 1, 1),
            ],
        )
        assert main() == 2

    def test_invalid_intent_json_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                "not-json",
            ],
        )
        assert main() == 2

    def test_missing_policy_var_exits_2(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--intent",
                _intent_json(1, 1, 1),
            ],
        )
        assert main() == 2

    def test_block_output_shows_block(self, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(50, 500, 512),
                "--state",
                _state_json(),
            ],
        )
        main()
        out = capsys.readouterr().out
        assert "Safety verdict: BLOCK" in out

    def test_block_output_shows_plain_english_reason(
        self, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(50, 500, 512),
                "--state",
                _state_json(),
            ],
        )
        main()
        out = capsys.readouterr().out
        assert "Safety verdict: BLOCK" in out
        assert "replicas" in out or "replica" in out

    def test_suggest_fix_outputs_recommendation(
        self, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(50, 500, 512),
                "--state",
                _state_json(),
                "--suggest-fix",
            ],
        )
        main()
        out = capsys.readouterr().out
        assert "Suggested fix (review required):" in out

    def test_json_suggest_fix_contains_entries(
        self, monkeypatch: pytest.MonkeyPatch, capsys
    ) -> None:
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(EXAMPLE_POLICY),
                "--policy-var",
                "ScalingPolicy",
                "--intent",
                _intent_json(50, 500, 512),
                "--state",
                _state_json(),
                "--json",
                "--suggest-fix",
            ],
        )
        main()
        out = capsys.readouterr().out
        json_line = next(
            (ln for ln in out.splitlines() if ln.strip().startswith("{")),
            None,
        )
        assert json_line is not None
        data = json.loads(json_line)
        assert isinstance(data.get("suggested_fixes"), list)
        assert len(data["suggested_fixes"]) >= 1
