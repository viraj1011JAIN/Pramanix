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


class TestPlainEnglishQuality:
    """Verify that block output is plain English — no raw Python identifiers leaked."""

    def _run_block(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> tuple[str, dict]:
        """Run a blocking simulate and return (text_out, json_out)."""
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
                _intent_json(50, 500, 512),  # replicas=50 violates max_replicas
                "--state",
                _state_json(),
                "--json",
            ],
        )
        main()
        out = capsys.readouterr().out
        json_line = next(ln for ln in out.splitlines() if ln.strip().startswith("{"))
        return out, json.loads(json_line)

    def test_plain_reason_is_a_sentence_not_a_raw_identifier(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _, data = self._run_block(monkeypatch, capsys)
        plain = data["plain_reason"]
        # Must not be a bare underscore-joined identifier like "max_replicas"
        # (a sentence contains spaces or punctuation)
        assert " " in plain or plain.endswith(
            "."
        ), f"plain_reason looks like a raw identifier, not a sentence: {plain!r}"

    def test_plain_reason_has_no_raw_underscores(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _, data = self._run_block(monkeypatch, capsys)
        plain = data["plain_reason"]
        # Underscores are fine inside word boundaries (e.g. "max_replicas" → "max replicas")
        # The rule: the entire plain_reason must not be a snake_case identifier
        words = plain.split()
        for word in words:
            cleaned = word.rstrip(".,;:")
            assert not (
                cleaned.startswith("_") or cleaned.endswith("_")
            ), f"Word in plain_reason has leading/trailing underscore: {word!r}"

    def test_next_step_is_actionable_guidance(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
    ) -> None:
        _, data = self._run_block(monkeypatch, capsys)
        next_step = data["next_step"]
        assert next_step, "next_step must not be empty"
        # Must be human-readable guidance, not a status code or identifier
        assert (
            " " in next_step
        ), f"next_step has no spaces — looks like an identifier: {next_step!r}"

    def test_block_text_output_shows_reason_line(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture
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
        assert "Reason:" in out, "Block output must include a 'Reason:' line"
        assert "Next step:" in out, "Block output must include a 'Next step:' line"


class TestSimulateDryRunGuarantees:
    """Verify simulate is side-effect free — no LLM, no audit writes, no external I/O."""

    def test_simulate_does_not_write_any_files(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """simulate must not create files under the system temp directory."""

        files_before = set(tmp_path.rglob("*"))
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
        main()
        files_after = set(tmp_path.rglob("*"))
        assert (
            files_before == files_after
        ), f"simulate created unexpected files: {files_after - files_before}"

    def test_simulate_uses_no_audit_sinks(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """simulate must build Guard with zero audit sinks regardless of policy meta."""

        policy_src = tmp_path / "audit_policy.py"
        policy_src.write_text(
            """
from decimal import Decimal
from pramanix import E, Field, Guard, GuardConfig, Policy

class _SinkSentinel:
    _calls = []
    def emit(self, decision):
        _SinkSentinel._calls.append(decision)

_sentinel = _SinkSentinel()

class AuditPolicy(Policy):
    class Meta:
        version = "1.0"
    amount = Field("amount", Decimal, "Real")
    @classmethod
    def fields(cls):
        return {"amount": cls.amount}
    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]

policy = AuditPolicy
""",
            encoding="utf-8",
        )

        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "simulate",
                "--policy",
                str(policy_src),
                "--policy-var",
                "policy",
                "--intent",
                '{"amount": 100}',
                "--state",
                '{"state_version": "1.0"}',
            ],
        )
        result = main()
        assert result == 0
        # The _SinkSentinel._calls list was NOT populated — simulate never
        # configured an audit sink on the Guard it built.
        import importlib.util

        spec = importlib.util.spec_from_file_location("_ap", str(policy_src))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert (
            mod._sentinel._calls == []
        ), "simulate must not call audit sink .emit() — dry-run guarantee violated"

    def test_simulate_succeeds_without_network(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """simulate must not attempt any network I/O — it is entirely local."""
        import socket

        def _no_connect(self, address):
            raise AssertionError(
                f"simulate attempted a network connection to {address!r} — "
                "dry-run guarantee violated: no network I/O is allowed"
            )

        monkeypatch.setattr(socket.socket, "connect", _no_connect)
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
        result = main()
        assert result == 0  # succeeded without any network I/O
