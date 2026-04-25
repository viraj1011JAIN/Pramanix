# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for schema export CLI subcommand (G-3)."""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest

from pramanix.cli import main


def _run_cli(args: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    """Run main() with given args; return (exit_code, stdout, stderr)."""
    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sys, "argv", ["pramanix", *args])
            exit_code = main()
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


def test_schema_export_stdout(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """schema export prints JSON to stdout."""
    policy_file = tmp_path / "mypolicy.py"
    policy_file.write_text(
        textwrap.dedent("""
            from decimal import Decimal
            from pramanix.expressions import E, Field
            from pramanix.policy import Policy

            class MyPolicy(Policy):
                amount = Field("amount", Decimal, "Real")
                flag = Field("flag", bool, "Bool")

                @classmethod
                def invariants(cls):
                    return [(E(cls.amount) > 0).named("pos")]
        """),
        encoding="utf-8",
    )

    exit_code, stdout, stderr = _run_cli(
        ["schema", "export", "--policy", f"{policy_file}:MyPolicy"],
        capsys,
    )
    assert exit_code == 0, stderr
    parsed = json.loads(stdout)
    assert parsed["title"] == "MyPolicy"
    assert "amount" in parsed["properties"]
    assert "flag" in parsed["properties"]


def test_schema_export_to_file(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """schema export writes JSON to --output file."""
    policy_file = tmp_path / "policy2.py"
    policy_file.write_text(
        textwrap.dedent("""
            from decimal import Decimal
            from pramanix.expressions import E, Field
            from pramanix.policy import Policy

            class AnotherPolicy(Policy):
                value = Field("value", int, "Int")

                @classmethod
                def invariants(cls):
                    return [(E(cls.value) >= 0).named("non_neg")]
        """),
        encoding="utf-8",
    )
    output_file = tmp_path / "schema.json"

    exit_code, _, stderr = _run_cli(
        [
            "schema",
            "export",
            "--policy",
            f"{policy_file}:AnotherPolicy",
            "--output",
            str(output_file),
        ],
        capsys,
    )
    assert exit_code == 0, stderr
    assert output_file.exists()
    parsed = json.loads(output_file.read_text(encoding="utf-8"))
    assert parsed["title"] == "AnotherPolicy"


def test_schema_export_invalid_policy_path(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """schema export exits non-zero for missing file."""
    exit_code, _, _ = _run_cli(
        ["schema", "export", "--policy", "nonexistent_file.py:MyPolicy"],
        capsys,
    )
    assert exit_code != 0


def test_schema_export_missing_class(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """schema export exits non-zero for missing class in file."""
    policy_file = tmp_path / "empty.py"
    policy_file.write_text("", encoding="utf-8")

    exit_code, _, _ = _run_cli(
        ["schema", "export", "--policy", f"{policy_file}:NonExistentClass"],
        capsys,
    )
    assert exit_code != 0


def test_schema_export_required_fields_sorted(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """required array is sorted alphabetically."""
    policy_file = tmp_path / "sorted.py"
    policy_file.write_text(
        textwrap.dedent("""
            from decimal import Decimal
            from pramanix.expressions import E, Field
            from pramanix.policy import Policy

            class SortedPolicy(Policy):
                zebra = Field("zebra", int, "Int")
                apple = Field("apple", bool, "Bool")
                mango = Field("mango", Decimal, "Real")

                @classmethod
                def invariants(cls):
                    return [(E(cls.zebra) >= 0).named("pos_z")]
        """),
        encoding="utf-8",
    )

    exit_code, stdout, stderr = _run_cli(
        ["schema", "export", "--policy", f"{policy_file}:SortedPolicy"],
        capsys,
    )
    assert exit_code == 0, stderr
    parsed = json.loads(stdout)
    assert parsed["required"] == sorted(parsed["required"])
