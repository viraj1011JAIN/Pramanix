# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Unit tests for the 'pramanix compile-policy' CLI subcommand (Phase 2)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from pramanix.cli import _COMPILE_POLICY_EXAMPLE, main

# ── Helpers ───────────────────────────────────────────────────────────────────


def _write_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(content, encoding="utf-8")
    return p


VALID_YAML = _COMPILE_POLICY_EXAMPLE  # the built-in example must compile cleanly

INVALID_YAML = """\
policy_name: broken
original_english: "This is missing required fields."
fields: []
constraints: []
"""

INVALID_CONSTRAINT_YAML = """\
policy_name: bad_constraint
original_english: "Bad constraint."
fields:
  - name: amount
    z3_type: Real
    description: "Amount."
constraints:
  - kind: comparison
    label: test
    lhs:
      kind: field
      field_name: amount
    operator: ">"
    rhs_value: "not_a_number_but_still_a_string_which_is_allowed"
    natural_language: "amount > not_a_number_but_still_a_string_which_is_allowed"
"""

# ── --example flag ────────────────────────────────────────────────────────────


def test_compile_policy_example_prints_template(capsys):
    """--example should print the YAML template and exit 0."""
    sys.argv = ["pramanix", "compile-policy", "--example"]
    ret = main()
    assert ret == 0
    captured = capsys.readouterr()
    assert "policy_name" in captured.out
    assert "NaturalPolicySchema" in captured.out


# ── Valid schema ──────────────────────────────────────────────────────────────


def test_compile_policy_valid_yaml(tmp_path, capsys):
    """A valid YAML schema should compile and exit 0."""
    p = _write_yaml(tmp_path, VALID_YAML)
    sys.argv = ["pramanix", "compile-policy", str(p)]
    ret = main()
    assert ret == 0
    captured = capsys.readouterr()
    assert "Compiled" in captured.out
    assert "PASS" in captured.out


def test_compile_policy_valid_yaml_json_output(tmp_path, capsys):
    """--json flag should produce parseable JSON."""
    p = _write_yaml(tmp_path, VALID_YAML)
    sys.argv = ["pramanix", "compile-policy", str(p), "--json"]
    ret = main()
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is True
    assert data["policy_name"] == "example_transfer_policy"
    assert data["rules_compiled"] == 2
    assert data["verification_passed"] is True


def test_compile_policy_verify_skip(tmp_path, capsys):
    """--verify skip should always pass verification."""
    p = _write_yaml(tmp_path, VALID_YAML)
    sys.argv = ["pramanix", "compile-policy", str(p), "--verify", "skip", "--json"]
    ret = main()
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is True
    assert data["verification_passed"] is True


def test_compile_policy_verify_strict(tmp_path, capsys):
    """--verify strict on a clean schema should still pass."""
    p = _write_yaml(tmp_path, VALID_YAML)
    sys.argv = ["pramanix", "compile-policy", str(p), "--verify", "strict", "--json"]
    ret = main()
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is True


# ── Invalid / missing file ────────────────────────────────────────────────────


def test_compile_policy_missing_file(tmp_path, capsys):
    """A nonexistent file should exit 1 with an error."""
    sys.argv = ["pramanix", "compile-policy", str(tmp_path / "nonexistent.yaml")]
    ret = main()
    assert ret == 1


def test_compile_policy_no_file_no_example(capsys):
    """Omitting POLICY_FILE without --example should exit 2."""
    sys.argv = ["pramanix", "compile-policy"]
    ret = main()
    assert ret == 2


def test_compile_policy_json_error_on_bad_schema(tmp_path, capsys):
    """An invalid schema should produce a JSON error with ok=False when --json."""
    bad = """\
not_a_valid_schema: true
"""
    p = _write_yaml(tmp_path, bad)
    sys.argv = ["pramanix", "compile-policy", str(p), "--json"]
    ret = main()
    assert ret == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["ok"] is False
    assert "error" in data
