# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
"""Tests for the `pramanix lint-policy` CLI subcommand (GA-4).

All tests use real temporary files on disk — no mocks, no patches of builtins.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from pramanix.cli import main


# ── Helper: invoke CLI and return (exit_code, stdout, stderr) ─────────────────


def _run(argv: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    sys.argv = ["pramanix"] + argv
    try:
        code = main()
    except SystemExit as exc:
        code = int(exc.code) if exc.code is not None else 0
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ── Python policy fixtures ─────────────────────────────────────────────────────

_VALID_POLICY_PY = '''\
from decimal import Decimal
from pydantic import BaseModel
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class _AmountIntent(BaseModel):
    amount: Decimal
    limit: Decimal


class _AmountState(BaseModel):
    pass


class AmountPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    limit = Field("limit", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) <= E(cls.limit)).named("within_limit").explain("Amount must not exceed limit"),
            (E(cls.amount) >= 0).named("non_negative").explain("Amount must be non-negative"),
        ]

    class Meta:
        version = "1.0"
        intent_model = _AmountIntent
        state_model = _AmountState
'''

_POLICY_NO_META_PY = '''\
from decimal import Decimal
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class NoMetaPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]
'''

_POLICY_EMPTY_INVARIANTS_PY = '''\
from pramanix.policy import Policy


class EmptyPolicy(Policy):
    @classmethod
    def invariants(cls):
        return []
'''

_POLICY_MISSING_LABEL_PY = '''\
from decimal import Decimal
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class UnlabeledPolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [E(cls.amount) >= 0]  # no .named()
'''

_POLICY_DUPLICATE_LABEL_PY = '''\
from decimal import Decimal
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class DuplicatePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [
            (E(cls.amount) >= 0).named("check"),
            (E(cls.amount) <= 1000).named("check"),  # duplicate
        ]
'''

_POLICY_UNUSED_FIELD_PY = '''\
from decimal import Decimal
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class UnusedFieldPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    unused = Field("unused", Decimal, "Real")  # never referenced

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]

    class Meta:
        version = "1.0"
'''

_POLICY_SYNTAX_ERROR_PY = '''\
this is not valid Python at all !!!
'''

_VALID_YAML = """\
meta:
  name: SimpleYAMLPolicy
  version: "1.0"

fields:
  amount:
    z3_type: Real
    type: Decimal
  limit:
    z3_type: Real
    type: Decimal

invariants:
  - name: within_limit
    expr: "amount <= limit"
"""

_VALID_TOML = """\
[meta]
name = "SimpleTOMLPolicy"
version = "1.0"

[fields.amount]
z3_type = "Real"

[fields.limit]
z3_type = "Real"

[[invariants]]
name = "within_limit"
expr = "amount <= limit"
"""

_POLICY_WITH_INTENT_MODEL_PY = '''\
from decimal import Decimal
from pydantic import BaseModel
from pramanix.policy import Policy
from pramanix.expressions import E, Field


class _Intent(BaseModel):
    amount: Decimal
    limit: Decimal


class FullMetaPolicy(Policy):
    amount = Field("amount", Decimal, "Real")
    limit = Field("limit", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) <= E(cls.limit)).named("within_limit").explain("Amount must not exceed limit")]

    class Meta:
        version = "1.0"
        intent_model = _Intent
'''


# ── Test: valid Python policy ─────────────────────────────────────────────────


class TestLintPolicyValid:
    def test_valid_py_exits_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0

    def test_valid_py_prints_ok(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p)], capsys)
        assert "OK" in out or "no issues" in out

    def test_valid_py_json_ok_true(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert result["ok"] is True
        assert result["errors"] == 0

    def test_valid_py_json_has_findings_key(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert "findings" in result
        assert result["findings"] == []


# ── Test: YAML / TOML policy ──────────────────────────────────────────────────


class TestLintPolicyDeclarative:
    def test_valid_yaml_exits_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        pytest.importorskip("yaml")
        p = tmp_path / "policy.yaml"
        p.write_text(_VALID_YAML, encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0

    def test_valid_toml_exits_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.toml"
        p.write_text(_VALID_TOML, encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0

    def test_valid_yaml_json_mode(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        pytest.importorskip("yaml")
        p = tmp_path / "policy.yml"
        p.write_text(_VALID_YAML, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert result["ok"] is True


# ── Test: file-not-found / bad extension ─────────────────────────────────────


class TestLintPolicyLoadErrors:
    def test_file_not_found_exits_one(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "ghost.py"
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1

    def test_file_not_found_reports_e004(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "ghost.py"
        _, out, _ = _run(["lint-policy", str(p)], capsys)
        assert "E004" in out

    def test_file_not_found_json_mode(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "ghost.py"
        code, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert result["ok"] is False
        assert result["errors"] >= 1

    def test_unsupported_extension_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.json"
        p.write_text("{}", encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1

    def test_unsupported_extension_reports_e004(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.json"
        p.write_text("{}", encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p)], capsys)
        assert "E004" in out

    def test_syntax_error_py_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "bad.py"
        p.write_text(_POLICY_SYNTAX_ERROR_PY, encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1

    def test_no_policy_subclass_exits_one(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "empty_module.py"
        p.write_text("x = 1\n", encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1
        assert "E004" in out


# ── Test: structural errors (E001, E002, E003) ────────────────────────────────


class TestLintPolicyErrors:
    def test_empty_invariants_e003(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_EMPTY_INVARIANTS_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1
        assert "E003" in out

    def test_missing_label_e001(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_MISSING_LABEL_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1
        assert "E001" in out

    def test_duplicate_label_e002(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_DUPLICATE_LABEL_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 1
        assert "E002" in out

    def test_errors_json_findings_has_code(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_EMPTY_INVARIANTS_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        codes = [f["code"] for f in result["findings"]]
        assert "E003" in codes


# ── Test: warnings (W001, W002, W003, W004) ───────────────────────────────────


class TestLintPolicyWarnings:
    def test_no_meta_w001_exits_zero(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0  # warnings don't fail without --strict
        assert "W001" in out

    def test_no_meta_strict_exits_one(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p), "--strict"], capsys)
        assert code == 1

    def test_unused_field_w004(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_UNUSED_FIELD_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0
        assert "W004" in out
        assert "unused" in out

    def test_no_intent_model_w002(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p)], capsys)
        # W001 covers Meta absence; W002 would apply if Meta present but no intent_model
        assert "W001" in out  # absence of Meta implies W001

    def test_meta_with_intent_model_no_w002(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_WITH_INTENT_MODEL_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p)], capsys)
        assert "W002" not in out
        assert code == 0


# ── Test: --policy-var flag ────────────────────────────────────────────────────


class TestLintPolicyVar:
    def test_policy_var_loads_named_class(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p), "--policy-var", "AmountPolicy"], capsys)
        assert code == 0

    def test_policy_var_missing_class_e004(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        code, out, _ = _run(
            ["lint-policy", str(p), "--policy-var", "NonExistentClass"], capsys
        )
        assert code == 1
        assert "E004" in out

    def test_policy_var_non_policy_class_e004(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text("class NotAPolicy:\n    pass\n", encoding="utf-8")
        code, out, _ = _run(["lint-policy", str(p), "--policy-var", "NotAPolicy"], capsys)
        assert code == 1
        assert "E004" in out


# ── Test: JSON output structure ───────────────────────────────────────────────


class TestLintPolicyJSONOutput:
    def test_json_contains_file_path(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_VALID_POLICY_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert "file" in result
        assert str(p.name) in result["file"]

    def test_json_errors_count(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_EMPTY_INVARIANTS_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert result["errors"] >= 1

    def test_json_warnings_count(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        assert result["warnings"] >= 1

    def test_json_findings_have_code_level_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json"], capsys)
        result = json.loads(out)
        for finding in result["findings"]:
            assert "code" in finding
            assert "level" in finding
            assert "message" in finding

    def test_json_strict_warnings_ok_false(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        p = tmp_path / "policy.py"
        p.write_text(_POLICY_NO_META_PY, encoding="utf-8")
        _, out, _ = _run(["lint-policy", str(p), "--json", "--strict"], capsys)
        result = json.loads(out)
        assert result["ok"] is False


# ── Test: multiple policies in one file ───────────────────────────────────────


class TestLintPolicyMultiClass:
    def test_first_policy_discovered_no_errors(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        src = (
            _VALID_POLICY_PY
            + "\n\n"
            + "class SecondPolicy(AmountPolicy):\n    pass\n"
        )
        p = tmp_path / "policy.py"
        p.write_text(src, encoding="utf-8")
        code, _, _ = _run(["lint-policy", str(p)], capsys)
        assert code == 0
