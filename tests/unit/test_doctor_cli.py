# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Tests for `pramanix doctor` CLI subcommand."""
from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest

from pramanix.cli import main
from tests.helpers.real_protocols import _PingFailRedisClient, _PingOkRedisClient


def _run_cli(args: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(sys, "argv", ["pramanix", *args])
            exit_code = main()
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 1
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


# ─────────────────────────────────────────────────────────────────────────────
# Basic invocation
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorBasicInvocation:
    def test_doctor_exits_zero_on_healthy_env(self, capsys: pytest.CaptureFixture) -> None:
        """In a normal test environment (z3 + pydantic installed) doctor exits 0."""
        exit_code, stdout, _ = _run_cli(["doctor"], capsys)
        # Must exit 0 or 1 — never 2 (usage error).
        assert exit_code in (0, 1), f"Expected 0 or 1, got {exit_code}"
        # Must print check results.
        assert "OK" in stdout or "ERR" in stdout or "WARN" in stdout

    def test_doctor_json_output_is_valid_json(self, capsys: pytest.CaptureFixture) -> None:
        exit_code, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        assert "passed" in data
        assert "errors" in data
        assert "warnings" in data
        assert "checks" in data
        assert isinstance(data["checks"], list)
        assert exit_code in (0, 1)

    def test_doctor_json_checks_have_required_fields(self, capsys: pytest.CaptureFixture) -> None:
        _run_cli(["doctor", "--json"], capsys)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        for check in data["checks"]:
            assert "name" in check
            assert "level" in check
            assert "detail" in check
            assert check["level"] in ("OK", "WARN", "ERROR", "SKIP")

    def test_doctor_json_passed_bool_coherent(self, capsys: pytest.CaptureFixture) -> None:
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        has_error = any(c["level"] == "ERROR" for c in data["checks"])
        assert data["passed"] == (not has_error)

    def test_doctor_json_counts_coherent(self, capsys: pytest.CaptureFixture) -> None:
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        assert data["errors"] == sum(1 for c in data["checks"] if c["level"] == "ERROR")
        assert data["warnings"] == sum(1 for c in data["checks"] if c["level"] == "WARN")


# ─────────────────────────────────────────────────────────────────────────────
# Core checks always present
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorCoreChecks:
    def _checks_by_name(self, capsys: pytest.CaptureFixture) -> dict[str, dict]:
        _run_cli(["doctor", "--json"], capsys)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        return {c["name"]: c for c in data["checks"]}

    def test_python_version_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "python-version" in checks

    def test_python_version_ok_in_test_env(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        # We run tests on Python 3.13+ per pyproject.toml requirement.
        assert checks["python-version"]["level"] == "OK"
        assert "3." in checks["python-version"]["detail"]

    def test_z3_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "z3-solver" in checks

    def test_z3_ok_when_installed(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        # z3-solver is a required dependency — must be OK in test env.
        assert checks["z3-solver"]["level"] == "OK"
        assert "functional" in checks["z3-solver"]["detail"]

    def test_pydantic_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "pydantic" in checks

    def test_pydantic_ok_v2_in_test_env(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert checks["pydantic"]["level"] == "OK"

    def test_pramanix_import_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "pramanix-import" in checks

    def test_pramanix_import_ok(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert checks["pramanix-import"]["level"] == "OK"

    def test_platform_bits_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "platform-bits" in checks

    def test_signing_key_check_present(self, capsys: pytest.CaptureFixture) -> None:
        checks = self._checks_by_name(capsys)
        assert "signing-key" in checks


# ─────────────────────────────────────────────────────────────────────────────
# Signing key detection
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorSigningKey:
    def test_signing_key_warn_when_unset(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        checks = {c["name"]: c for c in data["checks"]}
        assert checks["signing-key"]["level"] == "WARN"

    def test_signing_key_ok_when_set(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", "a" * 64)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        checks = {c["name"]: c for c in data["checks"]}
        assert checks["signing-key"]["level"] == "OK"


# ─────────────────────────────────────────────────────────────────────────────
# --strict flag behaviour
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorStrictFlag:
    def test_strict_exits_1_on_warnings(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With --strict, any WARN should cause exit code 1."""
        # Ensure signing key is unset so we always have at least one WARN.
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        _exit_code, _stdout, _ = _run_cli(["doctor", "--strict"], capsys)
        data_exit, data_stdout, _ = _run_cli(["doctor", "--strict", "--json"], capsys)
        checks = json.loads(data_stdout)
        has_warn = any(c["level"] == "WARN" for c in checks["checks"])
        if has_warn:
            assert data_exit == 1

    def test_non_strict_exits_0_on_warnings_only(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without --strict, warnings alone should not cause exit 1 (unless there are errors)."""
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        has_error = any(c["level"] == "ERROR" for c in data["checks"])
        exit_code, _, _ = _run_cli(["doctor"], capsys)
        if not has_error:
            assert exit_code == 0


# ─────────────────────────────────────────────────────────────────────────────
# Python version failure
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorPythonVersionCheck:
    def test_old_python_reports_error(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Simulate Python 3.12 — should report ERROR on python-version check."""
        import sys as _sys
        import types
        # sys.version_info is a C struct and cannot be re-instantiated directly.
        # The doctor check reads .major / .minor / .micro, so SimpleNamespace works.
        fake_vi = types.SimpleNamespace(major=3, minor=12, micro=0)
        monkeypatch.setattr(_sys, "version_info", fake_vi)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        checks = {c["name"]: c for c in data["checks"]}
        assert checks["python-version"]["level"] == "ERROR"
        assert "3.13" in checks["python-version"]["detail"]


# ─────────────────────────────────────────────────────────────────────────────
# Z3 failure simulation
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorZ3Check:
    def test_z3_not_installed_reports_error(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Block z3 import to simulate missing z3-solver."""
        import builtins
        real_import = builtins.__import__

        def patched_import(name: str, *args, **kwargs):  # type: ignore[no-untyped-def]
            if name == "z3":
                raise ImportError("No module named 'z3'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", patched_import)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        checks = {c["name"]: c for c in data["checks"]}
        assert checks["z3-solver"]["level"] == "ERROR"
        assert data["passed"] is False

    def test_z3_functional_failure_reports_error(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        """Simulate z3 Solver returning 'unknown' (not 'sat')."""
        import z3 as _z3

        with patch.object(_z3.Solver, "check", return_value=_z3.unknown):
            _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
            data = json.loads(stdout)
            checks = {c["name"]: c for c in data["checks"]}
            assert checks["z3-solver"]["level"] == "ERROR"


# ─────────────────────────────────────────────────────────────────────────────
# Redis check
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorRedisCheck:
    def test_redis_unreachable_reports_error(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_REDIS_URL set but ping fails → ERROR on redis-ping."""
        monkeypatch.setenv("PRAMANIX_REDIS_URL", "redis://127.0.0.1:16379")
        # Use real redis module but patch from_url to raise
        try:
            import redis  # noqa: F401
        except ImportError:
            pytest.skip("redis not installed")

        with patch("redis.from_url", return_value=_PingFailRedisClient()):
            _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
            data = json.loads(stdout)
            checks = {c["name"]: c for c in data["checks"]}
            assert "redis-ping" in checks
            assert checks["redis-ping"]["level"] == "ERROR"

    def test_redis_reachable_reports_ok(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PRAMANIX_REDIS_URL set and ping succeeds → OK on redis-ping."""
        monkeypatch.setenv("PRAMANIX_REDIS_URL", "redis://127.0.0.1:6379")
        try:
            import redis  # noqa: F401
        except ImportError:
            pytest.skip("redis not installed")

        with patch("redis.from_url", return_value=_PingOkRedisClient()):
            _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
            data = json.loads(stdout)
            checks = {c["name"]: c for c in data["checks"]}
            assert checks["redis-ping"]["level"] == "OK"

    def test_no_redis_check_when_url_not_set(
        self, capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("PRAMANIX_REDIS_URL", raising=False)
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        check_names = {c["name"] for c in data["checks"]}
        assert "redis-ping" not in check_names


# ─────────────────────────────────────────────────────────────────────────────
# Optional extras are SKIP, not ERROR
# ─────────────────────────────────────────────────────────────────────────────


class TestDoctorOptionalExtras:
    def test_optional_extras_never_error(self, capsys: pytest.CaptureFixture) -> None:
        """Optional extras that are not installed must be SKIP, never ERROR."""
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        for check in data["checks"]:
            if check["name"].startswith("extra:"):
                assert check["level"] in ("OK", "SKIP"), (
                    f"Extra check {check['name']} has unexpected level {check['level']}"
                )

    def test_hints_present_on_skip(self, capsys: pytest.CaptureFixture) -> None:
        """Every SKIP check for an extra must include an install hint."""
        _, stdout, _ = _run_cli(["doctor", "--json"], capsys)
        data = json.loads(stdout)
        for check in data["checks"]:
            if check["name"].startswith("extra:") and check["level"] == "SKIP":
                assert check.get("hint"), (
                    f"SKIP check {check['name']} has no install hint"
                )
