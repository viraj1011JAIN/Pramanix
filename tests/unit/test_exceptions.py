# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.exceptions — class hierarchy, attributes, messages.

Coverage targets:
- Complete subclass hierarchy (issubclass assertions)
- All exceptions are ultimately Exception subclasses
- Exception raisability and catch-as-parent contracts
- SolverTimeoutError: label, timeout_ms attrs, message formatting
- StateValidationError: expected, actual attrs, default None values
- Every exception can be instantiated with a plain message string
"""
from __future__ import annotations

import pytest

from pramanix.exceptions import (
    ConfigurationError,
    FieldTypeError,
    GuardError,
    InvariantLabelError,
    PolicyCompilationError,
    PolicyError,
    PramanixError,
    SolverError,
    SolverTimeoutError,
    StateValidationError,
    TranspileError,
    ValidationError,
    WorkerError,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Heritage hierarchy
# ═══════════════════════════════════════════════════════════════════════════════


class TestHierarchy:
    """Every exception must be a subclass of the documented parent."""

    # Root
    def test_pramanix_error_is_exception(self) -> None:
        assert issubclass(PramanixError, Exception)

    # PolicyError branch
    def test_policy_error_is_pramanix_error(self) -> None:
        assert issubclass(PolicyError, PramanixError)

    def test_policy_compilation_error_is_policy_error(self) -> None:
        assert issubclass(PolicyCompilationError, PolicyError)

    def test_policy_compilation_error_is_pramanix_error(self) -> None:
        assert issubclass(PolicyCompilationError, PramanixError)

    def test_invariant_label_error_is_policy_error(self) -> None:
        assert issubclass(InvariantLabelError, PolicyError)

    def test_invariant_label_error_is_pramanix_error(self) -> None:
        assert issubclass(InvariantLabelError, PramanixError)

    def test_field_type_error_is_policy_error(self) -> None:
        assert issubclass(FieldTypeError, PolicyError)

    def test_field_type_error_is_pramanix_error(self) -> None:
        assert issubclass(FieldTypeError, PramanixError)

    def test_transpile_error_is_policy_error(self) -> None:
        assert issubclass(TranspileError, PolicyError)

    def test_transpile_error_is_pramanix_error(self) -> None:
        assert issubclass(TranspileError, PramanixError)

    # GuardError branch
    def test_guard_error_is_pramanix_error(self) -> None:
        assert issubclass(GuardError, PramanixError)

    def test_validation_error_is_guard_error(self) -> None:
        assert issubclass(ValidationError, GuardError)

    def test_validation_error_is_pramanix_error(self) -> None:
        assert issubclass(ValidationError, PramanixError)

    def test_state_validation_error_is_guard_error(self) -> None:
        assert issubclass(StateValidationError, GuardError)

    def test_state_validation_error_is_pramanix_error(self) -> None:
        assert issubclass(StateValidationError, PramanixError)

    def test_solver_timeout_error_is_guard_error(self) -> None:
        assert issubclass(SolverTimeoutError, GuardError)

    def test_solver_timeout_error_is_pramanix_error(self) -> None:
        assert issubclass(SolverTimeoutError, PramanixError)

    def test_solver_error_is_guard_error(self) -> None:
        assert issubclass(SolverError, GuardError)

    def test_solver_error_is_pramanix_error(self) -> None:
        assert issubclass(SolverError, PramanixError)

    def test_worker_error_is_guard_error(self) -> None:
        assert issubclass(WorkerError, GuardError)

    def test_worker_error_is_pramanix_error(self) -> None:
        assert issubclass(WorkerError, PramanixError)

    # ConfigurationError branch
    def test_configuration_error_is_pramanix_error(self) -> None:
        assert issubclass(ConfigurationError, PramanixError)

    def test_configuration_error_is_exception(self) -> None:
        assert issubclass(ConfigurationError, Exception)

    @pytest.mark.parametrize(
        "exc_class",
        [
            PramanixError,
            PolicyError,
            PolicyCompilationError,
            InvariantLabelError,
            FieldTypeError,
            TranspileError,
            GuardError,
            ValidationError,
            StateValidationError,
            SolverTimeoutError,
            SolverError,
            WorkerError,
            ConfigurationError,
        ],
    )
    def test_all_are_exception_subclasses(self, exc_class: type[BaseException]) -> None:
        assert issubclass(exc_class, Exception)


# ═══════════════════════════════════════════════════════════════════════════════
# Raisability and catch-as-parent
# ═══════════════════════════════════════════════════════════════════════════════


class TestRaisability:
    """Every exception must be raisable and catchable by its parent types."""

    def test_pramanix_error_raises(self) -> None:
        with pytest.raises(PramanixError):
            raise PramanixError("base error")

    def test_policy_error_caught_as_pramanix_error(self) -> None:
        with pytest.raises(PramanixError):
            raise PolicyError("bad policy")

    def test_policy_compilation_error_caught_as_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            raise PolicyCompilationError("unsupported type")

    def test_invariant_label_error_caught_as_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            raise InvariantLabelError("missing label")

    def test_field_type_error_caught_as_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            raise FieldTypeError("unknown z3_type")

    def test_transpile_error_caught_as_policy_error(self) -> None:
        with pytest.raises(PolicyError):
            raise TranspileError("unknown node type")

    def test_validation_error_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise ValidationError("bad intent data")

    def test_validation_error_caught_as_pramanix_error(self) -> None:
        with pytest.raises(PramanixError):
            raise ValidationError("bad state data")

    def test_state_validation_error_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise StateValidationError("state_version missing")

    def test_state_validation_error_caught_as_pramanix_error(self) -> None:
        with pytest.raises(PramanixError):
            raise StateValidationError("state_version mismatch")

    def test_solver_timeout_error_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise SolverTimeoutError("lbl", 100)

    def test_solver_timeout_error_caught_as_pramanix_error(self) -> None:
        with pytest.raises(PramanixError):
            raise SolverTimeoutError("lbl", 100)

    def test_solver_error_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise SolverError("z3.unknown")

    def test_worker_error_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise WorkerError("worker died")

    def test_configuration_error_caught_as_pramanix_error(self) -> None:
        with pytest.raises(PramanixError):
            raise ConfigurationError("bad config")


# ═══════════════════════════════════════════════════════════════════════════════
# SolverTimeoutError — structured attributes
# ═══════════════════════════════════════════════════════════════════════════════


class TestSolverTimeoutError:
    """SolverTimeoutError must store label and timeout_ms as attributes."""

    def test_label_attribute(self) -> None:
        err = SolverTimeoutError("non_negative_balance", 5_000)
        assert err.label == "non_negative_balance"

    def test_timeout_ms_attribute(self) -> None:
        err = SolverTimeoutError("non_negative_balance", 5_000)
        assert err.timeout_ms == 5_000

    def test_message_contains_label(self) -> None:
        err = SolverTimeoutError("within_daily_limit", 2_000)
        assert "within_daily_limit" in str(err)

    def test_message_contains_timeout_ms(self) -> None:
        err = SolverTimeoutError("within_daily_limit", 2_000)
        assert "2000" in str(err)

    @pytest.mark.parametrize(
        ("label", "timeout_ms"),
        [
            ("non_negative_balance", 10),
            ("<all-invariants>", 5_000),
            ("account_not_frozen", 100),
        ],
    )
    def test_attributes_match_constructor_args(self, label: str, timeout_ms: int) -> None:
        err = SolverTimeoutError(label, timeout_ms)
        assert err.label == label
        assert err.timeout_ms == timeout_ms

    def test_is_guard_error_instance(self) -> None:
        err = SolverTimeoutError("lbl", 1_000)
        assert isinstance(err, GuardError)
        assert isinstance(err, PramanixError)

    def test_str_is_non_empty(self) -> None:
        err = SolverTimeoutError("lbl", 50)
        assert len(str(err)) > 0


# ═══════════════════════════════════════════════════════════════════════════════
# StateValidationError — structured attributes and defaults
# ═══════════════════════════════════════════════════════════════════════════════


class TestStateValidationError:
    """StateValidationError carries optional expected/actual version attributes."""

    def test_message_stored(self) -> None:
        err = StateValidationError("version missing from model")
        assert "version missing" in str(err)

    def test_expected_attribute(self) -> None:
        err = StateValidationError("mismatch", expected="1.0", actual="0.9")
        assert err.expected == "1.0"

    def test_actual_attribute(self) -> None:
        err = StateValidationError("mismatch", expected="1.0", actual="0.9")
        assert err.actual == "0.9"

    def test_defaults_to_none_when_not_provided(self) -> None:
        err = StateValidationError("missing field")
        assert err.expected is None
        assert err.actual is None

    def test_is_guard_error_instance(self) -> None:
        err = StateValidationError("x")
        assert isinstance(err, GuardError)
        assert isinstance(err, PramanixError)

    def test_caught_as_guard_error(self) -> None:
        with pytest.raises(GuardError):
            raise StateValidationError("state_version is missing")


# ═══════════════════════════════════════════════════════════════════════════════
# Simple instantiation guarantee
# ═══════════════════════════════════════════════════════════════════════════════


class TestSimpleInstantiation:
    """All simple-message exceptions must accept a single string argument."""

    @pytest.mark.parametrize(
        "exc_class",
        [
            PramanixError,
            PolicyError,
            PolicyCompilationError,
            InvariantLabelError,
            FieldTypeError,
            TranspileError,
            GuardError,
            ValidationError,
            SolverError,
            WorkerError,
            ConfigurationError,
        ],
    )
    def test_instantiable_with_string_message(self, exc_class: type[Exception]) -> None:
        err = exc_class("test message")
        assert "test message" in str(err)
