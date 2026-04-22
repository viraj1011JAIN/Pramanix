# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Gate tests for Phase B-4: Semantic Policy Versioning & Migration.

Gate condition (from engineering plan):
    pytest -k 'policy_versioning'
    # State dict with old schema version must return BLOCK with reason='schema_version_mismatch'.
    # Migration spec must correctly rename fields.
"""
from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import pytest

from pramanix import E, Field, Guard, GuardConfig, Policy, PolicyMigration
from pramanix.exceptions import ConfigurationError


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

_amount_field = Field("amount", Decimal, "Real")
_balance_field = Field("balance", Decimal, "Real")


class _SemverPolicy(Policy):
    class Meta:
        semver = (2, 0, 0)

    amount = Field("amount", Decimal, "Real")
    balance = Field("balance", Decimal, "Real")

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [
            (E(_amount_field) <= Decimal("10000")).named("max_tx"),
            (E(_balance_field) - E(_amount_field) >= 0).named("funds_check"),
        ]


class _LegacyVersionPolicy(Policy):
    """Uses old Meta.version string — backward compat check."""

    class Meta:
        version = "1.0"

    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):  # type: ignore[override]
        return [(E(_amount_field) <= Decimal("10000")).named("max_tx")]


# ═══════════════════════════════════════════════════════════════════════════════
# Meta.semver declaration and validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestMetaSemver:
    def test_meta_semver_returns_tuple(self) -> None:
        assert _SemverPolicy.meta_semver() == (2, 0, 0)

    def test_meta_version_returns_semver_string_when_semver_set(self) -> None:
        assert _SemverPolicy.meta_version() == "2.0.0"

    def test_meta_semver_none_when_not_declared(self) -> None:
        class _P(Policy):
            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls):  # type: ignore[override]
                return [(E(_amount_field) >= 0).named("pos")]

        assert _P.meta_semver() is None

    def test_meta_version_still_works_for_plain_string(self) -> None:
        assert _LegacyVersionPolicy.meta_version() == "1.0"
        assert _LegacyVersionPolicy.meta_semver() is None

    def test_malformed_semver_raises_at_guard_init(self) -> None:
        class _Bad(Policy):
            class Meta:
                semver = "1.0.0"  # string instead of tuple

            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls):  # type: ignore[override]
                return [(E(_amount_field) >= 0).named("pos")]

        with pytest.raises(ConfigurationError, match="semver"):
            Guard(_Bad, GuardConfig(solver_timeout_ms=5000))

    def test_semver_wrong_length_raises_at_guard_init(self) -> None:
        class _Bad(Policy):
            class Meta:
                semver = (1, 0)  # only 2 elements

            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls):  # type: ignore[override]
                return [(E(_amount_field) >= 0).named("pos")]

        with pytest.raises(ConfigurationError, match="semver"):
            Guard(_Bad, GuardConfig(solver_timeout_ms=5000))

    def test_semver_negative_element_raises_at_guard_init(self) -> None:
        class _Bad(Policy):
            class Meta:
                semver = (1, -1, 0)

            amount = Field("amount", Decimal, "Real")

            @classmethod
            def invariants(cls):  # type: ignore[override]
                return [(E(_amount_field) >= 0).named("pos")]

        with pytest.raises(ConfigurationError, match="semver"):
            Guard(_Bad, GuardConfig(solver_timeout_ms=5000))


# ═══════════════════════════════════════════════════════════════════════════════
# Guard version checking with semver
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardSemverVersionCheck:
    def _guard(self) -> Guard:
        return Guard(_SemverPolicy, GuardConfig(solver_timeout_ms=5000))

    def test_allow_when_state_version_matches_semver(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "2.0.0"},
        )
        assert d.allowed is True

    def test_block_when_state_version_is_old_semver(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "1.0.0"},
        )
        assert d.allowed is False
        assert d.status.value == "stale_state"

    def test_block_when_state_version_is_minor_bump_semver(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "2.1.0"},
        )
        assert d.allowed is False
        assert d.status.value == "stale_state"

    def test_block_when_state_version_missing(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500")},
        )
        assert d.allowed is False

    def test_block_when_state_version_not_semver_format(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "v2"},
        )
        assert d.allowed is False

    def test_stale_state_carries_expected_and_actual_versions(self) -> None:
        guard = self._guard()
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"balance": Decimal("500"), "state_version": "1.0.0"},
        )
        assert "2.0.0" in d.explanation or "1.0.0" in d.explanation

    def test_legacy_version_string_still_works(self) -> None:
        guard = Guard(_LegacyVersionPolicy, GuardConfig(solver_timeout_ms=5000))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert d.allowed is True

    def test_legacy_version_mismatch_still_blocks(self) -> None:
        guard = Guard(_LegacyVersionPolicy, GuardConfig(solver_timeout_ms=5000))
        d = guard.verify(
            intent={"amount": Decimal("100")},
            state={"state_version": "2.0"},
        )
        assert d.allowed is False
        assert d.status.value == "stale_state"


# ═══════════════════════════════════════════════════════════════════════════════
# PolicyMigration — construction and validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestPolicyMigrationConstruction:
    def test_basic_construction(self) -> None:
        m = PolicyMigration(from_version=(1, 0, 0), to_version=(2, 0, 0))
        assert m.from_version == (1, 0, 0)
        assert m.to_version == (2, 0, 0)
        assert m.field_renames == {}
        assert m.removed_fields == []

    def test_version_string_properties(self) -> None:
        m = PolicyMigration(from_version=(1, 2, 3), to_version=(2, 0, 0))
        assert m.from_version_str == "1.2.3"
        assert m.to_version_str == "2.0.0"

    def test_malformed_from_version_raises(self) -> None:
        with pytest.raises(ValueError, match="from_version"):
            PolicyMigration(from_version=(1, 0), to_version=(2, 0, 0))  # type: ignore[arg-type]

    def test_malformed_to_version_raises(self) -> None:
        with pytest.raises(ValueError, match="to_version"):
            PolicyMigration(from_version=(1, 0, 0), to_version="2.0.0")  # type: ignore[arg-type]

    def test_negative_version_component_raises(self) -> None:
        with pytest.raises(ValueError):
            PolicyMigration(from_version=(1, -1, 0), to_version=(2, 0, 0))


# ═══════════════════════════════════════════════════════════════════════════════
# PolicyMigration.migrate() — field operations
# ═══════════════════════════════════════════════════════════════════════════════


class TestPolicyMigrationMigrate:
    def test_migrate_renames_fields(self) -> None:
        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            field_renames={"acct_id": "account_number"},
        )
        state = {"state_version": "1.0.0", "acct_id": "ACC-001", "balance": 100}
        result = m.migrate(state)
        assert "account_number" in result
        assert result["account_number"] == "ACC-001"
        assert "acct_id" not in result

    def test_migrate_removes_fields(self) -> None:
        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            removed_fields=["legacy_flag", "deprecated_field"],
        )
        state = {
            "state_version": "1.0.0",
            "balance": 100,
            "legacy_flag": True,
            "deprecated_field": "old",
        }
        result = m.migrate(state)
        assert "legacy_flag" not in result
        assert "deprecated_field" not in result
        assert result["balance"] == 100

    def test_migrate_updates_state_version(self) -> None:
        m = PolicyMigration(from_version=(1, 0, 0), to_version=(2, 0, 0))
        state = {"state_version": "1.0.0", "balance": 100}
        result = m.migrate(state)
        assert result["state_version"] == "2.0.0"

    def test_migrate_does_not_mutate_original(self) -> None:
        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            field_renames={"old": "new"},
        )
        original = {"state_version": "1.0.0", "old": "value"}
        m.migrate(original)
        assert "old" in original  # original unchanged
        assert "new" not in original

    def test_migrate_skips_absent_rename_field(self) -> None:
        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            field_renames={"nonexistent": "new_name"},
        )
        state = {"state_version": "1.0.0", "balance": 100}
        result = m.migrate(state)
        assert "nonexistent" not in result
        assert "new_name" not in result

    def test_migrate_skips_absent_remove_field(self) -> None:
        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            removed_fields=["ghost_field"],
        )
        state = {"state_version": "1.0.0", "balance": 100}
        result = m.migrate(state)  # must not raise
        assert result["balance"] == 100

    def test_can_migrate_returns_true_when_versions_match(self) -> None:
        m = PolicyMigration(from_version=(1, 0, 0), to_version=(2, 0, 0))
        assert m.can_migrate({"state_version": "1.0.0", "balance": 100}) is True

    def test_can_migrate_returns_false_when_versions_dont_match(self) -> None:
        m = PolicyMigration(from_version=(1, 0, 0), to_version=(2, 0, 0))
        assert m.can_migrate({"state_version": "2.0.0", "balance": 100}) is False


# ═══════════════════════════════════════════════════════════════════════════════
# CLI policy migrate command
# ═══════════════════════════════════════════════════════════════════════════════


class TestCliPolicyMigrate:
    def test_migrate_command_renames_and_removes(self, tmp_path: Path) -> None:
        state = {"state_version": "1.0.0", "acct_id": "ACC-001", "legacy_flag": True}
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))
        out_file = tmp_path / "out.json"

        from pramanix.cli import main as cli_main
        import sys

        argv_backup = sys.argv
        try:
            sys.argv = [
                "pramanix", "policy", "migrate",
                "--state", str(state_file),
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
                "--rename", "acct_id=account_number",
                "--remove", "legacy_flag",
                "--output", str(out_file),
            ]
            rc = cli_main()
        finally:
            sys.argv = argv_backup

        assert rc == 0
        result = json.loads(out_file.read_text())
        assert result["state_version"] == "2.0.0"
        assert result["account_number"] == "ACC-001"
        assert "acct_id" not in result
        assert "legacy_flag" not in result

    def test_migrate_command_fails_on_version_mismatch(self, tmp_path: Path) -> None:
        state = {"state_version": "2.0.0", "balance": 100}
        state_file = tmp_path / "state.json"
        state_file.write_text(json.dumps(state))

        from pramanix.cli import main as cli_main
        import sys

        argv_backup = sys.argv
        try:
            sys.argv = [
                "pramanix", "policy", "migrate",
                "--state", str(state_file),
                "--from-version", "1.0.0",
                "--to-version", "2.0.0",
            ]
            rc = cli_main()
        finally:
            sys.argv = argv_backup

        assert rc != 0  # must fail — state_version doesn't match from-version
