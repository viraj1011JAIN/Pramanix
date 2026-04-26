# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Declarative policy schema migration for Phase B-4.

Usage::

    from pramanix.migration import PolicyMigration

    v1_to_v2 = PolicyMigration(
        from_version=(1, 0, 0),
        to_version=(2, 0, 0),
        field_renames={"account_id": "account_number"},
        removed_fields=["legacy_flag"],
    )

    upgraded_state = v1_to_v2.migrate(old_state_dict)
"""
from __future__ import annotations

import dataclasses
from typing import Any

__all__ = ["PolicyMigration", "MigrationError"]

# Re-export so callers can do: from pramanix.migration import MigrationError
from pramanix.exceptions import MigrationError as MigrationError  # noqa: F401


@dataclasses.dataclass
class PolicyMigration:
    """Declarative schema migration between two policy semver versions.

    Each ``PolicyMigration`` describes the structural transformation needed
    to upgrade a state dict from ``from_version`` to ``to_version``.
    Migrations are purely additive: they rename and remove fields and update
    ``state_version``; they never validate business logic.

    Attributes:
        from_version:   Semver tuple this migration consumes (e.g. ``(1, 0, 0)``).
        to_version:     Semver tuple this migration produces (e.g. ``(2, 0, 0)``).
        field_renames:  Mapping of ``old_field_name → new_field_name``.  Fields
                        absent from the state dict are silently skipped.
        removed_fields: List of field names to drop.  Fields absent from the
                        state dict are silently skipped.

    Example::

        migration = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            field_renames={"acct_id": "account_number"},
            removed_fields=["deprecated_field"],
        )
        new_state = migration.migrate(old_state)
    """

    from_version: tuple[int, int, int]
    to_version: tuple[int, int, int]
    field_renames: dict[str, str] = dataclasses.field(default_factory=dict)
    removed_fields: list[str] = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        for attr, val in (("from_version", self.from_version), ("to_version", self.to_version)):
            if (
                not isinstance(val, tuple)
                or len(val) != 3
                or not all(isinstance(v, int) and v >= 0 for v in val)
            ):
                raise ValueError(
                    f"PolicyMigration.{attr} must be a 3-tuple of non-negative ints, "
                    f"got {val!r}."
                )

    @property
    def from_version_str(self) -> str:
        return "{}.{}.{}".format(*self.from_version)

    @property
    def to_version_str(self) -> str:
        return "{}.{}.{}".format(*self.to_version)

    def migrate(
        self, state: dict[str, Any], *, strict: bool = False
    ) -> dict[str, Any]:
        """Apply this migration to a state dict.

        Renames fields, removes deprecated fields, and updates
        ``state_version`` to :attr:`to_version_str`.

        Args:
            state:  A state dict whose ``state_version`` matches
                    :attr:`from_version_str`.  A copy is returned — the
                    original is never mutated.
            strict: When ``True``, raise :exc:`~pramanix.exceptions.MigrationError`
                    if any key declared in :attr:`field_renames` is absent
                    from *state*.  When ``False`` (default), missing keys are
                    silently skipped for backwards-compatible migrations.

        Returns:
            A new state dict upgraded to :attr:`to_version`.

        Raises:
            MigrationError: If ``strict=True`` and a ``field_renames`` key is
                missing from *state*.
        """
        result = dict(state)
        for old_name, new_name in self.field_renames.items():
            if old_name not in result:
                if strict:
                    raise MigrationError(
                        f"Migration {self.from_version_str!r} → {self.to_version_str!r}: "
                        f"field {old_name!r} not found in state. "
                        "Pass strict=False to skip missing keys silently.",
                        missing_key=old_name,
                        from_version=self.from_version_str,
                        to_version=self.to_version_str,
                    )
            else:
                result[new_name] = result.pop(old_name)
        for field_name in self.removed_fields:
            result.pop(field_name, None)
        result["state_version"] = self.to_version_str
        return result

    def can_migrate(self, state: dict[str, Any]) -> bool:
        """Return ``True`` if *state* has the expected ``state_version``."""
        return state.get("state_version") == self.from_version_str
