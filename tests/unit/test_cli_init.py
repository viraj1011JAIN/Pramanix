# SPDX-License-Identifier: Apache-2.0
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for `pramanix init` CLI subcommand."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pramanix.cli import main


class TestInitSubcommand:
    def test_init_writes_finance_template(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out_file = tmp_path / "finance_guard.yaml"
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "init",
                "--template",
                "finance",
                "--output",
                str(out_file),
            ],
        )
        assert main() == 0
        content = out_file.read_text(encoding="utf-8")
        assert "policy_name: finance_trade_guard" in content

    def test_init_refuses_overwrite_without_force(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out_file = tmp_path / "policy.yaml"
        out_file.write_text("old-content\n", encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "init",
                "--template",
                "pii",
                "--output",
                str(out_file),
            ],
        )
        assert main() == 2
        assert out_file.read_text(encoding="utf-8") == "old-content\n"

    def test_init_force_overwrites_existing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        out_file = tmp_path / "policy.yaml"
        out_file.write_text("old-content\n", encoding="utf-8")
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "pramanix",
                "init",
                "--template",
                "infra",
                "--output",
                str(out_file),
                "--force",
            ],
        )
        assert main() == 0
        content = out_file.read_text(encoding="utf-8")
        assert "policy_name: infra_scale_guard" in content
