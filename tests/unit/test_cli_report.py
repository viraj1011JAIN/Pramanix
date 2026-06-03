# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Tests for the ``pramanix report`` CLI subcommand (P3.6).

All tests use the real CLI entry-point, real file I/O, and real
ComplianceReport serialization — no mocks.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest

from pramanix.cli import main
from pramanix.helpers.compliance import ComplianceReport


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_report(**overrides) -> ComplianceReport:
    defaults = dict(
        decision_id="test-decision-id-001",
        decision_hash="sha256-abc123",
        timestamp="2026-06-01T00:00:00Z",
        verdict="BLOCKED",
        severity="HIGH",
        policy_name="TransferPolicy",
        policy_version="1.0",
        violated_rules=("amount_limit",),
        compliance_rationale=("Amount exceeds configured limit",),
        regulatory_refs=("SOC2 CC6.1",),
        explanation="Amount 9999 > limit 500",
    )
    defaults.update(overrides)
    return ComplianceReport(**defaults)


def _write_report_json(tmp_path: Path, **overrides) -> Path:
    report = _make_report(**overrides)
    p = tmp_path / "report.json"
    p.write_text(report.to_json(), encoding="utf-8")
    return p


# ── Text format (default) ──────────────────────────────────────────────────────

class TestReportTextFormat:
    def test_text_output_contains_header(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file)]
        rc = main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "PRAMANIX COMPLIANCE REPORT" in out

    def test_text_output_contains_verdict(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file)]
        main()
        out = capsys.readouterr().out
        assert "BLOCKED" in out

    def test_text_output_contains_policy(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file)]
        main()
        out = capsys.readouterr().out
        assert "TransferPolicy" in out
        assert "1.0" in out

    def test_text_output_contains_violated_rules(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file)]
        main()
        out = capsys.readouterr().out
        assert "amount_limit" in out

    def test_text_output_contains_regulatory_refs(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file)]
        main()
        out = capsys.readouterr().out
        assert "SOC2 CC6.1" in out

    def test_text_output_allowed_verdict(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(
            tmp_path,
            verdict="ALLOWED",
            violated_rules=(),
            severity="MEDIUM",
        )
        sys.argv = ["pramanix", "report", str(report_file)]
        main()
        out = capsys.readouterr().out
        assert "ALLOWED" in out

    def test_text_write_to_file(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        out_file = tmp_path / "output.txt"
        sys.argv = ["pramanix", "report", str(report_file), "--out", str(out_file)]
        rc = main()
        assert rc == 0
        content = out_file.read_text(encoding="utf-8")
        assert "PRAMANIX COMPLIANCE REPORT" in content
        # Nothing written to stdout when --out is used
        assert capsys.readouterr().out == ""


# ── JSON format ────────────────────────────────────────────────────────────────

class TestReportJsonFormat:
    def test_json_output_is_valid_json(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file), "--format", "json"]
        rc = main()
        out = capsys.readouterr().out
        assert rc == 0
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_json_output_fields(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file), "--format", "json"]
        main()
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["decision_id"] == "test-decision-id-001"
        assert parsed["verdict"] == "BLOCKED"
        assert parsed["policy_name"] == "TransferPolicy"
        assert "amount_limit" in parsed["violated_rules"]

    def test_json_write_to_file(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        out_file = tmp_path / "output.json"
        sys.argv = [
            "pramanix", "report", str(report_file), "--format", "json",
            "--out", str(out_file),
        ]
        rc = main()
        assert rc == 0
        content = json.loads(out_file.read_text(encoding="utf-8"))
        assert content["verdict"] == "BLOCKED"
        assert capsys.readouterr().out == ""


# ── PDF format ─────────────────────────────────────────────────────────────────

class TestReportPdfFormat:
    def test_pdf_requires_out_flag(self, tmp_path: Path, capsys) -> None:
        report_file = _write_report_json(tmp_path)
        sys.argv = ["pramanix", "report", str(report_file), "--format", "pdf"]
        rc = main()
        assert rc == 2
        assert "--out" in capsys.readouterr().err

    def test_pdf_written_when_fpdf2_available(self, tmp_path: Path, capsys) -> None:
        fpdf2 = pytest.importorskip("fpdf", reason="fpdf2 not installed — skipping PDF test")
        report_file = _write_report_json(tmp_path)
        out_file = tmp_path / "output.pdf"
        sys.argv = [
            "pramanix", "report", str(report_file), "--format", "pdf",
            "--out", str(out_file),
        ]
        rc = main()
        assert rc == 0
        assert out_file.exists()
        assert out_file.read_bytes()[:4] == b"%PDF"


# ── Error handling ─────────────────────────────────────────────────────────────

class TestReportErrors:
    def test_missing_file_returns_2(self, tmp_path: Path, capsys) -> None:
        sys.argv = ["pramanix", "report", str(tmp_path / "nonexistent.json")]
        rc = main()
        assert rc == 2
        assert "not found" in capsys.readouterr().err.lower()

    def test_invalid_json_returns_2(self, tmp_path: Path, capsys) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("not json at all!!!", encoding="utf-8")
        sys.argv = ["pramanix", "report", str(bad_file)]
        rc = main()
        assert rc == 2
        assert "Invalid JSON" in capsys.readouterr().err

    def test_non_dict_json_returns_2(self, tmp_path: Path, capsys) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("[1, 2, 3]", encoding="utf-8")
        sys.argv = ["pramanix", "report", str(bad_file)]
        rc = main()
        assert rc == 2

    def test_stdin_text_format(self, tmp_path: Path, capsys, monkeypatch) -> None:
        report = _make_report()
        monkeypatch.setattr("sys.stdin", io.StringIO(report.to_json()))
        sys.argv = ["pramanix", "report", "-"]
        rc = main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "PRAMANIX COMPLIANCE REPORT" in out
