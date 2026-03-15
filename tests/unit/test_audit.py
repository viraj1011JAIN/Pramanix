# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for Pramanix cryptographic audit trail.

Tests DecisionSigner, DecisionVerifier, MerkleAnchor, and CLI.
"""
from __future__ import annotations

import json
import sys
from typing import Any

import pytest

from pramanix.audit.merkle import MerkleAnchor
from pramanix.audit.signer import DecisionSigner, SignedDecision
from pramanix.audit.verifier import DecisionVerifier
from pramanix.decision import Decision

_KEY_32 = "x" * 32
_KEY_64 = "x" * 64


def _make_block_decision() -> Decision:
    return Decision.unsafe(
        violated_invariants=("overdraft_limit", "kyc_required"),
        explanation="Transfer blocked: insufficient balance.",
    )


def _make_allow_decision() -> Decision:
    return Decision.safe(solver_time_ms=12.5)


# ── TestDecisionSigner ────────────────────────────────────────────────────────


class TestDecisionSigner:
    def test_sign_returns_none_without_key(self, monkeypatch):
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        signer = DecisionSigner(signing_key=None)
        d = _make_block_decision()
        assert signer.sign(d) is None

    def test_sign_returns_none_with_short_key(self):
        signer = DecisionSigner(signing_key="short")
        d = _make_block_decision()
        assert signer.sign(d) is None

    def test_sign_returns_signed_decision_with_valid_key(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        result = signer.sign(d)
        assert result is not None
        assert isinstance(result, SignedDecision)
        assert len(result.token) > 20

    def test_token_has_three_parts(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_allow_decision()
        result = signer.sign(d)
        assert result is not None
        parts = result.token.split(".")
        assert len(parts) == 3

    def test_token_is_url_safe(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        result = signer.sign(d)
        assert result is not None
        assert "+" not in result.token
        assert "/" not in result.token
        assert "=" not in result.token

    def test_signed_decision_id_matches_original(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        result = signer.sign(d)
        assert result is not None
        assert result.decision_id == d.decision_id

    def test_is_active_false_without_key(self, monkeypatch):
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        signer = DecisionSigner(signing_key=None)
        assert signer.is_active is False

    def test_is_active_true_with_valid_key(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        assert signer.is_active is True

    def test_sign_never_raises_on_garbage_input(self, monkeypatch):
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()

        def _boom(decision: Any) -> dict:
            raise RuntimeError("simulated canonicalize failure")

        monkeypatch.setattr(signer, "_canonicalize", _boom)
        result = signer.sign(d)
        assert result is None


# ── TestDecisionVerifier ──────────────────────────────────────────────────────


class TestDecisionVerifier:
    def test_constructor_raises_on_empty_key(self):
        with pytest.raises(ValueError, match="Signing key must be"):
            DecisionVerifier(signing_key="")

    def test_constructor_raises_on_short_key(self):
        with pytest.raises(ValueError):
            DecisionVerifier(signing_key="tooshort")

    def test_verify_valid_token_returns_valid_true(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        result = verifier.verify(signed.token)
        assert result.valid is True

    def test_verify_result_decision_id_matches(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        result = verifier.verify(signed.token)
        assert result.decision_id == d.decision_id

    def test_verify_result_allowed_matches(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)

        block_d = _make_block_decision()
        allow_d = _make_allow_decision()

        block_signed = signer.sign(block_d)
        allow_signed = signer.sign(allow_d)

        assert block_signed is not None
        assert allow_signed is not None

        assert verifier.verify(block_signed.token).allowed is False
        assert verifier.verify(allow_signed.token).allowed is True

    def test_verify_result_violated_invariants_match(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        result = verifier.verify(signed.token)
        assert "overdraft_limit" in result.violated_invariants
        assert "kyc_required" in result.violated_invariants

    def test_verify_tampered_payload_returns_valid_false(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        parts = signed.token.split(".")
        tampered = f"{parts[0]}.TAMPERED_PAYLOAD_HERE.{parts[2]}"
        result = verifier.verify(tampered)
        assert result.valid is False

    def test_verify_tampered_signature_returns_valid_false(self):
        signer = DecisionSigner(signing_key=_KEY_64)
        verifier = DecisionVerifier(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        parts = signed.token.split(".")
        tampered = f"{parts[0]}.{parts[1]}.TAMPERED_SIGNATURE"
        result = verifier.verify(tampered)
        assert result.valid is False

    def test_verify_truncated_token_returns_valid_false(self):
        verifier = DecisionVerifier(signing_key=_KEY_64)
        result = verifier.verify("only.two")
        assert result.valid is False

    def test_verify_wrong_key_returns_valid_false(self):
        key_a = "a" * 32
        key_b = "b" * 32
        signer = DecisionSigner(signing_key=key_a)
        verifier = DecisionVerifier(signing_key=key_b)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        result = verifier.verify(signed.token)
        assert result.valid is False

    def test_verify_never_raises(self):
        verifier = DecisionVerifier(signing_key=_KEY_64)
        result = verifier.verify("garbage!!!not.a.valid.token.at.all")
        assert result.valid is False
        assert result.error is not None


# ── TestMerkleAnchor ──────────────────────────────────────────────────────────


class TestMerkleAnchor:
    def test_empty_anchor_root_is_none(self):
        anchor = MerkleAnchor()
        assert anchor.root() is None

    def test_single_leaf_root_is_not_none(self):
        anchor = MerkleAnchor()
        anchor.add("decision-001")
        assert anchor.root() is not None

    def test_two_leaves_root_differs_from_leaves(self):
        anchor = MerkleAnchor()
        anchor.add("d1")
        anchor.add("d2")
        root = anchor.root()
        assert root is not None
        # Root should differ from individual leaf hashes
        proof1 = anchor.prove("d1")
        proof2 = anchor.prove("d2")
        assert proof1 is not None
        assert proof2 is not None
        assert root != proof1.leaf_hash
        assert root != proof2.leaf_hash

    def test_prove_returns_none_for_unknown_id(self):
        anchor = MerkleAnchor()
        anchor.add("d1")
        assert anchor.prove("nonexistent") is None

    def test_proof_verifies_true_for_single_leaf(self):
        anchor = MerkleAnchor()
        anchor.add("only-decision")
        proof = anchor.prove("only-decision")
        assert proof is not None
        assert proof.verify() is True

    @pytest.mark.parametrize("idx", [0, 1])
    def test_proof_verifies_true_for_two_leaves(self, idx):
        ids = ["decision-a", "decision-b"]
        anchor = MerkleAnchor()
        for d in ids:
            anchor.add(d)
        proof = anchor.prove(ids[idx])
        assert proof is not None
        assert proof.verify() is True

    @pytest.mark.parametrize("idx", [0, 1, 2, 3])
    def test_proof_verifies_true_for_four_leaves(self, idx):
        ids = [f"decision-{i}" for i in range(4)]
        anchor = MerkleAnchor()
        for d in ids:
            anchor.add(d)
        proof = anchor.prove(ids[idx])
        assert proof is not None
        assert proof.verify() is True

    def test_proof_verifies_true_for_odd_number_of_leaves(self):
        ids = ["d0", "d1", "d2"]  # 3 leaves — odd
        anchor = MerkleAnchor()
        for d in ids:
            anchor.add(d)
        for d in ids:
            proof = anchor.prove(d)
            assert proof is not None
            assert proof.verify() is True, f"Proof for {d} failed to verify"

    def test_proof_fails_after_tampering_leaf_hash(self):
        anchor = MerkleAnchor()
        anchor.add("d1")
        anchor.add("d2")
        proof = anchor.prove("d1")
        assert proof is not None
        proof.leaf_hash = "tampered" * 4  # mutate
        assert proof.verify() is False

    def test_proof_fails_after_tampering_root_hash(self):
        anchor = MerkleAnchor()
        anchor.add("d1")
        anchor.add("d2")
        proof = anchor.prove("d1")
        assert proof is not None
        proof.root_hash = "tampered" * 4  # mutate
        assert proof.verify() is False


# ── TestCLIVerifyProof ────────────────────────────────────────────────────────


class TestCLIVerifyProof:
    """Tests for CLI main() using monkeypatched sys.argv."""

    def _run_cli(self, argv: list[str], monkeypatch) -> int:
        from pramanix.cli import main

        monkeypatch.setattr(sys, "argv", ["pramanix", *argv])
        return main()

    def test_cli_missing_key_exits_1(self, monkeypatch):
        monkeypatch.delenv("PRAMANIX_SIGNING_KEY", raising=False)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        # Key not set and not passed → exit 1
        rc = self._run_cli(["verify-proof", signed.token], monkeypatch)
        assert rc == 1

    def test_cli_empty_token_exits_2_or_1(self, monkeypatch):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        # --stdin with empty stdin
        monkeypatch.setattr(sys, "stdin", __import__("io").StringIO(""))
        rc = self._run_cli(["verify-proof", "--stdin"], monkeypatch)
        assert rc in (1, 2)

    def test_cli_valid_token_exits_0(self, monkeypatch, capsys):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_allow_decision()
        signed = signer.sign(d)
        assert signed is not None
        rc = self._run_cli(["verify-proof", signed.token], monkeypatch)
        assert rc == 0
        out = capsys.readouterr().out
        assert "VALID" in out

    def test_cli_invalid_token_exits_1(self, monkeypatch, capsys):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        rc = self._run_cli(["verify-proof", "tampered.bad.token"], monkeypatch)
        assert rc == 1
        out = capsys.readouterr().out
        assert "INVALID" in out

    def test_cli_json_flag_produces_parseable_output(self, monkeypatch, capsys):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_allow_decision()
        signed = signer.sign(d)
        assert signed is not None
        self._run_cli(["verify-proof", signed.token, "--json"], monkeypatch)
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert isinstance(parsed, dict)

    def test_cli_json_valid_has_correct_fields(self, monkeypatch, capsys):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        self._run_cli(["verify-proof", signed.token, "--json"], monkeypatch)
        out = capsys.readouterr().out
        parsed = json.loads(out)
        for field in ("valid", "decision_id", "allowed", "status", "explanation"):
            assert field in parsed, f"Missing field: {field}"

    def test_cli_json_invalid_has_error_field(self, monkeypatch, capsys):
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        self._run_cli(["verify-proof", "bad.tampered.token", "--json"], monkeypatch)
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert "error" in parsed

    def test_full_roundtrip(self, monkeypatch, capsys):
        """Sign a real Decision → extract token → CLI verifies → exit 0."""
        key = "roundtrip-test-key-" + "a" * 45
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", key)
        signer = DecisionSigner(signing_key=key)
        d = Decision.unsafe(
            violated_invariants=("test_rule",),
            explanation="Test block for CLI roundtrip",
        )
        signed = signer.sign(d)
        assert signed is not None
        rc = self._run_cli(["verify-proof", signed.token], monkeypatch)
        assert rc == 0
        out = capsys.readouterr().out
        assert "VALID" in out
        assert d.decision_id in out

    def test_cli_no_subcommand_exits_2(self, monkeypatch):
        """No subcommand → print help → exit 2."""
        rc = self._run_cli([], monkeypatch)
        assert rc == 2

    def test_cli_no_token_no_stdin_exits_2(self, monkeypatch, capsys):
        """verify-proof with no token argument and no --stdin → exit 2."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        rc = self._run_cli(["verify-proof"], monkeypatch)
        assert rc == 2
        err = capsys.readouterr().err
        assert "Provide token" in err

    def test_cli_short_key_exits_1(self, monkeypatch, capsys):
        """Passing --key with a short value hits ValueError path → exit 1."""
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_allow_decision()
        signed = signer.sign(d)
        assert signed is not None
        rc = self._run_cli(
            ["verify-proof", signed.token, "--key", "short"],
            monkeypatch,
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "ERROR" in err

    def test_cli_valid_block_shows_violated_invariants(self, monkeypatch, capsys):
        """BLOCK decision with violated invariants displays them in output."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        rc = self._run_cli(["verify-proof", signed.token], monkeypatch)
        assert rc == 0
        out = capsys.readouterr().out
        assert "overdraft_limit" in out

    def test_cli_valid_with_explanation_shows_explanation(self, monkeypatch, capsys):
        """BLOCK decision with explanation displays it in output."""
        monkeypatch.setenv("PRAMANIX_SIGNING_KEY", _KEY_64)
        signer = DecisionSigner(signing_key=_KEY_64)
        d = _make_block_decision()
        signed = signer.sign(d)
        assert signed is not None
        rc = self._run_cli(["verify-proof", signed.token], monkeypatch)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Transfer blocked" in out
