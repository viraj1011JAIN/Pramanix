#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""pramanix CLI — verify cryptographic decision proofs.

Usage:
    pramanix verify-proof <token> [--key KEY] [--json]
    pramanix verify-proof --stdin [--key KEY] [--json]

Examples:
    pramanix verify-proof eyJhbGciOiJIUzI1NiJ9...
    echo "eyJ..." | pramanix verify-proof --stdin
    PRAMANIX_SIGNING_KEY=... pramanix verify-proof eyJ...
    pramanix verify-proof eyJ... --json | jq .decision_id

Exit codes:
    0 — proof is valid
    1 — proof is invalid or verification error
    2 — usage error (missing key, bad arguments)
"""
from __future__ import annotations

import argparse
import json as _json
import os
import sys
from datetime import UTC, datetime
from typing import Any


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pramanix",
        description="Pramanix cryptographic proof verification",
    )
    sub = parser.add_subparsers(dest="command")

    vp = sub.add_parser("verify-proof", help="Verify a JWS decision proof")
    vp.add_argument("token", nargs="?", help="JWS compact token")
    vp.add_argument("--stdin", action="store_true", help="Read token from stdin")
    vp.add_argument("--key", help="Signing key (default: PRAMANIX_SIGNING_KEY env var)")
    vp.add_argument("--json", dest="as_json", action="store_true", help="Output as JSON")

    audit = sub.add_parser("audit", help="Audit log verification tools")
    audit_sub = audit.add_subparsers(dest="audit_command")

    av = audit_sub.add_parser(
        "verify",
        help="Verify a JSONL audit log signed with PramanixSigner (Ed25519). "
             "For HMAC JWS bearer tokens use 'verify-proof' instead.",
    )
    av.add_argument("log_file", help="Path to JSONL audit log file")
    av.add_argument(
        "--public-key",
        required=True,
        help="Path to Ed25519 public key PEM file (from PramanixSigner.public_key_pem())",
    )
    av.add_argument("--json", dest="as_json", action="store_true", help="Output results as JSON")
    av.add_argument("--fail-fast", action="store_true", help="Stop at first invalid record")

    args = parser.parse_args()

    if args.command == "verify-proof":
        return _cmd_verify_proof(args)

    if args.command == "audit":
        return _cmd_audit(args)

    parser.print_help()
    return 2


def _cmd_verify_proof(args: argparse.Namespace) -> int:
    if args.stdin:
        token = sys.stdin.read().strip()
        if not token:
            print("Provide token via argument or stdin.", file=sys.stderr)
            return 2
    elif args.token:
        token = args.token.strip()
    else:
        print("Provide token via positional argument or --stdin.", file=sys.stderr)
        return 2

    if not token:
        print("Provide token: empty input.", file=sys.stderr)
        return 2

    key = args.key or os.environ.get("PRAMANIX_SIGNING_KEY", "")
    if not key:
        return 1

    try:
        from pramanix.audit.verifier import DecisionVerifier

        verifier = DecisionVerifier(signing_key=key)
        result = verifier.verify(token)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    if args.as_json:
        output: dict[str, object] = {
            "valid": result.valid,
            "decision_id": result.decision_id,
            "allowed": result.allowed,
            "status": result.status,
            "violated_invariants": result.violated_invariants,
            "explanation": result.explanation,
            "policy": result.policy,
            "issued_at": result.issued_at,
        }
        if result.error:
            output["error"] = result.error
        print(_json.dumps(output))
        return 0 if result.valid else 1

    if result.valid:
        try:
            ts = datetime.fromtimestamp(result.issued_at, tz=UTC).isoformat()
        except Exception:  # pragma: no cover
            ts = str(result.issued_at)  # pragma: no cover
        status_line = f"status={result.status}"
        if result.violated_invariants:
            status_line += f"  violated={result.violated_invariants}"
        if result.explanation:
            status_line += f"  explanation={result.explanation!r}"
        print(f"VALID  decision_id={result.decision_id}  issued_at={ts}  {status_line}")
        return 0
    else:
        print(f"INVALID  decision_id={result.decision_id}  error={result.error or 'signature mismatch'}")
        return 1


def _cmd_audit(args: argparse.Namespace) -> int:
    if not hasattr(args, "audit_command") or args.audit_command == "verify":
        return _cmd_audit_verify(args)
    print("Usage: pramanix audit verify <log_file> --public-key <key.pem>")
    return 2


def _cmd_audit_verify(args: argparse.Namespace) -> int:
    """Verify a JSONL audit log file produced by Guard with PramanixSigner.

    This command verifies audit logs signed with Ed25519 (``PramanixSigner``),
    which is configured on ``GuardConfig(signer=PramanixSigner(...))``.  It is
    *not* for verifying HMAC-SHA256 JWS bearer tokens — use ``verify-proof``
    for those.

    Two-stage verification per record:
    1. Recompute decision_hash from stored fields (detects field tampering).
    2. Verify Ed25519 signature over decision_hash (authenticates the record).

    Records without a signature field are flagged as MISSING_SIG — this is
    expected when the Guard was not configured with a PramanixSigner.

    Exit codes:
        0 — all records valid (or all unsigned, if no signer was configured)
        1 — any record tampered, signature invalid, or malformed
        2 — usage error (file not found, key file missing/invalid)
    """
    import json

    pub_key_path = getattr(args, "public_key", None)
    if not pub_key_path:
        print("ERROR: --public-key is required", file=sys.stderr)
        return 2

    try:
        with open(pub_key_path, "rb") as f:
            public_key_pem = f.read()
    except FileNotFoundError:
        print(f"ERROR: Public key file not found: {pub_key_path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"ERROR: Cannot read public key: {e}", file=sys.stderr)
        return 2

    try:
        from pramanix.crypto import PramanixVerifier
        verifier = PramanixVerifier(public_key_pem=public_key_pem)
    except ImportError:  # pragma: no cover
        print("ERROR: cryptography package required. pip install cryptography", file=sys.stderr)  # pragma: no cover
        return 2  # pragma: no cover
    except Exception as e:
        print(f"ERROR: Invalid public key: {e}", file=sys.stderr)
        return 2

    log_path = args.log_file
    results: list[dict[str, Any]] = []
    total = valid = tampered = invalid_sig = missing_sig = errors = 0
    fail_fast = getattr(args, "fail_fast", False)

    try:
        with open(log_path, encoding="utf-8") as log_file:
            for line_num, line in enumerate(log_file, 1):
                line = line.strip()
                if not line:
                    continue

                total += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    errors += 1
                    result: dict[str, Any] = {
                        "line": line_num,
                        "status": "ERROR",
                        "decision_id": "UNKNOWN",
                        "reason": "Invalid JSON on line",
                    }
                    results.append(result)
                    if not getattr(args, "as_json", False):
                        print(f"[ERROR] line={line_num} — Invalid JSON")
                    if fail_fast:
                        break
                    continue

                decision_id = record.get("decision_id", "UNKNOWN")
                stored_hash = record.get("decision_hash", "")
                signature = record.get("signature", "")

                try:
                    recomputed_hash = _recompute_hash(record)
                except Exception as e:
                    errors += 1
                    result = {
                        "line": line_num,
                        "status": "ERROR",
                        "decision_id": decision_id,
                        "reason": f"Hash recomputation failed: {e}",
                    }
                    results.append(result)
                    if not getattr(args, "as_json", False):
                        print(f"[ERROR] decision_id={decision_id} — {e}")
                    if fail_fast:
                        break
                    continue

                if recomputed_hash != stored_hash:
                    tampered += 1
                    result = {
                        "line": line_num,
                        "status": "TAMPERED",
                        "decision_id": decision_id,
                        "reason": "decision_hash mismatch — fields were modified",
                        "stored_hash": stored_hash,
                        "computed_hash": recomputed_hash,
                    }
                    results.append(result)
                    if not getattr(args, "as_json", False):
                        print(
                            f"[TAMPERED]    decision_id={decision_id} "
                            f"| stored={stored_hash[:16]}... "
                            f"computed={recomputed_hash[:16]}..."
                        )
                    if fail_fast:
                        break
                    continue

                if not signature:
                    missing_sig += 1
                    result = {
                        "line": line_num,
                        "status": "MISSING_SIG",
                        "decision_id": decision_id,
                        "reason": "No signature field in record",
                    }
                    results.append(result)
                    if not getattr(args, "as_json", False):
                        print(f"[MISSING_SIG] decision_id={decision_id}")
                    if fail_fast:
                        break
                    continue

                sig_valid = verifier.verify(
                    decision_hash=recomputed_hash,
                    signature=signature,
                )

                if not sig_valid:
                    invalid_sig += 1
                    result = {
                        "line": line_num,
                        "status": "INVALID_SIG",
                        "decision_id": decision_id,
                        "reason": "Ed25519 signature invalid — wrong key or tampered signature",
                    }
                    results.append(result)
                    if not getattr(args, "as_json", False):
                        print(f"[INVALID_SIG] decision_id={decision_id}")
                    if fail_fast:
                        break
                    continue

                valid += 1
                if not getattr(args, "as_json", False):
                    verdict = "ALLOW" if record.get("allowed") else "BLOCK"
                    print(f"[VALID]       decision_id={decision_id} ({verdict})")

    except FileNotFoundError:
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        return 2

    any_failure = (tampered + invalid_sig + missing_sig + errors) > 0

    if getattr(args, "as_json", False):
        summary = {
            "total": total,
            "valid": valid,
            "tampered": tampered,
            "invalid_sig": invalid_sig,
            "missing_sig": missing_sig,
            "errors": errors,
            "all_valid": not any_failure,
            "records": results,
        }
        print(json.dumps(summary, indent=2))
    else:
        print(f"\n{'─' * 60}")
        print(f"Audit complete: {total} records")
        print(f"  ✅ Valid:        {valid}")
        if tampered:
            print(f"  ❌ Tampered:     {tampered}")
        if invalid_sig:
            print(f"  ❌ Invalid sig:  {invalid_sig}")
        if missing_sig:
            print(f"  ⚠️  Missing sig:  {missing_sig}")
        if errors:
            print(f"  ⚠️  Errors:       {errors}")
        print()
        if not any_failure:
            print("✅ AUDIT PASSED — All records verified")
        else:
            print("❌ AUDIT FAILED — See details above")

    return 1 if any_failure else 0


def _recompute_hash(record: dict[str, Any]) -> str:
    """Recompute decision_hash from a JSONL audit record.

    Delegates to :func:`pramanix.decision._build_decision_canonical` and
    :func:`pramanix.decision._canonical_bytes` — the same functions used by
    :meth:`Decision._compute_hash` — guaranteeing byte-for-byte determinism
    with a single canonical-field definition shared by library and CLI.
    """
    import hashlib

    from pramanix.decision import _build_decision_canonical, _canonical_bytes

    canonical = _build_decision_canonical(
        allowed=bool(record.get("allowed", False)),
        explanation=str(record.get("explanation", "")),
        intent_dump=record.get("intent_dump") or {},
        policy=str(record.get("policy", "")),
        state_dump=record.get("state_dump") or {},
        status=str(record.get("status", "")),
        violated_invariants=record.get("violated_invariants") or [],
    )
    return hashlib.sha256(_canonical_bytes(canonical)).hexdigest()


if __name__ == "__main__":
    sys.exit(main())
