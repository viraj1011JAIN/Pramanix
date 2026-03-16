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

    args = parser.parse_args()

    if args.command == "verify-proof":
        return _cmd_verify_proof(args)

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
        except Exception:
            ts = str(result.issued_at)
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


if __name__ == "__main__":
    sys.exit(main())
