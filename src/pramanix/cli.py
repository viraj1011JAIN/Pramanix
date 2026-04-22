#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""pramanix CLI — verify cryptographic decision proofs and simulate policy checks.

Usage:
    pramanix verify-proof <token> [--key KEY] [--json]
    pramanix verify-proof --stdin [--key KEY] [--json]
    pramanix simulate --policy POLICY_FILE --intent INTENT_JSON [--state STATE_JSON] [--json]
    pramanix simulate --policy POLICY_FILE --intent-file FILE [--json]

Examples:
    pramanix verify-proof eyJhbGciOiJIUzI1NiJ9...
    echo "eyJ..." | pramanix verify-proof --stdin
    PRAMANIX_SIGNING_KEY=... pramanix verify-proof eyJ...
    pramanix verify-proof eyJ... --json | jq .decision_id
    pramanix simulate --policy banking_policy.py --intent '{"amount": 500, "currency": "USD"}'
    pramanix simulate --policy banking_policy.py --intent-file intent.json --json

Exit codes:
    0 — proof valid / policy allows the request
    1 — proof invalid / policy blocks the request / verification error
    2 — usage error (missing key, bad arguments)
"""
from __future__ import annotations

import argparse
import json as _json
import os
import sys
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

    sim = sub.add_parser(
        "simulate",
        help="Simulate a policy decision against an intent dict (no LLM, no side-effects).",
    )
    sim.add_argument(
        "--policy",
        required=True,
        metavar="POLICY_FILE",
        help=(
            "Path to a Python (.py) file that defines a Policy object.  "
            "Use --policy-var to specify the variable name (default: 'policy')."
        ),
    )
    _intent_grp = sim.add_mutually_exclusive_group(required=True)
    _intent_grp.add_argument(
        "--intent",
        metavar="JSON",
        help="Intent dict as a JSON string, e.g. '{\"amount\": 500}'.",
    )
    _intent_grp.add_argument(
        "--intent-file",
        metavar="FILE",
        help="Path to a JSON file containing the intent dict.",
    )
    sim.add_argument(
        "--state",
        metavar="JSON",
        help="Optional state dict as a JSON string passed to guard.verify().",
    )
    sim.add_argument(
        "--policy-var",
        default="policy",
        metavar="VAR",
        help="Name of the Policy variable in the Python file (default: 'policy').",
    )
    sim.add_argument("--json", dest="as_json", action="store_true", help="Output decision as JSON")

    # B-4: policy migrate subcommand
    pm = sub.add_parser(
        "policy",
        help="Policy management tools (semver migration, schema validation).",
    )
    pm_sub = pm.add_subparsers(dest="policy_command")
    mig = pm_sub.add_parser(
        "migrate",
        help="Apply a PolicyMigration spec to a state JSON file.",
    )
    mig.add_argument("--state", required=True, metavar="JSON_FILE",
                     help="Path to the state JSON file to migrate.")
    mig.add_argument("--from-version", required=True, metavar="X.Y.Z",
                     help="Expected current semver of the state (e.g. 1.0.0).")
    mig.add_argument("--to-version", required=True, metavar="X.Y.Z",
                     help="Target semver after migration (e.g. 2.0.0).")
    mig.add_argument("--rename", action="append", default=[], metavar="OLD=NEW",
                     help="Rename a field: --rename old_name=new_name (repeatable).")
    mig.add_argument("--remove", action="append", default=[], metavar="FIELD",
                     help="Remove a field: --remove field_name (repeatable).")
    mig.add_argument("--output", metavar="JSON_FILE",
                     help="Write migrated state to this file (default: stdout).")
    mig.add_argument("--json", dest="as_json", action="store_true",
                     help="Output migrated state as JSON (default when --output not set).")

    args = parser.parse_args()

    if args.command == "verify-proof":
        return _cmd_verify_proof(args)

    if args.command == "audit":
        return _cmd_audit(args)

    if args.command == "simulate":
        return _cmd_simulate(args)

    if args.command == "policy":
        return _cmd_policy(args)

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
            "policy_hash": result.policy_hash,
            # issued_at is always 0 for tokens produced by SDK >= v0.5.x
            # (iat was removed from the signed payload for deterministic replay).
            "issued_at": result.issued_at,
        }
        if result.error:
            output["error"] = result.error
        print(_json.dumps(output))
        return 0 if result.valid else 1

    if result.valid:
        status_line = f"status={result.status}"
        if result.violated_invariants:
            status_line += f"  violated={result.violated_invariants}"
        if result.explanation:
            status_line += f"  explanation={result.explanation!r}"
        if result.policy_hash:
            status_line += f"  policy_hash={result.policy_hash[:12]}..."
        print(f"VALID  decision_id={result.decision_id}  {status_line}")
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


def _cmd_simulate(args: argparse.Namespace) -> int:
    """Simulate a ``Guard.verify()`` call with a literal intent dict.

    Loads a Policy from a Python source file, constructs a minimal Guard
    (no translator, no circuit breaker, no signing), then calls
    ``guard.verify(intent)`` with the provided intent dict.

    This command is **side-effect free**: it never calls any LLM, never
    writes to any audit log, and never modifies any external state.  It is
    designed for local policy testing and CI pipelines.

    Exit codes:
        0 — policy ALLOWS the request (Decision.allowed == True)
        1 — policy BLOCKS or errors
        2 — usage error (bad arguments, file not found, import error)
    """
    import importlib.util
    import json

    # ── Load intent ───────────────────────────────────────────────────────────
    if args.intent:
        try:
            intent: dict[str, Any] = json.loads(args.intent)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --intent is not valid JSON: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            with open(args.intent_file, encoding="utf-8") as f:
                intent = json.load(f)
        except FileNotFoundError:
            print(f"ERROR: Intent file not found: {args.intent_file}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(f"ERROR: --intent-file is not valid JSON: {exc}", file=sys.stderr)
            return 2

    if not isinstance(intent, dict):
        print("ERROR: intent must be a JSON object (dict), not a list or scalar.", file=sys.stderr)
        return 2

    # ── Load state (optional) ─────────────────────────────────────────────────
    state: dict[str, Any] = {}
    if getattr(args, "state", None):
        try:
            state = json.loads(args.state)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --state is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(state, dict):
            print("ERROR: --state must be a JSON object.", file=sys.stderr)
            return 2

    # ── Load policy from Python file ──────────────────────────────────────────
    policy_path = args.policy
    policy_var = getattr(args, "policy_var", "policy")

    try:
        spec = importlib.util.spec_from_file_location("_pramanix_sim_policy", policy_path)
        if spec is None or spec.loader is None:
            print(f"ERROR: Cannot load module spec from {policy_path}", file=sys.stderr)
            return 2
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except FileNotFoundError:
        print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: Failed to import policy file: {exc}", file=sys.stderr)
        return 2

    policy = getattr(module, policy_var, None)
    if policy is None:
        print(
            f"ERROR: Variable '{policy_var}' not found in {policy_path}. "
            f"Use --policy-var to specify the correct name.",
            file=sys.stderr,
        )
        return 2

    # ── Build guard and verify ────────────────────────────────────────────────
    try:
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        config = GuardConfig(execution_mode="sync")
        guard_instance = Guard(policy=policy, config=config)
        decision = guard_instance.verify(intent=intent, state=state)
    except Exception as exc:
        print(f"ERROR: Guard verification failed: {exc}", file=sys.stderr)
        return 2

    # ── Output ────────────────────────────────────────────────────────────────
    if getattr(args, "as_json", False):
        output: dict[str, Any] = {
            "allowed": decision.allowed,
            "status": decision.status,
            "explanation": decision.explanation,
            "violated_invariants": decision.violated_invariants,
            "decision_id": decision.decision_id,
        }
        print(_json.dumps(output))
    else:
        verdict = "ALLOW" if decision.allowed else "BLOCK"
        print(f"{verdict}  status={decision.status}")
        if decision.explanation:
            print(f"  explanation: {decision.explanation}")
        if decision.violated_invariants:
            print(f"  violated:    {decision.violated_invariants}")
        print(f"  decision_id: {decision.decision_id}")

    return 0 if decision.allowed else 1


def _cmd_policy(args: argparse.Namespace) -> int:
    """Handle the 'policy' subcommand group."""
    if getattr(args, "policy_command", None) == "migrate":
        return _cmd_policy_migrate(args)
    # No subcommand given — print help.
    print("Usage: pramanix policy <migrate>", file=sys.stderr)
    return 2


def _cmd_policy_migrate(args: argparse.Namespace) -> int:
    """Apply a PolicyMigration to a state JSON file (B-4)."""
    import json as _json_mod
    import pathlib

    from pramanix.migration import PolicyMigration

    # Parse versions
    def _parse_semver(s: str, flag: str) -> tuple[int, int, int]:
        try:
            parts = tuple(int(p) for p in s.strip().split("."))
            if len(parts) != 3:
                raise ValueError
            return parts  # type: ignore[return-value]
        except ValueError:
            print(
                f"ERROR: {flag} must be a semver string like '1.2.0', got {s!r}.",
                file=sys.stderr,
            )
            raise SystemExit(2)

    from_ver = _parse_semver(args.from_version, "--from-version")
    to_ver = _parse_semver(args.to_version, "--to-version")

    # Parse field renames
    renames: dict[str, str] = {}
    for rename_spec in (args.rename or []):
        if "=" not in rename_spec:
            print(
                f"ERROR: --rename must be OLD=NEW, got {rename_spec!r}.",
                file=sys.stderr,
            )
            return 2
        old, new = rename_spec.split("=", 1)
        renames[old.strip()] = new.strip()

    removed = [f.strip() for f in (args.remove or [])]

    # Load state
    try:
        state_path = pathlib.Path(args.state)
        state = _json_mod.loads(state_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        print(f"ERROR: State file not found: {args.state}", file=sys.stderr)
        return 2
    except _json_mod.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in state file: {exc}", file=sys.stderr)
        return 2

    migration = PolicyMigration(
        from_version=from_ver,
        to_version=to_ver,
        field_renames=renames,
        removed_fields=removed,
    )

    if not migration.can_migrate(state):
        print(
            f"ERROR: state_version {state.get('state_version')!r} does not match "
            f"--from-version {args.from_version!r}.",
            file=sys.stderr,
        )
        return 1

    migrated = migration.migrate(state)
    output_json = _json_mod.dumps(migrated, indent=2, default=str)

    if args.output:
        pathlib.Path(args.output).write_text(output_json + "\n", encoding="utf-8")
        print(f"Migrated state written to {args.output}")
    else:
        print(output_json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
