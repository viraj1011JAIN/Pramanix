#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""pramanix CLI — verify cryptographic decision proofs, lint readiness,
and simulate policy checks.

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
import contextlib
import json as _json
import os
import pathlib
import sys
from decimal import Decimal
from typing import Any, Literal, NotRequired, TypedDict, get_args, get_origin


def main() -> int:
    """Entry point for the pramanix CLI; dispatches subcommands and returns an exit code."""
    parser = argparse.ArgumentParser(
        prog="pramanix",
        description="Pramanix cryptographic proof verification and setup checks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Plain-English first steps:\n"
            "  pramanix check            Run the readiness check\n"
            "  pramanix lint             Alias of check (easy discovery)\n"
            "  pramanix explain          Human-readable policy verdicts\n"
            "  pramanix init --template finance  Bootstrap a policy blueprint\n"
            "  pramanix verify-proof     Verify a signed decision proof\n"
            "  pramanix compile-policy   Compile a policy schema\n"
            "\n"
            "If you are new to the project, start with `pramanix check` and fix\n"
            "the first ERROR it reports before moving on."
        ),
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
        aliases=["explain"],
        help="Simulate a policy decision against an intent dict (no LLM, no side-effects).",
    )
    sim.add_argument(
        "--policy",
        required=True,
        metavar="POLICY_FILE",
        help=(
            "Path to a policy file. Supported formats: "
            ".py (Python — use --policy-var to name the variable, default: 'policy'), "
            ".yaml/.yml (YAML DSL), .toml (TOML DSL). "
            "--policy-var is ignored for YAML/TOML files."
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
    _state_grp = sim.add_mutually_exclusive_group(required=False)
    _state_grp.add_argument(
        "--state",
        metavar="JSON",
        help="Optional state dict as a JSON string passed to guard.verify().",
    )
    _state_grp.add_argument(
        "--state-file",
        metavar="FILE",
        help="Optional path to a JSON file containing the state dict.",
    )
    sim.add_argument(
        "--policy-var",
        default="policy",
        metavar="VAR",
        help=(
            "Name of the Policy variable in a Python policy file (default: 'policy'). "
            "Ignored for YAML/TOML."
        ),
    )
    sim.add_argument(
        "--suggest-fix",
        action="store_true",
        help=("Suggest safe, review-required policy edits from the failed decision."),
    )
    sim.add_argument("--json", dest="as_json", action="store_true", help="Output decision as JSON")

    init_cmd = sub.add_parser(
        "init",
        help="Scaffold a production-ready policy blueprint from a template.",
    )
    init_cmd.add_argument(
        "--template",
        required=True,
        choices=["finance", "pii", "infra"],
        help="Blueprint template to write.",
    )
    init_cmd.add_argument(
        "--output",
        default="policy_template.yaml",
        metavar="FILE",
        help="Output file path (default: policy_template.yaml).",
    )
    init_cmd.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists.",
    )

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
    mig.add_argument(
        "--state",
        required=True,
        metavar="JSON_FILE",
        help="Path to the state JSON file to migrate.",
    )
    mig.add_argument(
        "--from-version",
        required=True,
        metavar="X.Y.Z",
        help="Expected current semver of the state (e.g. 1.0.0).",
    )
    mig.add_argument(
        "--to-version",
        required=True,
        metavar="X.Y.Z",
        help="Target semver after migration (e.g. 2.0.0).",
    )
    mig.add_argument(
        "--rename",
        action="append",
        default=[],
        metavar="OLD=NEW",
        help="Rename a field: --rename old_name=new_name (repeatable).",
    )
    mig.add_argument(
        "--remove",
        action="append",
        default=[],
        metavar="FIELD",
        help="Remove a field: --remove field_name (repeatable).",
    )
    mig.add_argument(
        "--output", metavar="JSON_FILE", help="Write migrated state to this file (default: stdout)."
    )
    mig.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output migrated state as JSON (default when --output not set).",
    )

    # G-3: schema export subcommand
    schema_cmd = sub.add_parser(
        "schema",
        help="Policy JSON schema tools.",
    )
    schema_sub = schema_cmd.add_subparsers(dest="schema_command")
    schema_export = schema_sub.add_parser(
        "export",
        help="Export a Policy's JSON schema to stdout or a file.",
    )
    schema_export.add_argument(
        "--policy",
        required=True,
        metavar="FILE:CLASS",
        help=(
            "Python file and class name, e.g. my_policy.py:TradePolicy.  "
            "The class must be a subclass of pramanix.policy.Policy."
        ),
    )
    schema_export.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON schema to this file (default: stdout).",
    )
    schema_export.add_argument(
        "--indent",
        type=int,
        default=2,
        metavar="N",
        help="JSON indentation level (default: 2).",
    )

    # D-4: calibrate-injection subcommand
    calib_cmd = sub.add_parser(
        "calibrate-injection",
        help="Fit a calibrated injection scorer from a labelled dataset.",
    )
    calib_cmd.add_argument(
        "--dataset",
        required=True,
        metavar="JSONL_FILE",
        help=("Path to a JSONL file.  Each line: " '{"text": "...", "is_injection": true|false}'),
    )
    calib_cmd.add_argument(
        "--output",
        required=True,
        metavar="SCORER_FILE",
        help="Write the fitted scorer (.npz) to this path.",
    )
    calib_cmd.add_argument(
        "--min-examples",
        type=int,
        default=200,
        metavar="N",
        help="Minimum labelled examples required (default: 200).",
    )
    calib_cmd.add_argument(
        "--hmac-key-hex",
        metavar="HEX",
        default=None,
        help=(
            "64-character hex string (= 32 bytes) used to sign the saved scorer "
            "with HMAC-SHA-256.  Alternatively, set the PRAMANIX_SCORER_HMAC_KEY_HEX "
            "environment variable.  When neither is supplied, Pramanix auto-generates "
            "a random key and writes it to <output>.key — keep that file secret."
        ),
    )

    # doctor subcommand
    doctor_cmd = sub.add_parser(
        "doctor",
        aliases=["check", "lint"],
        help="Run the readiness check for environment, dependencies, and config.",
    )
    doctor_cmd.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output results as JSON instead of human-readable text.",
    )
    doctor_cmd.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any WARNING is found (not just errors).",
    )
    doctor_cmd.add_argument(
        "--production",
        action="store_true",
        help=("Run deployment-gate profile (hard-fail on critical security " "misconfigurations)."),
    )

    # compile-policy subcommand (Phase 2 — Natural Policy Compiler)
    compile_cmd = sub.add_parser(
        "compile-policy",
        help=(
            "Compile a natural-language policy YAML/JSON to a Z3 ConstraintExpr "
            "(Phase 2 — Natural Policy Engine)."
        ),
    )
    compile_cmd.add_argument(
        "policy_file",
        metavar="POLICY_FILE",
        nargs="?",
        default=None,
        help=(
            "Path to a YAML or JSON file conforming to the NaturalPolicySchema.  "
            "See 'pramanix compile-policy --example' for a minimal template."
        ),
    )
    compile_cmd.add_argument(
        "--verify",
        choices=["strict", "warn", "skip"],
        default="warn",
        help="Meta-verification mode (default: warn).",
    )
    compile_cmd.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output compilation result as JSON instead of human-readable text.",
    )
    compile_cmd.add_argument(
        "--example",
        action="store_true",
        help="Print a minimal policy YAML template to stdout and exit.",
    )

    # lint-policy subcommand — static linter for Python and YAML/TOML policy files
    lp = sub.add_parser(
        "lint-policy",
        help=(
            "Statically lint a Policy definition file and report authoring issues "
            "(unlabelled invariants, unused fields, duplicate labels, missing Meta, etc.)."
        ),
    )
    lp.add_argument(
        "policy_file",
        metavar="POLICY_FILE",
        help=(
            "Path to a policy file.  Supported formats:\n"
            "  .py         — Python file; --policy-var names the Policy class (default: first Policy subclass)\n"
            "  .yaml/.yml  — YAML declarative DSL\n"
            "  .toml       — TOML declarative DSL"
        ),
    )
    lp.add_argument(
        "--policy-var",
        metavar="CLASS",
        default=None,
        help=(
            "For Python files: name of the Policy class to lint "
            "(default: first Policy subclass found in the file)."
        ),
    )
    lp.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output results as JSON.",
    )
    lp.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on warnings as well as errors.",
    )

    # report subcommand — render a ComplianceReport JSON to text / JSON / PDF
    rep_cmd = sub.add_parser(
        "report",
        help=(
            "Render a ComplianceReport JSON file (from ComplianceReport.to_json()) "
            "as text, JSON, or PDF."
        ),
    )
    rep_cmd.add_argument(
        "input",
        nargs="?",
        default="-",
        help="Path to a ComplianceReport JSON file, or '-' to read from stdin (default: -).",
    )
    rep_cmd.add_argument(
        "--format",
        dest="output_format",
        choices=["text", "json", "pdf"],
        default="text",
        help="Output format: text (default), json, or pdf (requires fpdf2).",
    )
    rep_cmd.add_argument(
        "--out",
        dest="output_file",
        default=None,
        help="Write output to FILE instead of stdout (required for --format pdf).",
    )

    # coverage subcommand — run test cases through a policy and report coverage
    cov_cmd = sub.add_parser(
        "coverage",
        help="Run a set of test-case intents through a policy and report coverage statistics.",
    )
    cov_cmd.add_argument(
        "--policy",
        required=True,
        metavar="POLICY_FILE",
        help=(
            "Path to a policy file (.py, .yaml/.yml, .toml). "
            "For Python files, --policy-var selects the variable (default: 'policy')."
        ),
    )
    cov_cmd.add_argument(
        "--policy-var",
        default="policy",
        metavar="VAR",
        help=(
            "Name of the Policy variable in a Python policy file (default: 'policy'). "
            "Ignored for YAML/TOML."
        ),
    )
    cov_cmd.add_argument(
        "--test-cases",
        required=True,
        metavar="FILE",
        help=(
            "Path to a JSONL file where each line is a JSON object with an "
            "'intent' key (required) and an optional 'state' key."
        ),
    )
    cov_cmd.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Output the coverage report as JSON.",
    )
    cov_cmd.add_argument(
        "--fail-under",
        metavar="N",
        type=float,
        default=None,
        help="Exit 1 if total_verifications < N.",
    )

    args = parser.parse_args()

    if args.command == "verify-proof":
        return _cmd_verify_proof(args)

    if args.command == "audit":
        return _cmd_audit(args)

    if args.command in ("simulate", "explain"):
        return _cmd_simulate(args)

    if args.command == "init":
        return _cmd_init(args)

    if args.command == "policy":
        return _cmd_policy(args)

    if args.command == "schema":
        return _cmd_schema(args)

    if args.command == "calibrate-injection":
        return _cmd_calibrate_injection(args)

    if args.command in ("doctor", "check", "lint"):
        return _cmd_doctor(args)

    if args.command == "compile-policy":
        return _cmd_compile_policy(args)

    if args.command == "lint-policy":
        return _cmd_lint_policy(args)

    if args.command == "coverage":
        return _cmd_coverage(args)

    if args.command == "report":
        return _cmd_report(args)

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
        print(
            f"INVALID  decision_id={result.decision_id}  error={result.error or 'signature mismatch'}"
        )
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
    except ImportError:
        print("ERROR: cryptography package required. pip install cryptography", file=sys.stderr)
        return 2
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
    import numbers

    def _humanize_rule_name(rule_name: str) -> str:
        return rule_name.replace("_", " ").replace("-", " ").strip()

    def _plain_reason(decision: Any) -> str:
        explanation = str(getattr(decision, "explanation", "") or "").strip()
        if explanation and not explanation.startswith("Invariant(s) violated:"):
            return explanation

        violated = [str(rule) for rule in getattr(decision, "violated_invariants", ()) if str(rule)]
        if violated:
            if len(violated) == 1:
                return f"Safety rule violated: {_humanize_rule_name(violated[0])}."
            rule_list = ", ".join(_humanize_rule_name(rule) for rule in violated)
            return f"Safety rules violated: {rule_list}."

        return "Action blocked by safety policy."

    def _next_step(decision: Any) -> str:
        if getattr(decision, "allowed", False):
            return "No action needed."
        return "Revise the request or update the policy rule."

    def _annotation_contains_decimal(annotation: Any) -> bool:
        if annotation is Decimal:
            return True
        origin = get_origin(annotation)
        if origin is None:
            return False
        return any(_annotation_contains_decimal(arg) for arg in get_args(annotation))

    def _coerce_numeric_to_decimal_by_model(
        payload: dict[str, Any], model_cls: Any
    ) -> dict[str, Any]:
        model_fields = getattr(model_cls, "model_fields", {})
        if not isinstance(model_fields, dict):
            return payload

        coerced = dict(payload)
        for field_name, field_info in model_fields.items():
            if field_name not in coerced:
                continue
            annotation = getattr(field_info, "annotation", None)
            value = coerced[field_name]
            if _annotation_contains_decimal(annotation):
                if isinstance(value, bool):
                    continue
                if isinstance(value, numbers.Real):
                    coerced[field_name] = Decimal(str(value))
        return coerced

    def _numeric(value: Any) -> float | None:
        if isinstance(value, bool):
            return None
        if isinstance(value, numbers.Real):
            return float(value)
        return None

    def _suggest_fixes(
        decision: Any, intent_data: dict[str, Any], state_data: dict[str, Any]
    ) -> list[str]:
        if getattr(decision, "allowed", False):
            return []

        suggestions: list[str] = []
        violated = [str(v).lower() for v in getattr(decision, "violated_invariants", ())]
        numeric_intent = {key: val for key, val in intent_data.items() if _numeric(val) is not None}
        numeric_state = {key: val for key, val in state_data.items() if _numeric(val) is not None}

        for rule in violated:
            if "max" in rule or "limit" in rule or "cap" in rule or "budget" in rule:
                state_key = next(
                    (
                        key
                        for key in numeric_state
                        if any(token in key.lower() for token in ("max", "limit", "cap", "budget"))
                    ),
                    None,
                )
                intent_key = next((key for key in numeric_intent), None)
                if state_key and intent_key:
                    current_limit = _numeric(state_data[state_key])
                    requested = _numeric(intent_data[intent_key])
                    if (
                        current_limit is not None
                        and requested is not None
                        and requested > current_limit
                    ):
                        suggestions.append(
                            "Suggested fix (review required): "
                            f"raise {state_key} from {state_data[state_key]!r} "
                            f"to at least {intent_data[intent_key]!r} "
                            f"to satisfy current request key '{intent_key}'."
                        )
                        continue

            if "min" in rule:
                intent_key = next((key for key in numeric_intent), None)
                if intent_key:
                    suggestions.append(
                        "Suggested fix (review required): "
                        f"lower minimum constraint tied to '{intent_key}' or "
                        "adjust request to meet existing minimum."
                    )

        if not suggestions and violated:
            for rule in violated:
                suggestions.append(
                    "Suggested fix (review required): "
                    f"revisit invariant '{rule}' and decide whether request or policy should change."
                )

        # Keep output concise and deterministic.
        return list(dict.fromkeys(suggestions))[:3]

    # ── Load intent ───────────────────────────────────────────────────────────
    if args.intent:
        try:
            intent: dict[str, Any] = json.loads(args.intent)
        except json.JSONDecodeError as exc:
            print(f"ERROR: --intent is not valid JSON: {exc}", file=sys.stderr)
            print(
                "Hint: On PowerShell, prefer --intent-file for complex JSON.",
                file=sys.stderr,
            )
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
            print(
                "Hint: On PowerShell, prefer --state-file for complex JSON.",
                file=sys.stderr,
            )
            return 2
        if not isinstance(state, dict):
            print("ERROR: --state must be a JSON object.", file=sys.stderr)
            return 2
    elif getattr(args, "state_file", None):
        try:
            with open(args.state_file, encoding="utf-8") as f:
                state = json.load(f)
        except FileNotFoundError:
            print(f"ERROR: State file not found: {args.state_file}", file=sys.stderr)
            return 2
        except json.JSONDecodeError as exc:
            print(f"ERROR: --state-file is not valid JSON: {exc}", file=sys.stderr)
            return 2
        if not isinstance(state, dict):
            print("ERROR: --state-file must be a JSON object.", file=sys.stderr)
            return 2

    # ── Load policy (Python, YAML, or TOML) ───────────────────────────────────
    import pathlib as _pathlib

    policy_path = args.policy
    policy_var = getattr(args, "policy_var", "policy")
    _suffix = _pathlib.Path(policy_path).suffix.lower()

    policy: Any = None
    if _suffix in (".yaml", ".yml", ".toml"):
        try:
            from pramanix.natural_policy.yaml_loader import load_policy_file

            policy = load_policy_file(policy_path)
        except FileNotFoundError:
            print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"ERROR: Failed to compile policy file: {exc}", file=sys.stderr)
            return 2
    else:
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

    meta = getattr(policy, "Meta", None)
    intent_model = getattr(meta, "intent_model", None)
    state_model = getattr(meta, "state_model", None)
    if intent_model is not None:
        intent = _coerce_numeric_to_decimal_by_model(intent, intent_model)
    if state_model is not None:
        state = _coerce_numeric_to_decimal_by_model(state, state_model)

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
        suggested_fixes = _suggest_fixes(decision, intent, state) if args.suggest_fix else []
        output: dict[str, Any] = {
            "allowed": decision.allowed,
            "status": decision.status,
            "explanation": decision.explanation,
            "plain_reason": _plain_reason(decision),
            "next_step": _next_step(decision),
            "suggested_fixes": suggested_fixes,
            "violated_invariants": decision.violated_invariants,
            "decision_id": decision.decision_id,
        }
        print(_json.dumps(output))
    else:
        verdict = "ALLOW" if decision.allowed else "BLOCK"
        print(f"Safety verdict: {verdict}")
        if decision.allowed:
            print("Reason: all safety rules passed.")
            print("Next step: no action needed.")
        else:
            print(f"Reason: {_plain_reason(decision)}")
            if decision.violated_invariants:
                human_rules = ", ".join(
                    _humanize_rule_name(rule) for rule in decision.violated_invariants
                )
                print(f"Safety rule(s): {human_rules}")
            if args.suggest_fix:
                for fix in _suggest_fixes(decision, intent, state):
                    print(fix)
            print(f"Next step: {_next_step(decision)}")
        print(f"Decision ID: {decision.decision_id}")

    return 0 if decision.allowed else 1


_INIT_TEMPLATES: dict[str, str] = {
    "finance": """# Pramanix policy blueprint: finance
# Review every threshold before production use.
policy_name: finance_trade_guard
description: Enforce per-trade and daily risk guardrails.
version: 1.0
fields:
    - name: amount
        type: Real
    - name: daily_limit
        type: Real
    - name: notional_cap
        type: Real
rules:
    - name: within_daily_limit
        expression: amount <= daily_limit
        explain: Trade blocked: amount exceeds daily limit.
    - name: within_notional_cap
        expression: amount <= notional_cap
        explain: Trade blocked: amount exceeds notional cap.
""",
    "pii": """# Pramanix policy blueprint: pii
# Review every field name and exception path before production use.
policy_name: pii_redaction_guard
description: Block payloads that contain sensitive identifiers.
version: 1.0
fields:
    - name: has_ssn
        type: Bool
    - name: has_card_number
        type: Bool
    - name: break_glass_approved
        type: Bool
rules:
    - name: no_ssn_without_approval
        expression: (!has_ssn) or break_glass_approved
        explain: Output blocked: SSN detected without approval.
    - name: no_card_data
        expression: !has_card_number
        explain: Output blocked: card number detected.
""",
    "infra": """# Pramanix policy blueprint: infra
# Review every capacity limit before production use.
policy_name: infra_scale_guard
description: Constrain replica and resource changes.
version: 1.0
fields:
    - name: replicas
        type: Int
    - name: min_replicas
        type: Int
    - name: max_replicas
        type: Int
rules:
    - name: min_replicas
        expression: replicas >= min_replicas
        explain: Scale-down blocked: replicas below minimum.
    - name: max_replicas
        expression: replicas <= max_replicas
        explain: Scale-up blocked: replicas above maximum.
""",
}


def _cmd_init(args: argparse.Namespace) -> int:
    """Write a policy blueprint template for day-1 onboarding."""
    import pathlib

    template_name = str(args.template)
    output_path = pathlib.Path(args.output)
    content = _INIT_TEMPLATES.get(template_name)
    if content is None:
        print(f"ERROR: Unknown template '{template_name}'.", file=sys.stderr)
        return 2

    if output_path.exists() and not args.force:
        print(
            f"ERROR: Output file already exists: {output_path}. " "Use --force to overwrite.",
            file=sys.stderr,
        )
        return 2

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content.rstrip("\n") + "\n", encoding="utf-8")

    print(f"Template written: {output_path}")
    print("Next step: edit thresholds and rule names for your domain.")
    print(
        "Then run: pramanix explain --policy examples/cloud_infra.py "
        '--policy-var ScalingPolicy --intent \'{"replicas": 5, "cpu_request": 1000, "mem_request": 2048}\' '
        '--state \'{"state_version": "1.0", "min_r": 2, "max_r": 20, "cpu_budget": 4000, "mem_budget": 8192}\''
    )
    return 0


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
            return parts
        except ValueError:
            print(
                f"ERROR: {flag} must be a semver string like '1.2.0', got {s!r}.",
                file=sys.stderr,
            )
            raise SystemExit(2) from None

    from_ver = _parse_semver(args.from_version, "--from-version")
    to_ver = _parse_semver(args.to_version, "--to-version")

    # Parse field renames
    renames: dict[str, str] = {}
    for rename_spec in args.rename or []:
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


def _cmd_schema(args: argparse.Namespace) -> int:
    """Handle the 'schema' subcommand group."""
    if getattr(args, "schema_command", None) == "export":
        return _cmd_schema_export(args)
    print("Usage: pramanix schema export --policy FILE:CLASS [--output FILE]", file=sys.stderr)
    return 2


def _cmd_schema_export(args: argparse.Namespace) -> int:
    """Export a Policy's JSON schema (G-3).

    Loads a Policy subclass from a Python file and calls
    ``Policy.export_json_schema()``, then writes the result to stdout
    or a file.

    The ``--policy`` argument must be in the form ``path/to/file.py:ClassName``.

    Exit codes:
        0 — schema exported successfully
        2 — usage error (bad arguments, class not found, not a Policy)
    """
    import importlib.util
    import json as _json_mod
    import pathlib

    from pramanix.policy import Policy

    policy_spec: str = args.policy
    if ":" not in policy_spec:
        print(
            "ERROR: --policy must be in the form FILE:ClassName, e.g. " "my_policy.py:TradePolicy",
            file=sys.stderr,
        )
        return 2

    policy_file, class_name = policy_spec.rsplit(":", 1)

    try:
        spec = importlib.util.spec_from_file_location("_pramanix_schema_policy", policy_file)
        if spec is None or spec.loader is None:
            print(f"ERROR: Cannot load module spec from {policy_file}", file=sys.stderr)
            return 2
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except FileNotFoundError:
        print(f"ERROR: Policy file not found: {policy_file}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"ERROR: Failed to import policy file: {exc}", file=sys.stderr)
        return 2

    policy_cls = getattr(module, class_name, None)
    if policy_cls is None:
        print(
            f"ERROR: Class '{class_name}' not found in {policy_file}.",
            file=sys.stderr,
        )
        return 2

    if not (isinstance(policy_cls, type) and issubclass(policy_cls, Policy)):
        print(
            f"ERROR: '{class_name}' is not a subclass of pramanix.policy.Policy.",
            file=sys.stderr,
        )
        return 2

    try:
        schema = policy_cls.export_json_schema()
    except Exception as exc:
        print(f"ERROR: Failed to export schema: {exc}", file=sys.stderr)
        return 2

    indent: int = getattr(args, "indent", 2)
    output_json = _json_mod.dumps(schema, indent=indent, default=str)

    output_path = getattr(args, "output", None)
    if output_path:
        pathlib.Path(output_path).write_text(output_json + "\n", encoding="utf-8")
        print(f"Schema exported to {output_path}")
    else:
        print(output_json)

    return 0


def _cmd_calibrate_injection(args: argparse.Namespace) -> int:
    """Fit and persist a calibrated injection scorer (D-4).

    Reads a JSONL file where each line is:
        {"text": "...", "is_injection": true|false}

    Fits a ``CalibratedScorer`` and saves it as a NumPy ``.npz`` archive to ``--output``.

    Exit codes:
        0 — scorer fitted and saved
        1 — insufficient data or fitting failed
        2 — usage error
    """
    import json as _json_mod
    import pathlib

    dataset_path = pathlib.Path(args.dataset)
    if not dataset_path.exists():
        print(f"ERROR: Dataset file not found: {dataset_path}", file=sys.stderr)
        return 2

    texts: list[str] = []
    labels: list[bool] = []

    try:
        with open(dataset_path, encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    row = _json_mod.loads(line)
                except _json_mod.JSONDecodeError as exc:
                    print(f"ERROR: Invalid JSON on line {line_num}: {exc}", file=sys.stderr)
                    return 2
                if "text" not in row or "is_injection" not in row:
                    print(
                        f"ERROR: Line {line_num} missing 'text' or 'is_injection' key.",
                        file=sys.stderr,
                    )
                    return 2
                texts.append(str(row["text"]))
                labels.append(bool(row["is_injection"]))
    except Exception as exc:
        print(f"ERROR: Cannot read dataset: {exc}", file=sys.stderr)
        return 2

    min_examples: int = getattr(args, "min_examples", 200)
    if len(texts) < min_examples:
        print(
            f"ERROR: Dataset has only {len(texts)} examples; "
            f"minimum required is {min_examples}.  "
            "Provide more labelled examples for a reliable scorer.",
            file=sys.stderr,
        )
        return 1

    try:
        from pramanix.translator.injection_scorer import CalibratedScorer
    except ImportError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    try:
        scorer = CalibratedScorer()
        scorer.fit(texts, labels)
    except Exception as exc:
        print(f"ERROR: Failed to fit scorer: {exc}", file=sys.stderr)
        return 1

    output_path = pathlib.Path(args.output)

    # ── Resolve HMAC key (mandatory for pickle safety) ────────────────────────
    # Priority: --hmac-key-hex flag > PRAMANIX_SCORER_HMAC_KEY_HEX env var >
    #           auto-generate + write <output>.key sidecar.
    import secrets as _secrets

    _key_hex: str | None = getattr(args, "hmac_key_hex", None)
    if not _key_hex:
        _key_hex = os.environ.get("PRAMANIX_SCORER_HMAC_KEY_HEX")

    if _key_hex:
        try:
            hmac_key = bytes.fromhex(_key_hex)
        except ValueError as exc:
            print(
                f"ERROR: --hmac-key-hex / PRAMANIX_SCORER_HMAC_KEY_HEX is not valid hex: {exc}",
                file=sys.stderr,
            )
            return 2
        if len(hmac_key) < 16:
            print(
                "ERROR: HMAC key must be at least 16 bytes (32 hex chars); "
                f"got {len(hmac_key)} bytes.",
                file=sys.stderr,
            )
            return 2
    else:
        hmac_key = _secrets.token_bytes(32)
        key_path = output_path.with_suffix(output_path.suffix + ".key")
        key_path.write_text(hmac_key.hex() + "\n", encoding="utf-8")
        print(
            f"WARNING: No HMAC key supplied.  A random 32-byte key has been auto-generated "
            f"and written to {key_path}.\n"
            f"  Keep this file secret and pass it to future 'pramanix load-scorer' calls via:\n"
            f"    --hmac-key-hex $(cat {key_path})\n"
            f"  or set: PRAMANIX_SCORER_HMAC_KEY_HEX=$(cat {key_path})",
            file=sys.stderr,
        )

    try:
        scorer.save(output_path, hmac_key=hmac_key)
    except Exception as exc:
        print(f"ERROR: Failed to save scorer: {exc}", file=sys.stderr)
        return 1

    positives = sum(labels)
    negatives = len(labels) - positives
    print(
        f"Scorer fitted on {len(texts)} examples "
        f"({positives} injection, {negatives} benign) "
        f"and saved to {output_path}"
    )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# pramanix doctor — environment validation
# ─────────────────────────────────────────────────────────────────────────────


class _DoctorCheck(TypedDict):
    name: str
    level: Literal["OK", "WARN", "ERROR", "SKIP"]
    detail: str
    hint: NotRequired[str]


def _check_z3_solver(solver_factory: type | None = None) -> _DoctorCheck:
    """Run the Z3 functional sanity check.

    Args:
        solver_factory: Z3 Solver class to use.  Defaults to ``z3.Solver``.
            Pass a subclass in tests to exercise the ERROR path without
            monkeypatching the global ``z3.Solver``.

    Returns:
        A ``_check`` kwarg dict with ``name``, ``level``, ``detail``, ``hint``.
    """
    try:
        import z3

        _factory = solver_factory if solver_factory is not None else z3.Solver
        s = _factory()
        s.add(z3.Bool("x") == True)
        res = str(s.check())
        if res == "sat":
            return {
                "name": "z3-solver",
                "level": "OK",
                "detail": f"z3 {z3.get_version_string()} — solver functional",
                "hint": "",
            }
        return {
            "name": "z3-solver",
            "level": "ERROR",
            "detail": f"z3.Solver().check() returned {res!r} — unexpected",
            "hint": "Reinstall z3-solver: pip install 'z3-solver>=4.12'.",
        }
    except ImportError:
        return {
            "name": "z3-solver",
            "level": "ERROR",
            "detail": "z3-solver not installed",
            "hint": "pip install 'z3-solver>=4.12'",
        }
    except Exception as exc:
        return {
            "name": "z3-solver",
            "level": "ERROR",
            "detail": f"z3 functional check failed: {exc}",
            "hint": "Reinstall z3-solver: pip install 'z3-solver>=4.12'.",
        }


def _check_pointer_width(calcsize_fn: type | None = None) -> _DoctorCheck:
    """Return the pointer-width check result dict.

    Args:
        calcsize_fn: Callable with the same signature as ``struct.calcsize``.
            Defaults to ``struct.calcsize``.  Pass a lambda in tests to
            simulate a 32-bit machine without monkeypatching ``struct``.
    """
    import struct as _struct

    _fn = calcsize_fn if calcsize_fn is not None else _struct.calcsize
    bits = _fn("P") * 8
    if bits == 64:
        return {"name": "platform-bits", "level": "OK", "detail": "64-bit process", "hint": ""}
    return {
        "name": "platform-bits",
        "level": "WARN",
        "detail": f"{bits}-bit process — 32-bit is unsupported",
        "hint": "Run on a 64-bit platform.",
    }


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Validate the Pramanix deployment environment.

    Checks Python version, platform compatibility, core imports, Z3 solver
    functionality, optional extras, signing key configuration, and Redis
    reachability when configured.

    Exit codes:
        0 — all checks passed (warnings only if --strict not set)
        1 — one or more ERROR checks failed, or WARNING with --strict
        2 — usage error
    """
    import importlib
    import importlib.util
    import pathlib
    import platform
    import sys as _sys

    checks: list[dict[str, object]] = []
    _pramanix_env = os.environ.get("PRAMANIX_ENV", "").lower()
    is_production_profile = bool(
        getattr(args, "production", False) or _pramanix_env == "production"
    )

    def _check(
        name: str,
        level: Literal["OK", "WARN", "ERROR", "SKIP"],
        detail: str,
        hint: str = "",
    ) -> None:
        checks.append({"name": name, "level": level, "detail": detail, "hint": hint})

    def _has(modname: str) -> bool:
        try:
            return importlib.util.find_spec(modname) is not None
        except (ModuleNotFoundError, ValueError):
            return False

    def _is_probably_hex(value: str) -> bool:
        lowered = value.lower()
        return all(ch in "0123456789abcdef" for ch in lowered)

    # ── 1. Python version ─────────────────────────────────────────────────────
    vi = _sys.version_info
    if (vi.major, vi.minor) >= (3, 13):
        _check("python-version", "OK", f"Python {vi.major}.{vi.minor}.{vi.micro}")
    else:
        _check(
            "python-version",
            "ERROR",
            f"Python {vi.major}.{vi.minor}.{vi.micro} — minimum required is 3.13",
            hint="Upgrade to Python 3.13+.",
        )

    # ── 2. Platform / libc (musl vs glibc) ───────────────────────────────────
    from pramanix._platform import is_musl as _is_musl

    plat = platform.system()
    if plat == "Linux":
        if _is_musl():
            _check(
                "platform-libc",
                "ERROR",
                "musl libc detected (Alpine Linux)",
                hint="Use a glibc-based image (e.g. python:3.13-slim-bookworm). "
                "musl breaks z3-solver native extensions.",
            )
        else:
            import ctypes

            try:
                libc = ctypes.CDLL("libc.so.6", use_errno=True)
                gnu_get_libc_version = getattr(libc, "gnu_get_libc_version", None)
                if gnu_get_libc_version is not None:
                    gnu_get_libc_version.restype = ctypes.c_char_p
                    glibc_ver = gnu_get_libc_version().decode()
                    _check("platform-libc", "OK", f"glibc {glibc_ver} (Linux/{platform.machine()})")
                else:
                    _check("platform-libc", "OK", f"glibc detected (Linux/{platform.machine()})")
            except OSError:
                _check(
                    "platform-libc",
                    "OK",
                    "non-musl libc (libc.so.6 not loadable but musl check passed)",
                )
    else:
        _check(
            "platform-libc", "OK", f"{plat}/{platform.machine()} (non-Linux; glibc check skipped)"
        )

    # ── 3. Pointer width ──────────────────────────────────────────────────────
    _check(**_check_pointer_width())

    # ── 4. Core pramanix import ───────────────────────────────────────────────
    try:
        import pramanix as _px

        ver = getattr(_px, "__version__", "unknown")
        _check("pramanix-import", "OK", f"pramanix {ver}")
    except Exception as exc:
        _check(
            "pramanix-import",
            "ERROR",
            f"Import failed: {exc}",
            hint="Run 'pip install pramanix' or reinstall from source.",
        )

    # ── 5. Z3 solver ─────────────────────────────────────────────────────────
    z3_result = _check_z3_solver()
    _check(**z3_result)

    # ── 6. Pydantic ───────────────────────────────────────────────────────────
    try:
        import pydantic

        pv = pydantic.VERSION
        major = int(pv.split(".")[0])
        if major >= 2:
            _check("pydantic", "OK", f"pydantic {pv}")
        else:
            _check(
                "pydantic",
                "ERROR",
                f"pydantic {pv} — v2.x required",
                hint="pip install 'pydantic>=2.5'",
            )
    except ImportError:
        _check("pydantic", "ERROR", "pydantic not installed", hint="pip install 'pydantic>=2.5'")

    # ── 7. re2 linear-time regex engine ─────────────────────────────────────
    if _has("re2"):
        _check("security-re2", "OK", "google-re2 installed (ReDoS-resistant regex engine)")
    elif is_production_profile:
        _check(
            "security-re2",
            "ERROR",
            "google-re2 missing — stdlib re is vulnerable to crafted ReDoS payloads",
            hint="pip install 'pramanix[security]'",
        )
    else:
        _check(
            "security-re2",
            "WARN",
            "google-re2 missing — stdlib re fallback active",
            hint="pip install 'pramanix[security]'",
        )

    # ── 8. Signing key configuration ─────────────────────────────────────────
    signing_key = os.environ.get("PRAMANIX_SIGNING_KEY", "")
    if signing_key:
        if _is_probably_hex(signing_key):
            if len(signing_key) >= 64:
                _check("signing-key", "OK", "PRAMANIX_SIGNING_KEY is set (hex, >=32 bytes)")
            else:
                _check(
                    "signing-key",
                    "ERROR" if is_production_profile else "WARN",
                    "PRAMANIX_SIGNING_KEY is set but too short for production use",
                    hint=("Set a >=32-byte secret (64+ hex chars), e.g. " "openssl rand -hex 32"),
                )
        elif len(signing_key) >= 32:
            _check("signing-key", "OK", "PRAMANIX_SIGNING_KEY is set")
        else:
            _check(
                "signing-key",
                "ERROR" if is_production_profile else "WARN",
                "PRAMANIX_SIGNING_KEY is set but shorter than 32 chars",
                hint="Set a stronger key, e.g. openssl rand -hex 32",
            )
    else:
        _check(
            "signing-key",
            "ERROR" if is_production_profile else "WARN",
            "PRAMANIX_SIGNING_KEY not set — decision proofs will be unsigned",
            hint="Set PRAMANIX_SIGNING_KEY to a 32-byte hex secret, or use "
            "GuardConfig(signing_key=...) at runtime.",
        )

    # ── 9. Cryptography package (required for PramanixSigner / Ed25519) ───────
    if _has("cryptography"):
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,  # noqa: F401 — availability probe only
            )

            _check("cryptography", "OK", "cryptography — Ed25519 available")
        except ImportError as exc:
            _check(
                "cryptography",
                "WARN",
                f"cryptography import partial: {exc}",
                hint="Reinstall: pip install 'pramanix[crypto]'",
            )
    else:
        _check(
            "cryptography",
            "WARN",
            "cryptography not installed — Ed25519 signing unavailable",
            hint="pip install 'pramanix[crypto]'",
        )

    # ── 10. Optional extras ───────────────────────────────────────────────────
    _optional_checks: list[tuple[str, str, str]] = [
        ("otel", "opentelemetry.sdk", "pip install 'pramanix[otel]'"),
        ("translator-httpx", "httpx", "pip install 'pramanix[translator]'"),
        ("fastapi", "fastapi", "pip install 'pramanix[fastapi]'"),
        ("langchain", "langchain_core", "pip install 'pramanix[langchain]'"),
        ("llamaindex", "llama_index.core", "pip install 'pramanix[llamaindex]'"),
        ("redis", "redis", "pip install 'pramanix[identity]'"),
        ("pdf", "fpdf", "pip install 'pramanix[pdf]'"),
        ("aws-boto3", "boto3", "pip install 'pramanix[aws]'"),
        ("azure-identity", "azure.identity", "pip install 'pramanix[azure]'"),
        ("gcp-secretmgr", "google.cloud.secretmanager", "pip install 'pramanix[gcp]'"),
        ("vault-hvac", "hvac", "pip install 'pramanix[vault]'"),
        ("kafka", "confluent_kafka", "pip install 'pramanix[kafka]'"),
        ("datadog", "datadog_api_client", "pip install 'pramanix[datadog]'"),
    ]

    for label, modname, install_hint in _optional_checks:
        if _has(modname):
            _check(f"extra:{label}", "OK", f"{modname} installed")
        else:
            _check(
                f"extra:{label}", "SKIP", f"{modname} not installed (optional)", hint=install_hint
            )

    # ── 11. Logging handler configuration ────────────────────────────────────
    from pramanix.logging_helpers import check_logging_configuration as _chk_log

    _log_status = _chk_log("pramanix")
    _check(
        "logging-handlers",
        _log_status["level"],
        _log_status["detail"],
        hint=_log_status["hint"],
    )

    # ── 12. Policy-hash binding in production ─────────────────────────────────
    _policy_hash_env = os.environ.get("PRAMANIX_EXPECTED_POLICY_HASH", "")
    if is_production_profile:
        if _policy_hash_env:
            _check(
                "policy-hash-binding",
                "OK",
                "PRAMANIX_EXPECTED_POLICY_HASH is set " f"({_policy_hash_env[:12]}…)",
            )
        else:
            _check(
                "policy-hash-binding",
                "WARN",
                "PRAMANIX_EXPECTED_POLICY_HASH not set — "
                "policy-version binding disabled in production. "
                "Silent policy drift will not be detected.",
                hint=(
                    "Run guard = Guard(Policy) once, capture guard.policy_hash,"
                    " pin it in config, then set "
                    "GuardConfig(expected_policy_hash=<hash>)."
                ),
            )
    else:
        _check(
            "policy-hash-binding",
            "SKIP",
            "Production profile not enabled — policy-hash check skipped",
            hint=("Set PRAMANIX_ENV=production to enable production checks."),
        )

    # ── 13. Redis reachability (only if PRAMANIX_REDIS_URL is configured) ────
    redis_url = os.environ.get("PRAMANIX_REDIS_URL", "")
    if redis_url:
        if _has("redis"):
            try:
                import redis as _redis

                client = _redis.from_url(redis_url, socket_connect_timeout=3)
                client.ping()
                _check("redis-ping", "OK", f"Redis reachable at {redis_url}")
                client.close()
            except Exception as exc:
                _check(
                    "redis-ping",
                    "ERROR",
                    f"Redis unreachable at {redis_url}: {exc}",
                    hint="Check PRAMANIX_REDIS_URL and that Redis is running.",
                )
        else:
            _check(
                "redis-ping",
                "SKIP",
                "redis package not installed; skipping ping",
                hint="pip install 'pramanix[identity]'",
            )

    # ── 14. Execution token backend durability ─────────────────────────────
    _token_backend = os.environ.get("PRAMANIX_EXECUTION_TOKEN_BACKEND", "").lower()
    if is_production_profile:
        if _token_backend in ("", "memory", "inmemory", "in-memory"):
            _check(
                "execution-token-backend",
                "WARN",
                "Execution token backend is IN-MEMORY (default). "
                "In a multi-process or multi-replica deployment, tokens consumed "
                "on one worker are not visible to other workers — enabling replay "
                "attacks across processes. Process restarts also wipe consumed tokens.",
                hint=(
                    "Set PRAMANIX_EXECUTION_TOKEN_BACKEND=redis and configure "
                    "PRAMANIX_REDIS_URL, or use SQLiteExecutionTokenVerifier "
                    "for single-host multi-worker deployments."
                ),
            )
        else:
            _check(
                "execution-token-backend",
                "OK",
                f"Execution token backend: {_token_backend}",
            )
    else:
        _check(
            "execution-token-backend",
            "SKIP",
            "Production profile not enabled — token backend check skipped",
        )

    # ── 15. Audit sink reachability (deployment gate) ───────────────────────
    _audit_sink = os.environ.get("PRAMANIX_AUDIT_SINK", "").strip().lower()
    if is_production_profile:
        if not _audit_sink:
            _check(
                "audit-sink-reachability",
                "ERROR",
                "No AuditSink configured for production (PRAMANIX_AUDIT_SINK is unset)",
                hint=(
                    "Set PRAMANIX_AUDIT_SINK to a reachable durable sink "
                    "(e.g. kafka, datadog, http, file) before deploy."
                ),
            )
            # Back-compat contract used by older doctor tests.
            _check(
                "audit-sink-policy",
                "WARN",
                "PRAMANIX_AUDIT_SINK not set — sink durability cannot be asserted",
                hint=("Set PRAMANIX_AUDIT_SINK to a durable sink " "(e.g. kafka, datadog, http)."),
            )
        elif _audit_sink in ("console", "stdout", "stderr", "print"):
            _check(
                "audit-sink-reachability",
                "ERROR",
                "Console AuditSink configured in production; not durable/reachable",
                hint="Switch to a durable AuditSink (kafka/http/datadog/file) before deploy.",
            )
            _check(
                "audit-sink-policy",
                "WARN",
                "Console audit sink detected in production profile",
                hint="Switch to a durable sink (kafka/http/datadog/file) before deploy.",
            )
        else:
            _check("audit-sink-reachability", "OK", f"Audit sink configured: {_audit_sink}")
            _check("audit-sink-policy", "OK", f"Audit sink configured: {_audit_sink}")
    else:
        _check(
            "audit-sink-reachability",
            "SKIP",
            "Production profile not enabled — audit sink reachability check skipped",
        )
        _check(
            "audit-sink-policy",
            "SKIP",
            "Production profile not enabled — audit sink policy check skipped",
        )

    # ── 16. Async engine advisory (non-blocking) ─────────────────────────────
    _async_engine = os.environ.get("PRAMANIX_ASYNC_ENGINE", "default").strip().lower()
    if is_production_profile and _async_engine == "default":
        _check(
            "async-engine",
            "WARN",
            "Async engine is default; evaluate high-performance event loop for throughput",
            hint="Set PRAMANIX_ASYNC_ENGINE=uvloop on supported Linux workloads.",
        )
    elif is_production_profile:
        _check("async-engine", "OK", f"Async engine configured: {_async_engine}")
    else:
        _check("async-engine", "SKIP", "Production profile not enabled — async check skipped")

    # ── 17. Policy YAML quick lint (deployment gate) ─────────────────────────
    # Use os.walk (followlinks=False) instead of pathlib.glob(**) to avoid
    # following symlinks into .venv/Scripts on Windows, which causes the scan
    # to walk thousands of stdlib files and appear to hang indefinitely.
    import fnmatch as _fnmatch

    _YAML_NAMES = ("*policy*.yaml", "*policy*.yml", "mesh_policy_ir.yaml")
    _SKIP_DIRS = frozenset(
        {
            ".venv",
            ".git",
            "__pycache__",
            "node_modules",
            ".tox",
            ".mypy_cache",
            "dist",
            "build",
            ".eggs",
            ".pytest_cache",
            ".ruff_cache",
        }
    )
    policy_files: set[pathlib.Path] = set()
    for _root, _dirs, _files in os.walk(pathlib.Path.cwd(), followlinks=False):
        _dirs[:] = [d for d in _dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for _fname in _files:
            if any(_fnmatch.fnmatch(_fname, pat) for pat in _YAML_NAMES):
                policy_files.add(pathlib.Path(_root) / _fname)

    if not policy_files:
        _check(
            "policy-yaml-lint",
            "WARN" if is_production_profile else "SKIP",
            "No policy YAML files found for lint",
            hint="Add policy YAML files or run doctor from repo root.",
        )
    else:
        try:
            import yaml as _yaml

            bad_file: pathlib.Path | None = None
            bad_error = ""
            for file_path in sorted(policy_files):
                try:
                    _yaml.safe_load(file_path.read_text(encoding="utf-8"))
                except Exception as exc:
                    bad_file = file_path
                    bad_error = str(exc)
                    break

            if bad_file is None:
                _check("policy-yaml-lint", "OK", f"Linted {len(policy_files)} policy YAML file(s)")
            else:
                _check(
                    "policy-yaml-lint",
                    "ERROR" if is_production_profile else "WARN",
                    f"Invalid policy YAML: {bad_file} ({bad_error})",
                    hint="Fix YAML syntax before deploy.",
                )
        except ImportError:
            _check(
                "policy-yaml-lint",
                "ERROR" if is_production_profile else "WARN",
                "PyYAML is not installed; cannot lint policy YAML files",
                hint="pip install pyyaml",
            )

    # ── 18. Translator API key configuration ──────────────────────────────────
    # Warn when a translator backend looks configured but its API key env var
    # is absent, so that LLM calls don't fail silently at request time.
    _translator_key_map: list[tuple[str, str, str]] = [
        # (module_name_hint, env_var, display_name)
        ("openai", "OPENAI_API_KEY", "OpenAI"),
        ("anthropic", "ANTHROPIC_API_KEY", "Anthropic"),
        ("cohere", "COHERE_API_KEY", "Cohere"),
        ("mistral", "MISTRAL_API_KEY", "Mistral"),
        ("google.generativeai", "GOOGLE_API_KEY", "Google Gemini"),
        ("together", "TOGETHER_API_KEY", "Together AI"),
        ("groq", "GROQ_API_KEY", "Groq"),
    ]

    # Collect which translator packages are actually installed.
    _installed_translators: list[tuple[str, str, str]] = [
        (mod, envvar, name) for mod, envvar, name in _translator_key_map if _has(mod)
    ]

    if not _installed_translators:
        _check(
            "translator-api-keys",
            "SKIP",
            "No LLM translator packages detected — API key check skipped",
            hint="Install a translator extra: pip install 'pramanix[translator]'",
        )
    else:
        _missing_keys: list[str] = []
        _present_keys: list[str] = []
        for _mod, _envvar, _name in _installed_translators:
            if os.environ.get(_envvar, "").strip():
                _present_keys.append(f"{_name} ({_envvar})")
            else:
                _missing_keys.append(f"{_name} -> set {_envvar}")

        if _missing_keys and not _present_keys:
            # All installed translators are missing their key.
            _check(
                "translator-api-keys",
                "ERROR",
                f"LLM translator packages installed but NO API keys configured. "
                f"Missing: {', '.join(_missing_keys)}",
                hint="Set the corresponding environment variable(s) before deploying.",
            )
        elif _missing_keys:
            _check(
                "translator-api-keys",
                "WARN",
                f"Some translator API keys missing: {'; '.join(_missing_keys)}",
                hint="Set the missing environment variable(s) to enable those translators.",
            )
        else:
            _check(
                "translator-api-keys",
                "OK",
                f"Translator API key(s) configured: {', '.join(_present_keys)}",
            )

    # ── 19. Prometheus metrics availability ───────────────────────────────────
    if _has("prometheus_client"):
        _check(
            "metrics-prometheus", "OK", "prometheus_client installed — /metrics endpoint supported"
        )
    elif is_production_profile:
        _check(
            "metrics-prometheus",
            "ERROR",
            "prometheus_client not installed — all Pramanix decision metrics are silently dropped. "
            "Operators have no visibility into ALLOW/BLOCK rates, latency, or timeouts.",
            hint="pip install 'pramanix[metrics]' and expose /metrics.",
        )
    else:
        _check(
            "metrics-prometheus",
            "WARN",
            "prometheus_client not installed — decision metrics unavailable",
            hint="pip install 'pramanix[metrics]'",
        )

    # ── 20. OpenTelemetry tracing availability ────────────────────────────────
    if _has("opentelemetry.sdk"):
        _check("tracing-otel", "OK", "opentelemetry-sdk installed — distributed tracing active")
    elif is_production_profile:
        _check(
            "tracing-otel",
            "WARN",
            "opentelemetry-sdk not installed — all Guard.verify() spans are no-ops. "
            "Decision IDs cannot be correlated with downstream traces.",
            hint="pip install 'pramanix[otel]' and configure OTEL_EXPORTER_OTLP_ENDPOINT.",
        )
    else:
        _check(
            "tracing-otel",
            "SKIP",
            "opentelemetry-sdk not installed (optional for non-production)",
            hint="pip install 'pramanix[otel]'",
        )

    # ── 21. NLP toxicity scorer backend (detoxify) ────────────────────────────
    if _has("detoxify"):
        _check(
            "nlp-toxicity-backend",
            "OK",
            "detoxify installed — ToxicityScorer uses ML model backend",
        )
    elif is_production_profile:
        _check(
            "nlp-toxicity-backend",
            "WARN",
            "detoxify not installed — ToxicityScorer falls back to keyword-density heuristic. "
            "Adversarial inputs using synonyms, obfuscation, or non-English content "
            "will not be caught. pramanix_nlp_degradation_total counter will increment.",
            hint="pip install detoxify  (or pip install 'pramanix[nlp]')",
        )
    else:
        _check(
            "nlp-toxicity-backend",
            "SKIP",
            "detoxify not installed (keyword fallback active — acceptable for non-production)",
            hint="pip install detoxify for production-grade toxicity scoring",
        )

    # ── 22. Semantic similarity backend (sentence-transformers) ───────────────
    if _has("sentence_transformers"):
        _check(
            "nlp-semantic-backend",
            "OK",
            "sentence-transformers installed — SemanticSimilarityGuard uses embedding model",
        )
    elif is_production_profile:
        _check(
            "nlp-semantic-backend",
            "WARN",
            "sentence-transformers not installed — SemanticSimilarityGuard falls back to "
            "Jaccard word-overlap (easily evaded by paraphrasing). "
            "pramanix_nlp_degradation_total counter will increment.",
            hint="pip install sentence-transformers  (or pip install 'pramanix[nlp]')",
        )
    else:
        _check(
            "nlp-semantic-backend",
            "SKIP",
            "sentence-transformers not installed (Jaccard fallback active — acceptable for non-production)",
            hint="pip install sentence-transformers for production-grade semantic similarity",
        )

    # ── 23. Translator enabled flag ───────────────────────────────────────────
    _translator_enabled = os.environ.get("PRAMANIX_TRANSLATOR_ENABLED", "true").strip().lower()
    if _translator_enabled in ("false", "0", "no", "off"):
        if is_production_profile:
            _check(
                "translator-enabled",
                "WARN",
                "PRAMANIX_TRANSLATOR_ENABLED=false — LLM intent translation is globally "
                "disabled. All parse_and_verify() calls will skip the NLP extraction phase. "
                "Only pre-structured guard.verify(intent, state) calls are active.",
                hint="Remove PRAMANIX_TRANSLATOR_ENABLED=false or set to 'true' if LLM "
                "translation is required in production.",
            )
        else:
            _check(
                "translator-enabled",
                "WARN",
                "PRAMANIX_TRANSLATOR_ENABLED=false — LLM translation disabled",
                hint="Set PRAMANIX_TRANSLATOR_ENABLED=true to enable parse_and_verify()",
            )
    else:
        _check("translator-enabled", "OK", "PRAMANIX_TRANSLATOR_ENABLED is active (default)")

    # ── Render results ────────────────────────────────────────────────────────
    has_error = any(c["level"] == "ERROR" for c in checks)
    has_warn = any(c["level"] == "WARN" for c in checks)

    if getattr(args, "as_json", False):
        import json as _json_mod

        summary = {
            "profile": "production" if is_production_profile else "default",
            "passed": not has_error,
            "errors": sum(1 for c in checks if c["level"] == "ERROR"),
            "warnings": sum(1 for c in checks if c["level"] == "WARN"),
            "checks": checks,
        }
        print(_json_mod.dumps(summary, indent=2))
    else:
        _icons = {"OK": "OK  ", "WARN": "WARN", "ERROR": "ERR ", "SKIP": "SKIP"}
        for c in checks:
            icon = _icons.get(str(c["level"]), "    ")
            line = f"  [{icon}] {c['name']}: {c['detail']}"
            print(line)
            if c.get("hint") and c["level"] in ("WARN", "ERROR"):
                print(f"         -> {c['hint']}")
        print()
        ok_count = sum(1 for c in checks if c["level"] == "OK")
        skip_count = sum(1 for c in checks if c["level"] == "SKIP")
        warn_count = sum(1 for c in checks if c["level"] == "WARN")
        err_count = sum(1 for c in checks if c["level"] == "ERROR")
        print(f"  {ok_count} OK  {warn_count} WARN  {err_count} ERROR  {skip_count} SKIP")
        print()
        _first_actionable = next((c for c in checks if c["level"] in ("ERROR", "WARN")), None)
        if _first_actionable is None:
            print("  Next step: you are ready to use Pramanix.")
        else:
            _label = str(_first_actionable["name"]).replace("-", " ")
            _detail = str(_first_actionable["detail"])
            print(f"  Next step: fix {_label} first — {_detail}")
            if _first_actionable.get("hint"):
                print(f"             {_first_actionable['hint']}")
        print()
        if has_error:
            print("pramanix doctor: FAIL — fix ERROR items before deploying.")
        elif has_warn and (getattr(args, "strict", False) or is_production_profile):
            if is_production_profile:
                print("pramanix doctor: FAIL — warnings present (production profile).")
            else:
                print("pramanix doctor: FAIL — warnings present (--strict mode).")
        elif has_warn:
            print("pramanix doctor: PASS with warnings.")
        else:
            print("pramanix doctor: PASS — environment looks good.")

    if has_error:
        return 1
    if has_warn and (getattr(args, "strict", False) or is_production_profile):
        return 1
    return 0


# ── Natural Policy Compiler CLI (Phase 2) ─────────────────────────────────────

_COMPILE_POLICY_EXAMPLE = """\
# Minimal NaturalPolicySchema YAML template for 'pramanix compile-policy'
# This is the intermediate representation consumed by the compiler.
# Use this format when you already have a validated schema and want to skip
# the LLM translation step (NaturalPolicyCompiler.compile_from_schema).
#
# NOTE: rhs_value must be a scalar (int, float, bool, or str).
#       Field-to-field comparisons are not supported in the schema.
policy_name: example_transfer_policy
original_english: >
  Allow transfers only when the account balance is above zero
  and the transfer amount is strictly positive.
fields:
  - name: balance
    z3_type: Real
    description: "Current account balance in USD."
  - name: amount
    z3_type: Real
    description: "Requested transfer amount in USD."
constraints:
  - kind: comparison
    label: positive_balance
    lhs:
      kind: field
      field_name: balance
    operator: ">"
    rhs_value: 0
    natural_language: "balance > 0 (account balance must be greater than 0)."
  - kind: comparison
    label: positive_amount
    lhs:
      kind: field
      field_name: amount
    operator: ">"
    rhs_value: 0
    natural_language: "amount > 0 (transfer amount must be strictly positive, above 0)."
"""


def _cmd_compile_policy(args: argparse.Namespace) -> int:
    """Compile a NaturalPolicySchema YAML/JSON file to a Z3 ConstraintExpr."""
    if getattr(args, "example", False):
        print(_COMPILE_POLICY_EXAMPLE)
        return 0

    try:
        from pramanix.natural_policy import NaturalPolicyCompiler, VerificationMode
    except ImportError as exc:
        print(f"ERROR: could not import natural_policy module: {exc}", file=sys.stderr)
        return 1

    policy_path = args.policy_file
    verify_arg = getattr(args, "verify", "warn")
    as_json = getattr(args, "as_json", False)

    if not policy_path:
        print("ERROR: POLICY_FILE is required when --example is not used.", file=sys.stderr)
        print("Usage: pramanix compile-policy POLICY_FILE [--verify {strict,warn,skip}] [--json]")
        print("       pramanix compile-policy --example")
        return 2

    try:
        mode = VerificationMode[verify_arg.upper()]
    except KeyError:
        print(f"ERROR: unknown verification mode {verify_arg!r}", file=sys.stderr)
        return 2

    try:
        with open(policy_path, encoding="utf-8") as _fh:
            raw = _fh.read()
    except OSError as exc:
        print(f"ERROR: cannot read {policy_path!r}: {exc}", file=sys.stderr)
        return 1

    # Support both YAML and JSON input
    try:
        import yaml as _yaml

        policy_dict = _yaml.safe_load(raw)
    except ImportError:
        try:
            policy_dict = _json.loads(raw)
        except _json.JSONDecodeError as exc:
            print(
                f"ERROR: file is not valid JSON and PyYAML is not installed: {exc}",
                file=sys.stderr,
            )
            return 1
    except Exception as exc:
        print(f"ERROR: YAML parse error: {exc}", file=sys.stderr)
        return 1

    try:
        from pramanix.natural_policy.schemas import NaturalPolicySchema

        schema = NaturalPolicySchema.model_validate(policy_dict)
        compiled = NaturalPolicyCompiler.compile_from_schema(schema, verification_mode=mode)
    except Exception as exc:
        if as_json:
            print(_json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"ERROR: compilation failed: {exc}", file=sys.stderr)
        return 1

    result: dict[str, Any] = {
        "ok": True,
        "policy_name": compiled.schema.policy_name,
        "rules_compiled": len(compiled.constraints),
        "verification_mode": verify_arg,
        "verification_passed": compiled.verification.verified,
        "verification_warnings": list(compiled.verification.mismatches),
    }

    if as_json:
        print(_json.dumps(result, indent=2))
    else:
        ok_sym = "+" if result["verification_passed"] else "!"
        print(f"[{ok_sym}] Compiled: {result['policy_name']}")
        print(f"    Rules compiled : {result['rules_compiled']}")
        print(
            f"    Verification   : {verify_arg} — {'PASS' if result['verification_passed'] else 'MISMATCH'}"
        )
        for m in result["verification_warnings"]:
            print(f"    Mismatch: {m}")

    return 0 if compiled.verification.verified else 1


def _cmd_lint_policy(args: argparse.Namespace) -> int:
    """Static linter for Pramanix policy files.

    Reports errors (fail the build) and warnings (informational) across:

    * **E001** — Missing invariant label (``.named()`` not called)
    * **E002** — Duplicate invariant labels
    * **E003** — Empty invariants list
    * **E004** — File not found / import failure
    * **W001** — No ``Meta`` class declared (version pinning unavailable)
    * **W002** — No ``intent_model`` on ``Meta`` (intent validation disabled)
    * **W003** — No ``state_model`` on ``Meta`` (state validation disabled)
    * **W004** — Fields declared but not referenced by any invariant
    * **W005** — ``Policy.validate()`` raises (policy is syntactically ill-formed)
    * **W006** — Invariant missing ``.explain()`` call (violation messages will
      be generic; operators won't be able to surface useful context to callers)

    Exit codes:
        0 — No errors (warnings only if ``--strict`` is not set)
        1 — One or more errors (or warnings in ``--strict`` mode)
        2 — Usage error
    """
    import pathlib

    policy_path = pathlib.Path(args.policy_file)
    as_json = getattr(args, "as_json", False)
    strict = getattr(args, "strict", False)

    findings: list[dict[str, str]] = []

    def _report(code: str, level: str, message: str) -> None:
        findings.append({"code": code, "level": level, "message": message})

    # ── Load the Policy class ─────────────────────────────────────────────────
    policy_cls = None
    suffix = policy_path.suffix.lower()

    if not policy_path.exists():
        _report("E004", "ERROR", f"File not found: {policy_path}")
    elif suffix == ".py":
        policy_cls = _lint_load_python_policy(
            policy_path, getattr(args, "policy_var", None), _report
        )
    elif suffix in (".yaml", ".yml", ".toml"):
        policy_cls = _lint_load_declarative_policy(policy_path, suffix, _report)
    else:
        _report(
            "E004",
            "ERROR",
            f"Unsupported file extension {policy_path.suffix!r}.  "
            "Use .py, .yaml, .yml, or .toml",
        )

    # ── Structural lint (only when loading succeeded) ─────────────────────────
    if policy_cls is not None:
        _lint_policy_class(policy_cls, _report)

    # ── Output ────────────────────────────────────────────────────────────────
    errors = [f for f in findings if f["level"] == "ERROR"]
    warnings = [f for f in findings if f["level"] == "WARN"]

    if as_json:
        print(
            _json.dumps(
                {
                    "file": str(policy_path),
                    "errors": len(errors),
                    "warnings": len(warnings),
                    "findings": findings,
                    "ok": len(errors) == 0 and (not strict or len(warnings) == 0),
                },
                indent=2,
            )
        )
    else:
        total = len(findings)
        if total == 0:
            print(f"[OK] {policy_path} — no issues found")
        else:
            for f in findings:
                sym = "E" if f["level"] == "ERROR" else "W"
                print(f"[{sym}] {f['code']} {f['message']}")
            print(f"\n{len(errors)} error(s), {len(warnings)} warning(s) " f"in {policy_path}")

    if errors:
        return 1
    if strict and warnings:
        return 1
    return 0


def _lint_load_python_policy(
    path: pathlib.Path,
    class_name: str | None,
    report: Any,
) -> Any:
    """Import a Python policy file and return the Policy class."""
    import importlib.util

    try:
        spec = importlib.util.spec_from_file_location("_pramanix_lint_policy", path)
        if spec is None or spec.loader is None:
            report("E004", "ERROR", f"Cannot create module spec from {path}")
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as exc:
        report("E004", "ERROR", f"Failed to import {path}: {exc}")
        return None

    from pramanix.policy import Policy

    if class_name:
        cls = getattr(module, class_name, None)
        if cls is None:
            report("E004", "ERROR", f"Class {class_name!r} not found in {path}")
            return None
        if not (isinstance(cls, type) and issubclass(cls, Policy) and cls is not Policy):
            report("E004", "ERROR", f"{class_name!r} is not a Policy subclass")
            return None
        return cls

    # Discover the first Policy subclass in the module
    for name in dir(module):
        obj = getattr(module, name)
        if (
            isinstance(obj, type)
            and issubclass(obj, Policy)
            and obj is not Policy
            and obj.__module__ == module.__name__
        ):
            return obj

    report("E004", "ERROR", f"No Policy subclass found in {path}")
    return None


def _lint_load_declarative_policy(
    path: pathlib.Path,
    suffix: str,
    report: Any,
) -> Any:
    """Load a YAML/TOML declarative policy file."""
    try:
        from pramanix.natural_policy.yaml_loader import load_policy_file

        return load_policy_file(path)
    except Exception as exc:
        report("E004", "ERROR", f"Failed to load declarative policy {path}: {exc}")
        return None


def _lint_policy_class(policy_cls: Any, report: Any) -> None:
    """Inspect a loaded Policy class and emit lint findings."""

    # ── E003: invariants must not be empty ────────────────────────────────────
    try:
        invariants = policy_cls.invariants()
    except NotImplementedError:
        report("E003", "ERROR", "Policy.invariants() is not implemented")
        return
    except Exception as exc:
        report("E003", "ERROR", f"Policy.invariants() raised: {exc}")
        return

    if not invariants:
        report("E003", "ERROR", "Policy.invariants() returned an empty list")
        return

    # ── E001 / E002: label checks ─────────────────────────────────────────────
    seen_labels: set[str] = set()
    referenced_fields: set[str] = set()
    structural_errors = False

    for inv in invariants:
        label = getattr(inv, "label", None) or ""
        if not label:
            report("E001", "ERROR", "Invariant is missing a label (.named() not called)")
            structural_errors = True
        elif label in seen_labels:
            report("E002", "ERROR", f"Duplicate invariant label: {label!r}")
            structural_errors = True
        else:
            seen_labels.add(label)

        # Collect field references from the expression tree
        _collect_field_refs(inv, referenced_fields)

    # ── W005: validate() must not raise for reasons beyond E001-E003 ─────────
    # Only run if no structural errors were found (validate would raise for them too)
    if not structural_errors:
        try:
            policy_cls.validate()
        except Exception as exc:
            report("W005", "WARN", f"Policy.validate() raised unexpectedly: {exc}")

    # ── W001 / W002 / W003: Meta checks ──────────────────────────────────────
    meta = getattr(policy_cls, "Meta", None)
    if meta is None:
        report(
            "W001",
            "WARN",
            "No Meta class declared — version pinning and model validation unavailable",
        )
    else:
        if not getattr(meta, "intent_model", None):
            report("W002", "WARN", "Meta.intent_model not set — intent schema validation disabled")
        if not getattr(meta, "state_model", None):
            report("W003", "WARN", "Meta.state_model not set — state schema validation disabled")

    # ── W004: declared-but-unused fields ────────────────────────────────────
    declared_fields: dict[str, Any] = {}
    with contextlib.suppress(AttributeError, TypeError):
        declared_fields = policy_cls.fields()

    unused = sorted(set(declared_fields) - referenced_fields)
    for field_name in unused:
        report(
            "W004",
            "WARN",
            f"Field {field_name!r} is declared but not referenced by any invariant",
        )

    # ── W006: invariants without .explain() — operators cannot surface
    #    human-readable violation messages to callers ────────────────────────
    for inv in invariants:
        label = getattr(inv, "label", None) or ""
        explanation = getattr(inv, "explanation", None)
        if label and not explanation:
            report(
                "W006",
                "WARN",
                f"Invariant {label!r} has no .explain() message — "
                "callers will receive a generic violation string instead of a "
                "human-readable explanation. Add .explain('<message>') for better DX.",
            )


def _collect_field_refs(node: Any, out: set[str]) -> None:
    """Walk an expression tree and collect all field names referenced."""
    from pramanix.expressions import (
        ConstraintExpr,
        ExpressionNode,
        _BinOp,
        _BoolOp,
        _CmpOp,
        _FieldRef,
    )

    if node is None:
        return
    if isinstance(node, ConstraintExpr):
        _collect_field_refs(node.node, out)
        return
    if isinstance(node, ExpressionNode):
        _collect_field_refs(node.node, out)
        return
    if isinstance(node, _FieldRef):
        out.add(node.field.name)
        return
    if isinstance(node, _BinOp):
        _collect_field_refs(node.left, out)
        _collect_field_refs(node.right, out)
        return
    if isinstance(node, _CmpOp):
        _collect_field_refs(node.left, out)
        _collect_field_refs(node.right, out)
        return
    if isinstance(node, _BoolOp):
        for operand in node.operands:
            _collect_field_refs(operand, out)
        return


def _cmd_coverage(args: argparse.Namespace) -> int:
    """Run a JSONL test-case file through a policy and report coverage statistics.

    Each line of the JSONL file must be a JSON object with an ``intent`` key
    (required) and an optional ``state`` key.  The command constructs a real
    Guard (sync mode, no translator), runs every test case, and prints the
    ``PolicyCoverageReport`` produced by ``Guard.coverage_report()``.

    Exit codes:
        0 — all test cases processed; coverage threshold met (if --fail-under given)
        1 — coverage below --fail-under threshold
        2 — usage error (bad file, import failure, malformed JSONL)
    """
    import importlib.util
    import json as _json_mod
    import pathlib

    policy_path = pathlib.Path(args.policy)
    policy_var = getattr(args, "policy_var", "policy")
    suffix = policy_path.suffix.lower()

    # ── Load policy ───────────────────────────────────────────────────────────
    policy: Any = None
    if suffix in (".yaml", ".yml", ".toml"):
        try:
            from pramanix.natural_policy.yaml_loader import load_policy_file

            policy = load_policy_file(policy_path)
        except FileNotFoundError:
            print(f"ERROR: Policy file not found: {policy_path}", file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"ERROR: Failed to compile policy file: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            spec = importlib.util.spec_from_file_location("_pramanix_cov_policy", policy_path)
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

    # ── Load test cases from JSONL ────────────────────────────────────────────
    test_cases_path = pathlib.Path(args.test_cases)
    try:
        raw_lines = test_cases_path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        print(f"ERROR: Test cases file not found: {test_cases_path}", file=sys.stderr)
        return 2

    test_cases: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for line_no, line in enumerate(raw_lines, start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = _json_mod.loads(line)
        except _json_mod.JSONDecodeError as exc:
            print(
                f"ERROR: Line {line_no} of {test_cases_path} is not valid JSON: {exc}",
                file=sys.stderr,
            )
            return 2
        if not isinstance(obj, dict) or "intent" not in obj:
            print(
                f"ERROR: Line {line_no} must be a JSON object with an 'intent' key.",
                file=sys.stderr,
            )
            return 2
        intent = obj["intent"]
        state = obj.get("state", {})
        if not isinstance(intent, dict):
            print(f"ERROR: Line {line_no} 'intent' must be a JSON object.", file=sys.stderr)
            return 2
        test_cases.append((intent, state))

    if not test_cases:
        print("ERROR: No test cases found in JSONL file.", file=sys.stderr)
        return 2

    # ── Build guard and run all test cases ───────────────────────────────────
    try:
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        guard = Guard(policy=policy, config=GuardConfig(execution_mode="sync"))
    except Exception as exc:
        print(f"ERROR: Failed to construct Guard: {exc}", file=sys.stderr)
        return 2

    errors: list[str] = []
    for i, (intent, state) in enumerate(test_cases, start=1):
        try:
            guard.verify(intent=intent, state=state)
        except Exception as exc:
            errors.append(f"Test case {i}: {exc}")

    if errors:
        for msg in errors:
            print(f"WARNING: {msg}", file=sys.stderr)

    # ── Collect and emit coverage report ─────────────────────────────────────
    report = guard.coverage_report()
    as_json = getattr(args, "as_json", False)
    fail_under = getattr(args, "fail_under", None)

    invariants_hit = sorted(
        label for label, count in report.invariant_violations.items() if count > 0
    )
    invariants_missed = sorted(
        label
        for label in report.declared_invariants
        if report.invariant_violations.get(label, 0) == 0
    )

    if as_json:
        print(
            _json.dumps(
                {
                    "policy": str(policy_path),
                    "test_cases_file": str(test_cases_path),
                    "total_test_cases": len(test_cases),
                    "total_verifications": report.total_verifications,
                    "invariant_violations": report.invariant_violations,
                    "invariants_hit": invariants_hit,
                    "invariants_missed": invariants_missed,
                    "fields_seen": report.fields_seen,
                    "coverage_pct": report.coverage_pct,
                },
                indent=2,
            )
        )
    else:
        print(f"Policy:          {policy_path}")
        print(f"Test cases:      {len(test_cases)}")
        print(f"Verifications:   {report.total_verifications}")
        print(f"Coverage:        {report.coverage_pct:.1f}%")
        if invariants_hit:
            print(f"Invariants hit:  {', '.join(invariants_hit)}")
        if invariants_missed:
            print(f"Invariants missed: {', '.join(invariants_missed)}")

    if fail_under is not None and report.total_verifications < fail_under:
        if not as_json:
            print(
                f"\nFAIL: total_verifications ({report.total_verifications}) "
                f"< --fail-under ({fail_under})",
                file=sys.stderr,
            )
        return 1
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    """Render a ComplianceReport JSON file as text, JSON, or PDF.

    Reads a JSON document produced by ``ComplianceReport.to_json()`` and
    writes the report in the requested format.

    Exit codes:
        0 — success
        1 — render error (e.g. missing fpdf2 for PDF output)
        2 — usage / parse error (bad input, bad format)
    """
    import json as _json_mod
    import pathlib
    import sys as _sys

    input_path = getattr(args, "input", "-")
    output_format = getattr(args, "output_format", "text")
    output_file = getattr(args, "output_file", None)

    # ── Read input ────────────────────────────────────────────────────────────
    try:
        if input_path == "-":
            raw = _sys.stdin.read()
        else:
            raw = pathlib.Path(input_path).read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"ERROR: File not found: {input_path}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"ERROR: Cannot read {input_path}: {exc}", file=sys.stderr)
        return 2

    try:
        data = _json_mod.loads(raw)
    except _json_mod.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in {input_path}: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, dict):
        print("ERROR: ComplianceReport JSON must be a JSON object (dict).", file=sys.stderr)
        return 2

    # ── Reconstruct ComplianceReport ─────────────────────────────────────────
    try:
        from pramanix.helpers.compliance import ComplianceReport as _CR

        report = _CR(
            decision_id=str(data.get("decision_id", "")),
            decision_hash=str(data.get("decision_hash", "")),
            timestamp=str(data.get("timestamp", "")),
            verdict=str(data.get("verdict", "")),
            severity=str(data.get("severity", "")),
            policy_name=str(data.get("policy_name", "")),
            policy_version=str(data.get("policy_version", "")),
            violated_rules=tuple(data.get("violated_rules") or []),
            compliance_rationale=tuple(data.get("compliance_rationale") or []),
            regulatory_refs=tuple(data.get("regulatory_refs") or []),
            explanation=str(data.get("explanation", "")),
        )
    except Exception as exc:
        print(f"ERROR: Cannot deserialize ComplianceReport: {exc}", file=sys.stderr)
        return 2

    # ── Render ────────────────────────────────────────────────────────────────
    if output_format == "json":
        rendered_text = report.to_json()
        if output_file:
            try:
                pathlib.Path(output_file).write_text(rendered_text, encoding="utf-8")
            except OSError as exc:
                print(f"ERROR: Cannot write {output_file}: {exc}", file=sys.stderr)
                return 1
        else:
            print(rendered_text)
        return 0

    if output_format == "pdf":
        if not output_file:
            print(
                "ERROR: --out <FILE> is required for --format pdf "
                "(PDF is binary and cannot be written to stdout).",
                file=sys.stderr,
            )
            return 2
        try:
            pdf_bytes = report.to_pdf()
        except ImportError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        except Exception as exc:
            print(f"ERROR: PDF generation failed: {exc}", file=sys.stderr)
            return 1
        try:
            pathlib.Path(output_file).write_bytes(pdf_bytes)
            print(f"PDF written to {output_file}")
        except OSError as exc:
            print(f"ERROR: Cannot write {output_file}: {exc}", file=sys.stderr)
            return 1
        return 0

    # ── Text format (default) ─────────────────────────────────────────────────
    lines = [
        "=" * 60,
        "PRAMANIX COMPLIANCE REPORT",
        "=" * 60,
        f"Decision ID:     {report.decision_id}",
        f"Decision Hash:   {report.decision_hash}",
        f"Timestamp:       {report.timestamp}",
        f"Verdict:         {report.verdict}",
        f"Severity:        {report.severity}",
        f"Policy:          {report.policy_name} v{report.policy_version}",
    ]
    if report.violated_rules:
        lines.append(f"Violated Rules:  {', '.join(report.violated_rules)}")
    if report.explanation:
        lines.append(f"Explanation:     {report.explanation}")
    if report.compliance_rationale:
        lines.append("")
        lines.append("Compliance Rationale:")
        for item in report.compliance_rationale:
            lines.append(f"  - {item}")
    if report.regulatory_refs:
        lines.append("")
        lines.append("Regulatory References:")
        for ref in report.regulatory_refs:
            lines.append(f"  - {ref}")
    lines.append("=" * 60)
    rendered_text = "\n".join(lines)

    if output_file:
        try:
            pathlib.Path(output_file).write_text(rendered_text, encoding="utf-8")
        except OSError as exc:
            print(f"ERROR: Cannot write {output_file}: {exc}", file=sys.stderr)
            return 1
    else:
        print(rendered_text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
