# Pramanix — Architecture

> This document will be expanded as implementation progresses.
> For the complete design specification, see [Blueprint.md](../Blueprint.md).

## Overview

Pramanix is a deterministic neuro-symbolic guardrail SDK that places a
mathematically verified execution firewall between AI agent intent and
real-world consequences.

## Two-Phase Execution Model

1. **Intent Extraction** — Map input to a typed, validated Pydantic model.
   LLM involvement is optional (Neuro-Symbolic mode only).
2. **Formal Safety Verification** — Z3 SMT solver proves all policy invariants
   are satisfied. Zero LLM involvement.

## Key Design Decisions

| Decision | Rationale | Reference |
|---|---|---|
| Z3 SMT for verification | Mathematical proof, not confidence score | Blueprint §1 |
| Fail-safe default | Any error → BLOCK, never ALLOW | Blueprint §2 |
| Python DSL (not YAML/Rego) | IDE autocomplete, type checking, static analysis | Blueprint §2 |
| `model_dump()` before process boundary | Pydantic models are not safely picklable | Blueprint §15 |
| Worker warmup with dummy Z3 solve | Eliminates cold-start JIT spike | Blueprint §15 |
| `assert_and_track` (not `add`) | Required for unsat core attribution | Blueprint §14 |
| Alpine Linux banned | Z3 requires glibc; musl causes segfaults | Blueprint §48 |

## Module Map

See Blueprint §9 for the complete directory structure and Blueprint §10–§20
for detailed module specifications.
