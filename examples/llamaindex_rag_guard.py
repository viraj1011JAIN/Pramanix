#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""
llamaindex_rag_guard.py — PHI-access guard for a LlamaIndex RAG pipeline.

A LlamaIndex RAG pipeline over patient records, guarded by a HIPAA-compliant
PHI access policy. The policy formally verifies the requester's role,
purpose, and consent status before any query reaches the vector store.

Install: pip install 'pramanix[llamaindex]' llama-index-core

Run:
    python examples/llamaindex_rag_guard.py
"""
from __future__ import annotations

import asyncio
import json

from pydantic import BaseModel

from pramanix import E, Field, Guard, GuardConfig, Policy
from pramanix.integrations.llamaindex import PramanixFunctionTool, PramanixQueryEngineTool

# ── PHI Access Policy (HIPAA-aligned) ────────────────────────────────────────
#
# Access is allowed only when:
#   1. requester has a clinical role (is_clinician = True)
#   2. patient has given consent (consent_active = True)
#   3. access is for treatment, not research (purpose_code = 1)
#

_is_clinician   = Field("is_clinician",   bool,    "Bool")
_consent_active = Field("consent_active", bool,    "Bool")
_purpose_code   = Field("purpose_code",   int,     "Int")   # 1=treatment, 2=research


class PhiAccessPolicy(Policy):
    """HIPAA PHI access policy — formally verified with Z3."""

    class Meta:
        version = "1.0"

    @classmethod
    def fields(cls) -> dict:
        return {
            "is_clinician":   _is_clinician,
            "consent_active": _consent_active,
            "purpose_code":   _purpose_code,
        }

    @classmethod
    def invariants(cls) -> list:
        return [
            (E(_is_clinician) == True).named("must_be_clinician").explain(  # noqa: E712
                "PHI access requires clinical role — requester is_clinician={is_clinician}"
            ),
            (E(_consent_active) == True).named("consent_required").explain(  # noqa: E712
                "PHI access requires patient consent — consent_active={consent_active}"
            ),
            (E(_purpose_code) == 1).named("treatment_purpose_only").explain(
                "PHI access only for treatment (purpose_code=1) — got {purpose_code}"
            ),
        ]


# ── Intent schema ─────────────────────────────────────────────────────────────

class PhiAccessIntent(BaseModel):
    is_clinician:   bool
    consent_active: bool
    purpose_code:   int


# ── State (from auth context / patient record) ────────────────────────────────

def get_state() -> dict:
    return {"state_version": "1.0"}  # Policy has no state_model, so any state passes version check


# ── Mock query engine (replace with real VectorStoreIndex in production) ───────

class _PatientRecordEngine:
    """Stub query engine simulating a LlamaIndex VectorStoreIndex."""

    async def aquery(self, query: str) -> str:
        return f"[MOCK PATIENT RECORD] Query: {query} — Name: Jane Doe, DOB: 1985-04-12, Dx: T2DM"

    def query(self, query: str) -> str:
        return f"[MOCK] {query}"


# ── Guarded tools ─────────────────────────────────────────────────────────────

guard = Guard(PhiAccessPolicy, GuardConfig(execution_mode="sync", solver_timeout_ms=3_000))


# Tool 1: PHI function tool (direct data access)
def fetch_patient_summary(is_clinician: bool, consent_active: bool, purpose_code: int) -> str:
    """Fetch patient summary from EHR system."""
    return "Patient: Jane Doe | DOB: 1985-04-12 | Conditions: T2DM, Hypertension"


phi_function_tool = PramanixFunctionTool(
    fn=fetch_patient_summary,
    guard=guard,
    intent_schema=PhiAccessIntent,
    state_provider=get_state,
    name="fetch_patient_summary",
    description="Fetch patient PHI summary. Requires clinical role + consent + treatment purpose.",
)

# Tool 2: PHI query engine tool (RAG over patient records)
phi_rag_tool = PramanixQueryEngineTool(
    query_engine=_PatientRecordEngine(),
    guard=guard,
    intent_schema=PhiAccessIntent,
    state_provider=get_state,
    name="query_patient_records",
    description="Run RAG queries over patient records. Requires clinical role + consent + treatment purpose.",
)


# ── Demo ──────────────────────────────────────────────────────────────────────

async def demo() -> None:
    print("=== Pramanix LlamaIndex PHI Access Guard Demo ===\n")

    # Scenario A: ALLOW — clinician, with consent, for treatment
    intent_allow = json.dumps({"is_clinician": True, "consent_active": True, "purpose_code": 1})

    print("Scenario A: Clinician accessing for treatment (ALLOW)")
    result = await phi_function_tool.acall(intent_allow)
    print(f"  Content: {result.content}")
    print(f"  is_error: {result.is_error}\n")

    result = await phi_rag_tool.acall(intent_allow)
    print(f"  RAG result: {result.content[:80]}...\n")

    # Scenario B: BLOCK — researcher (purpose_code=2)
    intent_block = json.dumps({"is_clinician": True, "consent_active": True, "purpose_code": 2})

    print("Scenario B: Researcher access attempt (BLOCK)")
    result = await phi_function_tool.acall(intent_block)
    print(f"  Content: {result.content}")
    print(f"  is_error: {result.is_error}\n")

    # Scenario C: BLOCK — no consent
    intent_no_consent = json.dumps({"is_clinician": True, "consent_active": False, "purpose_code": 1})

    print("Scenario C: No patient consent (BLOCK)")
    result = await phi_rag_tool.acall(intent_no_consent)
    print(f"  Content: {result.content}\n")

    print("=== HIPAA-compliant access control enforced with Z3 proof ===")


if __name__ == "__main__":
    asyncio.run(demo())
