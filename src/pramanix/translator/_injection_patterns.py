# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Canonical injection-pattern registry shared by all detection layers.

Single source of truth imported by both:
  - :mod:`pramanix.translator._sanitise`  (pre-LLM sanitisation)
  - :mod:`pramanix.translator.injection_filter`  (InjectionFilter scorer)

Keeping patterns in one file prevents drift between the two defenders.
"""
from __future__ import annotations

from typing import Final

# List of (regex_pattern, label) tuples — CASE-INSENSITIVE at compile time.
# Coverage: GPT-*, Claude, Llama 2/3, Mistral/ChatML, Phi-3, open-source
# jailbreak playbooks as of 2026-04.
INJECTION_PATTERNS: Final[list[tuple[str, str]]] = [
    # ── Classic instruction overrides ──────────────────────────────────
    (
        r"ignore\s+(previous|above|all)\s+"
        r"(instructions?|prompts?|rules?|context)",
        "instruction_override",
    ),
    (r"ignore\s+all", "instruction_override"),
    (
        r"disregard\s+(?:all\s+)?(?:previous|above|any|all)\s+"
        r"(instructions?|rules?|guidelines?)",
        "instruction_override",
    ),
    (
        r"forget\s+(all|everything|previous|above|prior)\s+"
        r"(instructions?|context|rules?)",
        "instruction_override",
    ),
    # ── Jailbreak trigger words ─────────────────────────────────────────
    (r"\bjailbreak\b", "jailbreak_keyword"),
    (r"\bdo\s+anything\s+now\b|\bdan\s+mode\b|\bdan\s+jailbreak\b", "dan_jailbreak"),
    (r"developer\s+mode", "developer_mode"),
    (r"god\s+mode", "god_mode"),
    # ── Open-source model instruction tokens ───────────────────────────
    (r"\[INST\]", "llama2_inst_token"),
    (r"<<SYS>>", "llama2_sys_block"),
    (r"<\|im_start\|>", "chatml_token"),
    (r"<\|im_end\|>", "chatml_end_token"),
    (r"<\|eot_id\|>", "llama3_eot_token"),
    (r"<\|begin_of_text\|>", "llama3_bos_token"),
    (r"<\|system\|>", "chatml_system_token"),
    # ── Embedded role escalation ────────────────────────────────────────
    (r"system\s*:\s*(?=[A-Za-z])", "fake_system_message"),
    (
        r'\{\s*["\']role["\']\s*:\s*["\']system["\']',
        "embedded_json_role",
    ),
    # ── Persona / capability overrides ─────────────────────────────────
    (r"override\s+safety", "safety_override"),
    (r"pretend\s+you\s+are", "persona_override"),
    (r"you\s+are\s+now\s+(?!going\s+to|able)", "persona_override"),
    (
        r"act\s+as\s+(an?\s+)?"
        r"(admin|root|superuser|god|oracle|unrestricted"
        r"|assistant\s+without\s+(restrictions?|limits?|guidelines?))",
        "role_escalation",
    ),
    (
        r"unlock.{0,20}(mode|features?|capability|restriction)",
        "unlock_mode",
    ),
    # ── Markdown / structured instruction injection ─────────────────────
    (
        r"\\n\\n\s*#{1,3}\s*(instruction|system|prompt|task)",
        "markdown_injection",
    ),
    # ── Refusal bypass ──────────────────────────────────────────────────
    (r"(do\s+not|don'?t)\s+refuse", "refusal_bypass"),
    (
        r"you\s+(must|will|should|shall)\s+"
        r"(comply|obey|follow|execute)\s+",
        "compliance_coercion",
    ),
    # ── Prompt / system-prompt extraction ──────────────────────────────
    (
        r"(print|reveal|show|output|display|repeat)\s+"
        r"(your\s+)?(system\s+)?"
        r"(prompt|instructions?|rules?|configuration)",
        "prompt_extraction",
    ),
    (
        r"what\s+(are|were)\s+your\s+"
        r"(instructions?|system\s+prompt|rules?)",
        "prompt_extraction",
    ),
    # ── RL / reward-hacking phrases ─────────────────────────────────────
    (r"reward\s+hack", "reward_hack"),
    (r"prompt\s+injection", "prompt_injection_keyword"),
]
