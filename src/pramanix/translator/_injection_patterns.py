# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
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
        r"ignore\s+(previous|above|all)\s+" r"(instructions?|prompts?|rules?|context)",
        "instruction_override",
    ),
    (r"ignore\s+all", "instruction_override"),
    (
        r"disregard\s+(?:(?:the|all)\s+)?(?:previous|above|any|all)\s+"
        r"(instructions?|rules?|guidelines?)",
        "instruction_override",
    ),
    (
        r"forget\s+(all|everything|previous|above|prior)\s+" r"(instructions?|context|rules?)",
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
    (r"system\s*:\s*[A-Za-z]", "fake_system_message"),
    (
        r'\{\s*["\']role["\']\s*:\s*["\']system["\']',
        "embedded_json_role",
    ),
    # ── Persona / capability overrides ─────────────────────────────────
    (r"override\s+safety", "safety_override"),
    (r"pretend\s+you\s+are", "persona_override"),
    (r"you\s+are\s+now\s+\w", "persona_override"),
    (
        r"you\s+are\s+(?:an?\s+)?(admin|root|superuser|god|oracle)\b",
        "role_escalation",
    ),
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
    (r"(?:do\s+not|don'?t|must\s+not|shall\s+not|will\s+not|cannot)\s+refuse", "refusal_bypass"),
    (
        r"you\s+(must|will|should|shall)\s+" r"(comply|obey|follow|execute)\s+",
        "compliance_coercion",
    ),
    # ── Prompt / system-prompt extraction ──────────────────────────────
    (
        r"(print|reveal|show|output|display|repeat)\s+"
        r"(?:(?:me|us|the\s+user)\s+)?(your\s+)?(system\s+)?"
        r"(prompt|instructions?|rules?|configuration|message)",
        "prompt_extraction",
    ),
    (
        r"what\s+(are|were)\s+your\s+" r"(instructions?|system\s+prompt|rules?)",
        "prompt_extraction",
    ),
    # ── RL / reward-hacking phrases ─────────────────────────────────────
    (r"reward\s+hack", "reward_hack"),
    (r"prompt\s+injection", "prompt_injection_keyword"),
    # ── Constraint / rule override phrases (previously missing) ─────────
    (
        r"discard\s+(?:(?:all|previous|prior|above|existing)\s+)+"
        r"(?:constraints?|rules?|policies|guidelines?|instructions?)"
        r"|discard\s+(?:constraints?|rules?|policies)",
        "constraint_override",
    ),
    (
        r"ignore\s+(?:all\s+)?(?:constraints?|policies|rules?|limits?)",
        "constraint_override",
    ),
    (
        r"override\s+(?:(?:all|the)\s+)?(?:constraints?|policies|rules?|limits?)",
        "constraint_override",
    ),
    (
        r"bypass\s+(?:(?:the|all)\s+)?(?:\w+\s+)?(?:policy|policies|filter|filters|constraints?|rules?|safety)",
        "policy_bypass",
    ),
    (
        r"forget\s+(?:the\s+)?(?:constraints?|rules?|policies|guidelines?)",
        "constraint_override",
    ),
    (
        r"no\s+(?:more\s+)?(?:restrictions?|constraints?|limits?|rules?|policies)",
        "constraint_override",
    ),
    # ── Context delimiter injection ─────────────────────────────────────
    (
        r"<<\s*(?:new\s+)?(?:system|instructions?|prompt)\s*>>",
        "context_delimiter",
    ),
    (
        r"(?:---|\*{3}|={3})\s*(?:end\s+(?:of\s+)?(?:user\s+)?input|system|instructions?)\s*(?:---|\*{3}|={3})?",
        "context_delimiter",
    ),
    (
        r"#\s*(?:system|instructions?|prompt)\s*:",
        "context_delimiter",
    ),
    (
        r"\[\s*system\s*message\s*\]|\[\s*admin\s*\]",
        "context_delimiter",
    ),
    # ── Context poisoning / indirect compliance coercion ─────────────────
    (
        r"there\s+(?:are|is)\s+no\s+(?:restrictions?|policies|limits?|rules?|constraints?)\s+(?:here|in\s+this|for\s+this)",
        "context_poisoning",
    ),
    (
        r"(?:new|updated|latest)\s+(?:system\s+)?(?:system|configuration|settings?)\s+(?:says?|states?|allows?)\s*:",
        "context_poisoning",
    ),
    (
        r"admin\s*(?:message|alert|notice|override|command)\s*:",
        "context_poisoning",
    ),
    # ── Future-instruction injection ──────────────────────────────────
    (
        r"from\s+(?:now\s+on|this\s+(?:point|moment)|here(?:\s+forward)?)\s*,?\s+(?:you|ignore|treat|act|follow)",
        "future_instruction",
    ),
    (
        r"(?:going|moving)\s+forward\s*,?\s*(?:always\s+)?(?:ignore|bypass|skip|treat\s+every)",
        "future_instruction",
    ),
    # ── Paraphrase variants of instruction overrides ─────────────────────
    (
        r"(?:set|put|push|leave)\s+aside\s+(?:(?:all|the)\s+)?(?:(?:previous|above|prior|your|all)\s+)?"
        r"(?:instructions?|rules?|context|constraints?|guidelines?|policies)",
        "instruction_override",
    ),
    (
        r"(?:starting|beginning)\s+(?:fresh|over|again|anew)\s*[:,.]?\s*(?:ignore|forget|disregard)",
        "instruction_override",
    ),
    (
        r"new\s+(?:task|objective|goal|mission)\s*:\s*(?:ignore|forget|bypass|override|disregard)",
        "instruction_override",
    ),
    # ── Tool / function spec injection signals ───────────────────────────
    (
        r'"(?:tool|function_?name|name)"\s*:\s*"(?:exec(?:ute)?|shell|system|cmd|run|eval|os\.)"|'
        r"'(?:tool|function_?name|name)'\s*:\s*'(?:exec(?:ute)?|shell|system|cmd|run|eval|os\.)'",
        "tool_spec_injection",
    ),
    (
        r"<\s*tool_?(?:call|use|invoke)\b|<\s*function_?call\b",
        "tool_spec_injection",
    ),
    # ── Indirect prompt extraction ────────────────────────────────────────
    (
        r"(?:summarize|echo|repeat|recite|write\s+out)\s+your\s+(?:\w+\s+)?"
        r"(?:system\s+)?(?:message|prompt|initialization|context|training)",
        "prompt_extraction",
    ),
    (
        r"what\s+(?:does?\s+your|were\s+you|were\s+your)\s+"
        r"(?:initial|original|first|base)\s+(?:instructions?|prompt|rules?|message)",
        "prompt_extraction",
    ),
]
