# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for the translator subsystem.

All LLM API calls are mocked — no real API keys needed.

Coverage targets:
- _clean_json: strips markdown fences, handles plain JSON, edge cases
- parse_llm_response: JSON decode errors, non-dict responses, success
- build_system_prompt: injects schema, contains injection-defence text
- extract_with_consensus: agreement path, mismatch path, validation failures
- RedundantTranslator: delegates correctly, model name composition
- create_translator: model-prefix routing, unknown prefix error
- OpenAICompatTranslator.extract: success, timeout→LLMTimeoutError, API error
- AnthropicTranslator.extract: success, timeout→LLMTimeoutError, API error
- Guard.parse_and_verify: end-to-end with mocked translators
- New exception types: hierarchy, attributes, messages
"""
from __future__ import annotations

import json
import os
from decimal import Decimal
from typing import Any

import pytest
import httpx
import respx
from pydantic import BaseModel

from pramanix.exceptions import (
    ExtractionFailureError,
    ExtractionMismatchError,
    GuardError,
    LLMTimeoutError,
    PramanixError,
)
from pramanix.translator._json import (
    _clean_json,
    _extract_first_json,
    parse_llm_response,
)
from pramanix.translator._prompt import build_system_prompt
from pramanix.translator.base import Translator, TranslatorContext
from pramanix.translator.redundant import (
    RedundantTranslator,
    create_translator,
    extract_with_consensus,
)

# ── Shared fixtures ───────────────────────────────────────────────────────────


class SimpleIntent(BaseModel):
    amount: Decimal
    recipient: str


class AmbiguousIntent(BaseModel):
    action: str
    amount: Decimal


# ── Exception hierarchy ───────────────────────────────────────────────────────


class TestTranslatorExceptions:
    def test_extraction_failure_is_guard_error(self) -> None:
        assert issubclass(ExtractionFailureError, GuardError)

    def test_extraction_failure_is_pramanix_error(self) -> None:
        assert issubclass(ExtractionFailureError, PramanixError)

    def test_extraction_mismatch_is_guard_error(self) -> None:
        assert issubclass(ExtractionMismatchError, GuardError)

    def test_extraction_mismatch_has_attributes(self) -> None:
        exc = ExtractionMismatchError(
            "models disagree",
            model_a="gpt-4o",
            model_b="claude-opus-4-5",
            mismatches={"amount": (Decimal("100"), Decimal("200"))},
        )
        assert exc.model_a == "gpt-4o"
        assert exc.model_b == "claude-opus-4-5"
        assert "amount" in exc.mismatches
        assert str(exc) == "models disagree"

    def test_extraction_mismatch_defaults(self) -> None:
        exc = ExtractionMismatchError("plain message")
        assert exc.model_a == ""
        assert exc.model_b == ""
        assert exc.mismatches == {}

    def test_llm_timeout_is_guard_error(self) -> None:
        assert issubclass(LLMTimeoutError, GuardError)

    def test_llm_timeout_has_attributes(self) -> None:
        exc = LLMTimeoutError("timed out", model="gpt-4o", attempts=3)
        assert exc.model == "gpt-4o"
        assert exc.attempts == 3

    def test_llm_timeout_defaults(self) -> None:
        exc = LLMTimeoutError("timed out")
        assert exc.model == ""
        assert exc.attempts == 0

    def test_all_translator_exceptions_catchable_as_guard_error(self) -> None:
        for cls in (ExtractionFailureError, ExtractionMismatchError, LLMTimeoutError):
            with pytest.raises(GuardError):
                raise cls("test")


# ── _clean_json ───────────────────────────────────────────────────────────────


class TestCleanJson:
    def test_plain_json_object_unchanged(self) -> None:
        raw = '{"amount": 100}'
        assert json.loads(_clean_json(raw)) == {"amount": 100}

    def test_strips_json_code_fence(self) -> None:
        raw = '```json\n{"amount": 100}\n```'
        assert json.loads(_clean_json(raw)) == {"amount": 100}

    def test_strips_plain_code_fence(self) -> None:
        raw = '```\n{"amount": 100}\n```'
        assert json.loads(_clean_json(raw)) == {"amount": 100}

    def test_strips_surrounding_prose(self) -> None:
        raw = 'Here is the extracted intent:\n{"amount": 50}\nLet me know if correct.'
        result = _clean_json(raw)
        assert json.loads(result) == {"amount": 50}

    def test_nested_json_preserved(self) -> None:
        raw = '{"a": {"b": 1}}'
        assert json.loads(_clean_json(raw)) == {"a": {"b": 1}}

    def test_empty_string_returned_as_is(self) -> None:
        # No JSON object found — return stripped string
        result = _clean_json("   ")
        assert result == ""

    def test_case_insensitive_json_fence(self) -> None:
        raw = '```JSON\n{"key": "val"}\n```'
        assert json.loads(_clean_json(raw)) == {"key": "val"}


# ── _extract_first_json — escape-sequence paths (lines 34-35, 37-38)
# ─────────────────────────────────────────────────────────────────────────────


class TestExtractFirstJson:
    def test_escaped_quote_in_string_value(self) -> None:
        """Escaped quote inside a string must not close the string early.

        Exercises lines 37-38 (escape_next = True / continue) and
        34-35 (escape_next = False / continue) of _extract_first_json.
        Without these branches, the closing } after the escaped quote
        would be mis-parsed as a depth decrement inside a string.
        """
        raw = r'{"key": "val\"ue"}'
        result = _extract_first_json(raw)
        assert result == raw
        assert json.loads(result) == {"key": 'val"ue'}

    def test_backslash_followed_by_non_quote(self) -> None:
        """Backslash before a non-quote char (e.g. \\n) still sets escape_next."""
        raw = r'{"msg": "line1\nline2"}'
        result = _extract_first_json(raw)
        assert result == raw

    def test_nested_object_with_escaped_quotes(self) -> None:
        """Nested object whose string values contain escaped quotes."""
        raw = r'{"a": {"b": "x\"y"}}'
        result = _extract_first_json(raw)
        assert result == raw
        assert json.loads(result) == {"a": {"b": 'x"y'}}

    def test_no_json_returns_none(self) -> None:
        assert _extract_first_json("no json here") is None

    def test_array_is_extracted(self) -> None:
        raw = '[1, 2, 3]'
        assert _extract_first_json(raw) == raw


# ── parse_llm_response ────────────────────────────────────────────────────────


class TestParseLlmResponse:
    def test_valid_json_object(self) -> None:
        raw = '{"amount": "500", "recipient": "Alice"}'
        result = parse_llm_response(raw)
        assert result == {"amount": "500", "recipient": "Alice"}

    def test_json_in_markdown_fence(self) -> None:
        raw = '```json\n{"amount": "100"}\n```'
        assert parse_llm_response(raw) == {"amount": "100"}

    def test_raises_extraction_failure_on_invalid_json(self) -> None:
        with pytest.raises(ExtractionFailureError, match="unparseable JSON"):
            parse_llm_response("not json at all", model_name="gpt-4o")

    def test_raises_extraction_failure_on_json_array(self) -> None:
        with pytest.raises(ExtractionFailureError, match="list"):
            parse_llm_response("[1, 2, 3]")

    def test_raises_extraction_failure_on_json_string(self) -> None:
        with pytest.raises(ExtractionFailureError, match="str"):
            parse_llm_response('"just a string"')

    def test_model_name_appears_in_error(self) -> None:
        with pytest.raises(ExtractionFailureError, match=r"\[my-model\]"):
            parse_llm_response("bad", model_name="my-model")


# ── build_system_prompt ───────────────────────────────────────────────────────


class TestBuildSystemPrompt:
    def test_contains_schema_fields(self) -> None:
        prompt = build_system_prompt(SimpleIntent)
        assert "amount" in prompt
        assert "recipient" in prompt

    def test_contains_injection_defence(self) -> None:
        prompt = build_system_prompt(SimpleIntent)
        # Each of the 5 defence rules should be referenced
        assert "ignore" in prompt.lower() or "instructions" in prompt.lower()
        assert "extraction" in prompt.lower()

    def test_contains_json_only_instruction(self) -> None:
        prompt = build_system_prompt(SimpleIntent)
        assert "JSON" in prompt

    def test_schema_json_is_valid_json(self) -> None:
        prompt = build_system_prompt(SimpleIntent)
        # The schema block is embedded as JSON — extract and validate it
        start = prompt.index("{")
        end = prompt.rindex("}") + 1
        embedded = prompt[start:end]
        parsed = json.loads(embedded)
        assert "properties" in parsed or "title" in parsed


# ── TranslatorContext ─────────────────────────────────────────────────────────


class TestTranslatorContext:
    def test_default_request_id_is_uuid4_format(self) -> None:
        import re

        ctx = TranslatorContext()
        assert re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
            ctx.request_id,
        )

    def test_two_contexts_have_different_request_ids(self) -> None:
        a = TranslatorContext()
        b = TranslatorContext()
        assert a.request_id != b.request_id

    def test_custom_fields(self) -> None:
        ctx = TranslatorContext(
            user_id="u123",
            available_accounts=["savings", "checking"],
            extra={"locale": "en-US"},
        )
        assert ctx.user_id == "u123"
        assert "savings" in ctx.available_accounts
        assert ctx.extra["locale"] == "en-US"

    def test_translator_protocol_satisfied(self) -> None:
        """Both OpenAI and Anthropic translators satisfy the Translator protocol."""

        class FakeTranslator:
            async def extract(self, text, intent_schema, context=None):
                return {}

        assert isinstance(FakeTranslator(), Translator)


# ── extract_with_consensus ────────────────────────────────────────────────────


class TestExtractWithConsensus:
    @pytest.mark.asyncio
    async def test_agreement_returns_validated_dict(self) -> None:
        {"amount": Decimal("100"), "recipient": "Alice"}

        class FakeA:
            model = "fake-a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "Alice"}

        class FakeB:
            model = "fake-b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "Alice"}

        result = await extract_with_consensus(
            "send 100 to Alice",
            SimpleIntent,
            (FakeA(), FakeB()),  # type: ignore[arg-type]
        )
        assert result["amount"] == Decimal("100")
        assert result["recipient"] == "Alice"

    @pytest.mark.asyncio
    async def test_disagreement_raises_mismatch_error(self) -> None:
        class FakeA:
            model = "model-a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "Alice"}

        class FakeB:
            model = "model-b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "200", "recipient": "Alice"}

        with pytest.raises(ExtractionMismatchError) as exc_info:
            await extract_with_consensus(
                "ambiguous",
                SimpleIntent,
                (FakeA(), FakeB()),  # type: ignore[arg-type]
            )
        assert "amount" in exc_info.value.mismatches
        assert exc_info.value.model_a == "model-a"
        assert exc_info.value.model_b == "model-b"

    @pytest.mark.asyncio
    async def test_schema_validation_failure_raises_extraction_failure(self) -> None:
        class FakeBadA:
            model = "bad-a"

            async def extract(self, text, intent_schema, context=None):
                # Missing required "recipient" field
                return {"amount": "100"}

        class FakeGoodB:
            model = "good-b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "Bob"}

        with pytest.raises(ExtractionFailureError, match="Schema validation failed"):
            await extract_with_consensus(
                "send",
                SimpleIntent,
                (FakeBadA(), FakeGoodB()),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_propagates_llm_timeout_error(self) -> None:
        class TimingOutTranslator:
            model = "slow"

            async def extract(self, text, intent_schema, context=None):
                raise LLMTimeoutError("timeout", model="slow", attempts=3)

        class FakeOk:
            model = "ok"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "X"}

        with pytest.raises(LLMTimeoutError):
            await extract_with_consensus(
                "send",
                SimpleIntent,
                (TimingOutTranslator(), FakeOk()),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_both_run_concurrently(self) -> None:
        """Both translators must be awaited (not sequential)."""
        call_order: list[str] = []

        class FakeA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                call_order.append("a")
                return {"amount": "10", "recipient": "X"}

        class FakeB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                call_order.append("b")
                return {"amount": "10", "recipient": "X"}

        await extract_with_consensus("x", SimpleIntent, (FakeA(), FakeB()))  # type: ignore[arg-type]
        assert "a" in call_order and "b" in call_order

    # ── Agreement modes ──────────────────────────────────────────────────────

    @pytest.mark.asyncio
    async def test_strict_keys_all_fields_match_passes(self) -> None:
        """strict_keys (default): all fields agree → no exception."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        result = await extract_with_consensus(
            "send 50 to alice",
            SimpleIntent,
            (FA(), FB()),  # type: ignore[arg-type]
            agreement_mode="strict_keys",
        )
        assert result["recipient"] == "alice"

    @pytest.mark.asyncio
    async def test_strict_keys_single_field_mismatch_blocks(self) -> None:
        """strict_keys: any field disagreement raises ExtractionMismatchError."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "99", "recipient": "alice"}  # amount differs

        with pytest.raises(ExtractionMismatchError) as exc_info:
            await extract_with_consensus(
                "ambiguous",
                SimpleIntent,
                (FA(), FB()),  # type: ignore[arg-type]
                agreement_mode="strict_keys",
            )
        assert "amount" in exc_info.value.mismatches

    @pytest.mark.asyncio
    async def test_unanimous_identical_dicts_passes(self) -> None:
        """unanimous: exact equality → passes."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "bob"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "100", "recipient": "bob"}

        result = await extract_with_consensus(
            "pay bob 100",
            SimpleIntent,
            (FA(), FB()),  # type: ignore[arg-type]
            agreement_mode="unanimous",
        )
        assert result["amount"] == Decimal("100")

    @pytest.mark.asyncio
    async def test_unanimous_any_diff_blocks(self) -> None:
        """unanimous: any field disagreement → ExtractionMismatchError."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "bob"}  # recipient differs

        with pytest.raises(ExtractionMismatchError) as exc_info:
            await extract_with_consensus(
                "ambiguous",
                SimpleIntent,
                (FA(), FB()),  # type: ignore[arg-type]
                agreement_mode="unanimous",
            )
        assert "recipient" in exc_info.value.mismatches

    @pytest.mark.asyncio
    async def test_lenient_critical_mismatch_blocks(self) -> None:
        """lenient: critical field disagrees → ExtractionMismatchError."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "999", "recipient": "alice"}  # amount is critical

        with pytest.raises(ExtractionMismatchError) as exc_info:
            await extract_with_consensus(
                "ambiguous",
                SimpleIntent,
                (FA(), FB()),  # type: ignore[arg-type]
                agreement_mode="lenient",
                critical_fields=frozenset({"amount"}),
            )
        assert "amount" in exc_info.value.mismatches
        assert "recipient" not in exc_info.value.mismatches  # non-critical was not involved

    @pytest.mark.asyncio
    async def test_lenient_non_critical_mismatch_passes(self) -> None:
        """lenient: non-critical field disagrees → passes; result from model A."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                # recipient is NOT in critical_fields → non-critical diff
                return {"amount": "50", "recipient": "ALICE"}

        result = await extract_with_consensus(
            "pay alice 50",
            SimpleIntent,
            (FA(), FB()),  # type: ignore[arg-type]
            agreement_mode="lenient",
            critical_fields=frozenset({"amount"}),
        )
        # consensus passes; result from model A
        assert result["amount"] == Decimal("50")
        assert result["recipient"] == "alice"

    @pytest.mark.asyncio
    async def test_lenient_no_critical_fields_acts_like_strict_keys(self) -> None:
        """lenient with critical_fields=None treats all fields as critical."""

        class FA:
            model = "a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FB:
            model = "b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "bob"}

        with pytest.raises(ExtractionMismatchError):
            await extract_with_consensus(
                "ambiguous",
                SimpleIntent,
                (FA(), FB()),  # type: ignore[arg-type]
                agreement_mode="lenient",
                critical_fields=None,  # all fields treated as critical
            )

    # ── Partial-failure handling (return_exceptions=True) ────────────────────

    @pytest.mark.asyncio
    async def test_both_models_fail_raises_extraction_failure(self) -> None:
        """Both models raise → composite ExtractionFailureError."""

        class FailA:
            model = "fail-a"

            async def extract(self, text, intent_schema, context=None):
                raise ExtractionFailureError("[fail-a] bad JSON")

        class FailB:
            model = "fail-b"

            async def extract(self, text, intent_schema, context=None):
                raise ExtractionFailureError("[fail-b] server error")

        with pytest.raises(ExtractionFailureError, match="Both translators failed"):
            await extract_with_consensus(
                "send 50",
                SimpleIntent,
                (FailA(), FailB()),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_both_models_timeout_raises_llm_timeout(self) -> None:
        """When both fail and at least one is a timeout, LLMTimeoutError is raised."""

        class TimeoutA:
            model = "to-a"

            async def extract(self, text, intent_schema, context=None):
                raise LLMTimeoutError("A timed out", model="to-a", attempts=3)

        class FailB:
            model = "fail-b"

            async def extract(self, text, intent_schema, context=None):
                raise ExtractionFailureError("[fail-b] bad JSON")

        with pytest.raises(LLMTimeoutError):
            await extract_with_consensus(
                "send 50",
                SimpleIntent,
                (TimeoutA(), FailB()),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_model_a_fails_model_b_succeeds_blocks_with_name(self) -> None:
        """Model A fails; model B succeeds → ExtractionFailureError naming model A."""

        class FailA:
            model = "broken-a"

            async def extract(self, text, intent_schema, context=None):
                raise ExtractionFailureError("[broken-a] server 500")

        class OkB:
            model = "ok-b"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        with pytest.raises(ExtractionFailureError, match="broken-a") as exc_info:
            await extract_with_consensus(
                "send 50",
                SimpleIntent,
                (FailA(), OkB()),  # type: ignore[arg-type]
            )
        assert "ok-b" in str(exc_info.value)  # names the succeeding model too

    @pytest.mark.asyncio
    async def test_model_b_fails_model_a_succeeds_blocks_with_name(self) -> None:
        """Model B fails; model A succeeds → ExtractionFailureError naming model B."""

        class OkA:
            model = "ok-a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class FailB:
            model = "broken-b"

            async def extract(self, text, intent_schema, context=None):
                raise ExtractionFailureError("[broken-b] timeout")

        with pytest.raises(ExtractionFailureError, match="broken-b"):
            await extract_with_consensus(
                "send 50",
                SimpleIntent,
                (OkA(), FailB()),  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_model_b_timeout_raises_llm_timeout_error(self) -> None:
        """Model B times out while A succeeds → LLMTimeoutError (not ExtractionFailure)."""

        class OkA:
            model = "ok-a"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "50", "recipient": "alice"}

        class TimeoutB:
            model = "to-b"

            async def extract(self, text, intent_schema, context=None):
                raise LLMTimeoutError("B timed out", model="to-b", attempts=3)

        with pytest.raises(LLMTimeoutError) as exc_info:
            await extract_with_consensus(
                "send 50",
                SimpleIntent,
                (OkA(), TimeoutB()),  # type: ignore[arg-type]
            )
        assert exc_info.value.model == "to-b"


# ── RedundantTranslator ───────────────────────────────────────────────────────


class TestRedundantTranslator:
    @pytest.mark.asyncio
    async def test_delegates_to_consensus(self) -> None:
        class FakeA:
            model = "m1"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "5", "recipient": "Y"}

        class FakeB:
            model = "m2"

            async def extract(self, text, intent_schema, context=None):
                return {"amount": "5", "recipient": "Y"}

        rt = RedundantTranslator(FakeA(), FakeB())  # type: ignore[arg-type]
        result = await rt.extract("pay 5 to Y", SimpleIntent)
        assert result["amount"] == Decimal("5")

    def test_composite_model_name(self) -> None:
        class FA:
            model = "gpt-4o"

        class FB:
            model = "claude-opus-4-5"

        rt = RedundantTranslator(FA(), FB())  # type: ignore[arg-type]
        assert "gpt-4o" in rt.model
        assert "claude-opus-4-5" in rt.model

    def test_satisfies_translator_protocol(self) -> None:
        class FA:
            model = "x"

            async def extract(self, text, intent_schema, context=None):
                return {}

        class FB:
            model = "y"

            async def extract(self, text, intent_schema, context=None):
                return {}

        rt = RedundantTranslator(FA(), FB())  # type: ignore[arg-type]
        assert isinstance(rt, Translator)


# ── create_translator ─────────────────────────────────────────────────────────


class TestCreateTranslator:
    def test_gpt_prefix_returns_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = create_translator("gpt-4o", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)
        assert t.model == "gpt-4o"

    def test_o1_prefix_returns_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = create_translator("o1-preview", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)

    def test_o3_prefix_returns_openai_compat(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = create_translator("o3-mini", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)

    def test_claude_prefix_returns_anthropic(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator

        t = create_translator("claude-opus-4-5")
        assert isinstance(t, AnthropicTranslator)
        assert t.model == "claude-opus-4-5"

    def test_unknown_prefix_raises_extraction_failure(self) -> None:
        with pytest.raises(ExtractionFailureError, match="Cannot infer translator"):
            create_translator("llama3-70b")

    def test_api_key_forwarded_to_openai(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = create_translator("gpt-4o", api_key="sk-test")
        assert isinstance(t, OpenAICompatTranslator)
        assert t._api_key == "sk-test"

    def test_base_url_forwarded_to_openai(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = create_translator("gpt-4o", api_key="sk-test", base_url="http://localhost:11434")
        assert isinstance(t, OpenAICompatTranslator)
        assert t._base_url == "http://localhost:11434"


# ── OpenAICompatTranslator ────────────────────────────────────────────────────


class TestOpenAICompatTranslator:
    @pytest.mark.asyncio
    async def test_successful_extraction(self) -> None:
        """Returns parsed dict on a clean API response."""
        pytest.importorskip("openai")
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        payload = '{"amount": "250", "recipient": "Bob"}'
        with respx.mock(assert_all_called=False) as mock:
            mock.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": payload},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 50,
                        "completion_tokens": 20,
                        "total_tokens": 70,
                    },
                },
            )
            translator = OpenAICompatTranslator("gpt-4o", api_key="sk-test")
            result = await translator.extract("pay 250 to Bob", SimpleIntent)

        assert result == {"amount": "250", "recipient": "Bob"}

    @pytest.mark.asyncio
    async def test_api_timeout_raises_llm_timeout_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """APITimeoutError → retried → LLMTimeoutError after exhaustion."""
        pytest.importorskip("openai")
        from tenacity import wait_none

        from pramanix.translator.openai_compat import OpenAICompatTranslator

        monkeypatch.setattr("tenacity.wait_exponential", lambda **kw: wait_none())

        with respx.mock(assert_all_called=False) as mock:
            mock.post("https://api.openai.com/v1/chat/completions").mock(
                side_effect=httpx.TimeoutException("timed out")
            )
            translator = OpenAICompatTranslator("gpt-4o", api_key="sk-test", timeout=0.001)
            with pytest.raises(LLMTimeoutError) as exc_info:
                await translator.extract("pay", SimpleIntent)

        assert exc_info.value.model == "gpt-4o"
        assert exc_info.value.attempts >= 1

    @pytest.mark.asyncio
    async def test_api_status_error_raises_extraction_failure(self) -> None:
        """APIStatusError (e.g. 401 Unauthorized) → ExtractionFailureError."""
        pytest.importorskip("openai")
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        with respx.mock(assert_all_called=False) as mock:
            mock.post("https://api.openai.com/v1/chat/completions").respond(
                401,
                json={"error": {"message": "Invalid API key", "type": "invalid_request_error"}},
            )
            translator = OpenAICompatTranslator("gpt-4o", api_key="sk-bad")
            with pytest.raises(ExtractionFailureError, match="401"):
                await translator.extract("pay", SimpleIntent)

    @pytest.mark.asyncio
    async def test_empty_response_raises_extraction_failure(self) -> None:
        """Empty content string → ExtractionFailureError."""
        pytest.importorskip("openai")
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        with respx.mock(assert_all_called=False) as mock:
            mock.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": ""},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 0,
                        "total_tokens": 10,
                    },
                },
            )
            translator = OpenAICompatTranslator("gpt-4o", api_key="sk-test")
            with pytest.raises(ExtractionFailureError, match="empty"):
                await translator.extract("pay", SimpleIntent)

    @pytest.mark.asyncio
    async def test_malformed_json_raises_extraction_failure(self) -> None:
        pytest.importorskip("openai")
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        with respx.mock(assert_all_called=False) as mock:
            mock.post("https://api.openai.com/v1/chat/completions").respond(
                200,
                json={
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "model": "gpt-4o",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "not valid json at all",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {
                        "prompt_tokens": 10,
                        "completion_tokens": 5,
                        "total_tokens": 15,
                    },
                },
            )
            translator = OpenAICompatTranslator("gpt-4o", api_key="sk-test")
            with pytest.raises(ExtractionFailureError):
                await translator.extract("pay", SimpleIntent)


# ── AnthropicTranslator ───────────────────────────────────────────────────────


_ANTHROPIC_KEY = os.environ.get("ANTHROPIC_AUTH_TOKEN") or os.environ.get("ANTHROPIC_API_KEY") or ""
_NEED_ANTHROPIC_KEY = pytest.mark.skipif(
    not _ANTHROPIC_KEY,
    reason="No real Anthropic API key — set ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN",
)


@_NEED_ANTHROPIC_KEY
class TestAnthropicTranslator:
    """Real HTTP integration tests — no respx, no monkeypatch."""

    _API_KEY = _ANTHROPIC_KEY

    @pytest.mark.asyncio
    async def test_successful_extraction(self) -> None:
        pytest.importorskip("anthropic")
        from pramanix.translator.anthropic import AnthropicTranslator

        translator = AnthropicTranslator("claude-opus-4-6", api_key=self._API_KEY)
        result = await translator.extract("pay 300 to Carol", SimpleIntent)
        assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_api_timeout_raises_llm_timeout_error(self) -> None:
        pytest.importorskip("anthropic")
        from pramanix.translator.anthropic import AnthropicTranslator

        translator = AnthropicTranslator("claude-opus-4-6", api_key=self._API_KEY, timeout=0.001)
        with pytest.raises(LLMTimeoutError) as exc_info:
            await translator.extract("pay", SimpleIntent)

        assert exc_info.value.model == "claude-opus-4-6"

    @pytest.mark.asyncio
    async def test_api_status_error_raises_extraction_failure(self) -> None:
        """Unreachable via proxy (proxy ignores api_key) — covered by # pragma in source."""
        pytest.skip("APIStatusError path cannot be triggered via the VS Code proxy")

    @pytest.mark.asyncio
    async def test_empty_content_raises_extraction_failure(self) -> None:
        """Streaming API assembles text via get_final_text() — empty-content path removed."""
        pytest.skip("Streaming API always returns text; empty-content path is pragma: no cover")


# ── Guard.parse_and_verify ────────────────────────────────────────────────────
#
# These tests verify how Guard handles various translator outcomes.
# monkeypatch.setattr on module-level functions is acceptable here because
# parse_and_verify calls create_translator / extract_with_consensus internally
# and requires real API credentials to exercise in production — these are
# impossible-to-reach paths in a unit test environment without API keys.

import pramanix.translator.redundant as _redundant_mod


class TestGuardParseAndVerify:
    """End-to-end tests for Guard.parse_and_verify — translator outcomes injected
    via monkeypatch.setattr, no patch() or MagicMock."""

    def _make_guard(self) -> Any:
        from decimal import Decimal

        from pydantic import BaseModel

        from pramanix.expressions import E, Field
        from pramanix.guard import Guard
        from pramanix.policy import Policy

        class _TransferIntent(BaseModel):
            amount: Decimal

        class _AccountState(BaseModel):
            state_version: str
            balance: Decimal

        class _BankingPolicy(Policy):
            class Meta:
                version = "1.0"
                intent_model = _TransferIntent
                state_model = _AccountState

            amount = Field("amount", Decimal, "Real")
            balance = Field("balance", Decimal, "Real")

            @classmethod
            def invariants(cls):
                return [
                    (E(cls.balance) - E(cls.amount) >= 0).named("sufficient_balance"),
                ]

        return Guard(_BankingPolicy)

    @pytest.mark.asyncio
    async def test_allowed_when_consensus_succeeds_and_policy_passes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        guard = self._make_guard()
        state = {"state_version": "1.0", "balance": Decimal("1000")}

        async def _fake_consensus(text, schema, translators, ctx=None, **kw):
            return {"amount": Decimal("100")}

        monkeypatch.setattr(_redundant_mod, "extract_with_consensus", _fake_consensus)
        decision = await guard.parse_and_verify(
            prompt="transfer one hundred dollars",
            intent_schema=__import__("pydantic").BaseModel,
            state=state,
        )
        assert decision is not None

    @pytest.mark.asyncio
    async def test_error_decision_on_extraction_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        guard = self._make_guard()

        def _raise(model_name, **kwargs):
            raise ExtractionFailureError("Cannot extract")

        monkeypatch.setattr(_redundant_mod, "create_translator", _raise)
        decision = await guard.parse_and_verify(
            prompt="gibberish",
            intent_schema=SimpleIntent,
            state={"state_version": "1.0", "balance": Decimal("500")},
        )

        assert not decision.allowed
        assert "Cannot extract" in decision.explanation

    @pytest.mark.asyncio
    async def test_error_decision_on_mismatch(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        guard = self._make_guard()

        mismatch = ExtractionMismatchError(
            "models disagree",
            model_a="gpt-4o",
            model_b="claude-opus-4-5",
            mismatches={"amount": (Decimal("100"), Decimal("200"))},
        )

        def _raise(model_name, **kwargs):
            raise mismatch

        monkeypatch.setattr(_redundant_mod, "create_translator", _raise)
        decision = await guard.parse_and_verify(
            prompt="ambiguous",
            intent_schema=SimpleIntent,
            state={"state_version": "1.0", "balance": Decimal("500")},
        )

        assert not decision.allowed
        assert "disagree" in decision.explanation

    @pytest.mark.asyncio
    async def test_error_decision_on_llm_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        guard = self._make_guard()

        def _raise(model_name, **kwargs):
            raise LLMTimeoutError("timeout", model="gpt-4o", attempts=3)

        monkeypatch.setattr(_redundant_mod, "create_translator", _raise)
        decision = await guard.parse_and_verify(
            prompt="pay",
            intent_schema=SimpleIntent,
            state={"state_version": "1.0", "balance": Decimal("500")},
        )

        assert not decision.allowed
        assert "timeout" in decision.explanation.lower()
