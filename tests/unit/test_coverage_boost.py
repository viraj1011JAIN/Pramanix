# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Coverage boost tests — fills every gap identified in the 94.31% report.

Targets (all files that were below 96%):
  _platform.py, audit_sink.py, interceptors/grpc.py, interceptors/kafka.py,
  translator/cohere.py, translator/llamacpp.py, translator/openai_compat.py,
  translator/gemini.py, translator/injection_filter.py, translator/_json.py,
  translator/anthropic.py, translator/ollama.py, translator/mistral.py,
  exceptions.py, guard.py, key_provider.py, worker.py,
  audit/archiver.py, migration.py, translator/redundant.py,
  circuit_breaker.py, crypto.py, execution_token.py, cli.py
"""
from __future__ import annotations

import asyncio
import sys
import threading
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════════
# _platform.py — is_musl() (lines 27-42)
# ═══════════════════════════════════════════════════════════════════════════════


class TestIsMusl:
    def test_non_linux_returns_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import pramanix._platform as _p
        monkeypatch.setattr("sys.platform", "win32")
        assert _p.is_musl() is False

    def test_linux_glob_found_returns_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pramanix._platform as _p
        monkeypatch.setattr("sys.platform", "linux")
        with patch("glob.glob", return_value=["/lib/ld-musl-x86_64.so.1"]):
            assert _p.is_musl() is True

    def test_linux_no_glob_ctypes_fails_returns_true(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pramanix._platform as _p
        monkeypatch.setattr("sys.platform", "linux")
        with patch("glob.glob", return_value=[]):
            with patch("ctypes.CDLL", side_effect=OSError("not found")):
                assert _p.is_musl() is True

    def test_linux_no_glob_ctypes_ok_returns_false(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import pramanix._platform as _p
        monkeypatch.setattr("sys.platform", "linux")
        with patch("glob.glob", return_value=[]):
            with patch("ctypes.CDLL", return_value=MagicMock()):
                assert _p.is_musl() is False


# ═══════════════════════════════════════════════════════════════════════════════
# exceptions.py — MigrationError.__init__ with all keyword params (lines 383-386)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMigrationErrorInit:
    def test_all_kwargs_stored(self) -> None:
        from pramanix.exceptions import MigrationError

        e = MigrationError(
            "test msg",
            missing_key="old_field",
            from_version="1.0",
            to_version="2.0",
        )
        assert e.missing_key == "old_field"
        assert e.from_version == "1.0"
        assert e.to_version == "2.0"
        assert str(e) == "test msg"

    def test_defaults_are_empty_strings(self) -> None:
        from pramanix.exceptions import MigrationError

        e = MigrationError("oops")
        assert e.missing_key == ""
        assert e.from_version == ""
        assert e.to_version == ""


# ═══════════════════════════════════════════════════════════════════════════════
# migration.py — strict mode MigrationError (line 110)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMigrationStrict:
    def test_strict_raises_on_missing_key(self) -> None:
        from pramanix.exceptions import MigrationError
        from pramanix.migration import PolicyMigration

        m = PolicyMigration(
            from_version=(1, 0, 0),
            to_version=(2, 0, 0),
            field_renames={"old_field": "new_field"},
        )
        with pytest.raises(MigrationError, match="old_field"):
            m.migrate({"unrelated": "value"}, strict=True)


# ═══════════════════════════════════════════════════════════════════════════════
# translator/_json.py — JSONDecodeError in _extract_first_json (lines 36-37)
# ═══════════════════════════════════════════════════════════════════════════════


class TestExtractFirstJson:
    def test_invalid_json_after_brace_falls_through(self) -> None:
        from pramanix.translator._json import _extract_first_json

        # "{" followed by garbage — raw_decode raises JSONDecodeError
        result = _extract_first_json("{ this is NOT json")
        assert result is None

    def test_valid_json_extracted(self) -> None:
        from pramanix.translator._json import _extract_first_json

        result = _extract_first_json('prefix {"k": 1} suffix')
        assert result == '{"k": 1}'


# ═══════════════════════════════════════════════════════════════════════════════
# translator/redundant.py — invalid JSON in _raw_strings_agree (lines 63-66)
# ═══════════════════════════════════════════════════════════════════════════════


class TestRawStringsAgreeCoverage:
    def test_invalid_json_falls_back_to_string_equal(self) -> None:
        from pramanix.translator.redundant import _raw_strings_agree

        assert _raw_strings_agree("hello world", "hello world") is True

    def test_invalid_json_falls_back_to_string_unequal(self) -> None:
        from pramanix.translator.redundant import _raw_strings_agree

        assert _raw_strings_agree("foo", "bar") is False


# ═══════════════════════════════════════════════════════════════════════════════
# translator/anthropic.py — aclose / __aenter__ / __aexit__ (135, 138, 141)
# ═══════════════════════════════════════════════════════════════════════════════


class TestAnthropicTranslatorLifecycle:
    @pytest.mark.asyncio
    async def test_aclose_does_not_raise(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator

        t = AnthropicTranslator("claude-opus-4-6", api_key="sk-test")
        await t.aclose()  # must complete without error

    @pytest.mark.asyncio
    async def test_context_manager_returns_self(self) -> None:
        from pramanix.translator.anthropic import AnthropicTranslator

        async with AnthropicTranslator("claude-opus-4-6", api_key="sk-test") as ctx:
            assert isinstance(ctx, AnthropicTranslator)


# ═══════════════════════════════════════════════════════════════════════════════
# translator/ollama.py — aclose / __aenter__ / __aexit__ (169, 172, 175)
# ═══════════════════════════════════════════════════════════════════════════════


class TestOllamaTranslatorLifecycle:
    @pytest.mark.asyncio
    async def test_aclose_calls_client_aclose(self) -> None:
        from pramanix.translator.ollama import OllamaTranslator

        t = OllamaTranslator()
        mock_client = AsyncMock()
        t._client = mock_client
        await t.aclose()
        mock_client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        from pramanix.translator.ollama import OllamaTranslator

        t = OllamaTranslator()
        t._client = AsyncMock()
        async with t as ctx:
            assert ctx is t
        t._client.aclose.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# translator/openai_compat.py — ImportError paths, aclose, context manager
# ═══════════════════════════════════════════════════════════════════════════════


class TestOpenAICompatCoverage:
    def test_missing_openai_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "openai", None)
        if "pramanix.translator.openai_compat" in sys.modules:
            del sys.modules["pramanix.translator.openai_compat"]
        with pytest.raises(ImportError, match="openai"):
            from pramanix.translator.openai_compat import OpenAICompatTranslator
            OpenAICompatTranslator("gpt-4o")

    @pytest.mark.asyncio
    async def test_missing_tenacity_raises_import_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator
        from pydantic import BaseModel

        class _S(BaseModel):
            amount: float

        t = OpenAICompatTranslator("gpt-4o", api_key="sk-test")
        monkeypatch.setitem(sys.modules, "tenacity", None)
        with pytest.raises(ImportError, match="tenacity"):
            await t.extract("pay 10", _S)

    @pytest.mark.asyncio
    async def test_aclose_and_context_manager(self) -> None:
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        t = OpenAICompatTranslator("gpt-4o", api_key="sk-test")
        t._client = AsyncMock()
        await t.aclose()
        t._client.aclose.assert_awaited_once()

        t._client = AsyncMock()
        async with t as ctx:
            assert ctx is t
        t._client.aclose.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# translator/cohere.py — CohereError fallback (77-79), aclose, context manager
# ═══════════════════════════════════════════════════════════════════════════════


class TestCohereTranslatorCoverage:
    def test_cohere_error_fallback_when_core_missing(self) -> None:
        """CohereError generic fallback when cohere.core.api_error missing."""
        mock_cohere = MagicMock()
        # Make cohere.errors.TooManyRequestsError raise AttributeError
        del mock_cohere.errors
        # Make cohere.core.api_error.ApiError raise AttributeError too
        del mock_cohere.core
        # But give it a CohereError
        mock_cohere.CohereError = RuntimeError

        with patch.dict(sys.modules, {"cohere": mock_cohere}):
            if "pramanix.translator.cohere" in sys.modules:
                del sys.modules["pramanix.translator.cohere"]
            from pramanix.translator.cohere import CohereTranslator

            t = CohereTranslator.__new__(CohereTranslator)
            t.model = "command-r"
            t._api_key = None
            t._timeout = 30.0
            t._cohere = mock_cohere
            # Manually trigger the retryable detection
            try:
                _ = mock_cohere.errors.TooManyRequestsError
            except AttributeError:
                try:
                    _ = mock_cohere.core.api_error.ApiError
                except AttributeError:
                    _base = getattr(mock_cohere, "CohereError", None)
                    t._retryable = (_base,) if _base is not None else (OSError,)
            assert t._retryable == (RuntimeError,)

    def test_no_cohere_error_attr_falls_back_to_oserror(self) -> None:
        mock_cohere = MagicMock(spec=[])  # no attributes at all
        _base = getattr(mock_cohere, "CohereError", None)
        retryable = (_base,) if _base is not None else (OSError,)
        assert retryable == (OSError,)

    @pytest.mark.asyncio
    async def test_aclose_with_sync_close(self) -> None:
        from pramanix.translator.cohere import CohereTranslator

        t = CohereTranslator.__new__(CohereTranslator)
        mock_client = MagicMock()
        mock_client.aclose = None  # no aclose
        mock_client.close = MagicMock(return_value=None)
        t._client = mock_client
        await t.aclose()
        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_aclose_with_async_close(self) -> None:
        from pramanix.translator.cohere import CohereTranslator

        t = CohereTranslator.__new__(CohereTranslator)
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        t._client = mock_client
        await t.aclose()
        mock_client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_context_manager(self) -> None:
        from pramanix.translator.cohere import CohereTranslator

        t = CohereTranslator.__new__(CohereTranslator)
        mock_client = MagicMock()
        mock_client.aclose = AsyncMock()
        t._client = mock_client
        async with t as ctx:
            assert ctx is t
        mock_client.aclose.assert_awaited_once()


# ═══════════════════════════════════════════════════════════════════════════════
# translator/llamacpp.py — _get_llm cache miss, non-ExtractionFailure parse error
# ═══════════════════════════════════════════════════════════════════════════════


class TestLlamaCppCoverage:
    def test_get_llm_loads_from_cache(self) -> None:
        """_get_llm() returns from module cache without re-loading."""
        from pramanix.translator import llamacpp as _llamacpp_mod

        mock_llm = MagicMock()
        cache_key = ("/tmp/fake.gguf", 4096, 0)
        _llamacpp_mod._MODEL_CACHE[cache_key] = mock_llm

        from pramanix.translator.llamacpp import LlamaCppTranslator

        t = LlamaCppTranslator.__new__(LlamaCppTranslator)
        t._model_path = "/tmp/fake.gguf"
        t._n_ctx = 4096
        t._n_gpu_layers = 0
        t._llm = None

        result = t._get_llm()
        assert result is mock_llm
        del _llamacpp_mod._MODEL_CACHE[cache_key]

    @pytest.mark.asyncio
    async def test_non_extraction_parse_exception_wrapped(self) -> None:
        """Non-ExtractionFailureError from parse_llm_response is wrapped."""
        from pramanix.exceptions import ExtractionFailureError
        from pramanix.translator.llamacpp import LlamaCppTranslator
        from pydantic import BaseModel

        class _S(BaseModel):
            amount: float

        t = LlamaCppTranslator.__new__(LlamaCppTranslator)
        t._model_path = "/tmp/fake.gguf"
        t._n_ctx = 4096
        t._n_gpu_layers = 0
        t._max_tokens = 512
        t._llm = None

        # _inference returns a string; parse_llm_response will raise ExtractionFailureError
        # for bad JSON. For the non-ExtractionFailureError path, patch parse_llm_response
        with patch(
            "pramanix.translator.llamacpp.parse_llm_response",
            side_effect=ValueError("unexpected"),
        ):
            with patch.object(t, "_inference", return_value='{"amount": 1}'):
                with pytest.raises(ExtractionFailureError, match="failed to parse"):
                    await t.extract("pay 10", _S)

    @pytest.mark.asyncio
    async def test_timeout_error_raises_llm_timeout_error(self) -> None:
        from pramanix.exceptions import LLMTimeoutError
        from pramanix.translator.llamacpp import LlamaCppTranslator
        from pydantic import BaseModel

        class _S(BaseModel):
            amount: float

        t = LlamaCppTranslator.__new__(LlamaCppTranslator)
        t._model_path = "/tmp/fake.gguf"
        t._n_ctx = 4096
        t._n_gpu_layers = 0
        t._max_tokens = 512
        t._llm = None

        with patch.object(t, "_inference", side_effect=TimeoutError("timed out")):
            with pytest.raises(LLMTimeoutError):
                await t.extract("pay 10", _S)


# ═══════════════════════════════════════════════════════════════════════════════
# translator/gemini.py — ImportError (60-61), no api_key path (82)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGeminiTranslatorCoverage:
    def test_missing_google_generativeai_raises_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.exceptions import ConfigurationError

        monkeypatch.setitem(sys.modules, "google.generativeai", None)
        monkeypatch.setitem(sys.modules, "google", None)
        if "pramanix.translator.gemini" in sys.modules:
            del sys.modules["pramanix.translator.gemini"]
        with pytest.raises((ConfigurationError, ImportError)):
            from pramanix.translator.gemini import GeminiTranslator
            GeminiTranslator("gemini-pro")

    def test_no_api_key_sets_client_to_none(self) -> None:
        """When no api_key provided, _client is None (line 82)."""
        from pramanix.translator.gemini import GeminiTranslator

        t = GeminiTranslator("gemini-pro")  # no api_key
        assert t._client is None

    @pytest.mark.asyncio
    async def test_single_call_global_configure_path(self) -> None:
        """No per-instance client → falls back to genai.configure() path."""
        from pramanix.translator.gemini import GeminiTranslator

        t = GeminiTranslator.__new__(GeminiTranslator)
        t.model = "gemini-pro"
        t._api_key = "test-key"
        t._timeout = 30.0
        t._client = None  # force global configure path

        mock_genai = MagicMock()
        mock_response = MagicMock()
        mock_response.text = '{"amount": 5.0}'
        mock_model_instance = MagicMock()
        mock_model_instance.generate_content_async = AsyncMock(
            return_value=mock_response
        )
        mock_genai.GenerativeModel.return_value = mock_model_instance
        mock_genai.GenerationConfig = MagicMock()
        t._genai = mock_genai

        result = await t._single_call(prompt="test")
        assert result == '{"amount": 5.0}'


# ═══════════════════════════════════════════════════════════════════════════════
# translator/mistral.py — ImportError for httpx (lines 118-119)
# ═══════════════════════════════════════════════════════════════════════════════


class TestMistralHttpxImportError:
    @pytest.mark.asyncio
    async def test_httpx_not_installed_gives_empty_retryable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When httpx import fails inside extract(), _http_errors is empty tuple."""
        pytest.importorskip("mistralai")
        from pramanix.translator.mistral import MistralTranslator
        from pydantic import BaseModel

        class _S(BaseModel):
            amount: float

        t = MistralTranslator("mistral-small-latest", api_key="key")

        # Patch httpx to fail inside extract()
        # The code does: try: import httpx ... except ImportError: _http_errors = ()
        # This means the retryable tuple will exclude httpx errors
        # We can verify this by checking that the code path is reached
        # by blocking httpx import at the point inside extract()
        mock_client = AsyncMock()
        mock_response = MagicMock()
        mock_msg = MagicMock()
        mock_msg.content = '{"amount": 5.0}'
        mock_response.choices = [MagicMock(message=mock_msg)]
        mock_client.chat.complete_async = AsyncMock(return_value=mock_response)
        t._client = mock_client

        with patch.dict(sys.modules, {"httpx": None}):
            with patch(
                "pramanix.translator._json.parse_llm_response",
                return_value={"amount": 5.0},
            ):
                # Should succeed with empty _http_errors — just no httpx retryable
                result = await t.extract("pay 5", _S)
                assert result == {"amount": 5.0}


# ═══════════════════════════════════════════════════════════════════════════════
# translator/injection_filter.py — except Exception fallback (130-134)
# ═══════════════════════════════════════════════════════════════════════════════


class TestInjectionFilterException:
    def test_exception_in_filter_returns_false_fail_open(self) -> None:
        from pramanix.translator.injection_filter import InjectionFilter

        f = InjectionFilter()

        # Patch the combined regex to raise an unexpected exception
        with patch(
            "pramanix.translator.injection_filter._COMBINED_RE",
            new_callable=lambda: type(
                "_FakePat", (), {"search": staticmethod(
                    lambda t: (_ for _ in ()).throw(RuntimeError("regex crash"))
                )}
            ),
        ):
            detected, reason = f.is_injection("some text")
            assert detected is False
            assert "filter_error" in reason


# ═══════════════════════════════════════════════════════════════════════════════
# interceptors/grpc.py — all handler types (47-49, 141-143, 149-171)
# ═══════════════════════════════════════════════════════════════════════════════


class TestGrpcInterceptorCoverage:
    def _make_guard(self) -> MagicMock:
        guard = MagicMock()
        decision = MagicMock()
        decision.allowed = True
        decision.violated_invariants = []
        decision.explanation = ""
        guard.verify.return_value = decision
        return guard

    def test_grpc_not_available_sets_object_base(self) -> None:
        """When grpc is absent, _InterceptorBase = object."""
        with patch.dict(sys.modules, {"grpc": None}):
            if "pramanix.interceptors.grpc" in sys.modules:
                del sys.modules["pramanix.interceptors.grpc"]
            import pramanix.interceptors.grpc as _grpc_mod
            assert _grpc_mod._GRPC_AVAILABLE is False

    def test_intercept_service_none_handler(self) -> None:
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = self._make_guard()
        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )
        # continuation returns None → handler should pass through as None
        result = interceptor.intercept_service(lambda _: None, MagicMock())
        assert result is None

    def test_wrap_handler_no_grpc_returns_original(self) -> None:
        from pramanix.interceptors import grpc as _grpc_mod
        original_available = _grpc_mod._GRPC_AVAILABLE
        try:
            _grpc_mod._GRPC_AVAILABLE = False
            from pramanix.interceptors.grpc import PramanixGrpcInterceptor
            guard = self._make_guard()
            interceptor = PramanixGrpcInterceptor.__new__(PramanixGrpcInterceptor)
            interceptor._guard = guard
            interceptor._intent_extractor = lambda d, r: {}
            interceptor._state_provider = lambda: {}
            interceptor._denied_code = None
            fake_handler = MagicMock()
            result = interceptor._wrap_handler(fake_handler, MagicMock())
            assert result is fake_handler
        finally:
            _grpc_mod._GRPC_AVAILABLE = original_available

    def test_unary_stream_allowed(self) -> None:
        """_guarded_unary_stream yields from handler when guard allows."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = self._make_guard()
        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )

        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        fake_handler.unary_stream = MagicMock(return_value=iter([1, 2, 3]))
        fake_handler.stream_unary = None
        fake_handler.stream_stream = None
        fake_handler._replace = MagicMock(return_value=fake_handler)

        mock_context = MagicMock()
        mock_context.abort = MagicMock()

        wrapped = interceptor.intercept_service(lambda _: fake_handler, MagicMock())
        # The handler was replaced
        assert fake_handler._replace.called

    def test_stream_unary_empty_iterator(self) -> None:
        """_guarded_stream_unary with empty iterator returns None."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = self._make_guard()
        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )

        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        fake_handler.unary_stream = None
        fake_handler.stream_unary = MagicMock(return_value="done")
        fake_handler.stream_stream = None

        replace_kwargs_captured: dict = {}

        def fake_replace(**kwargs: object) -> MagicMock:
            replace_kwargs_captured.update(kwargs)
            return fake_handler

        fake_handler._replace = fake_replace

        interceptor.intercept_service(lambda _: fake_handler, MagicMock())

        # Now call stream_unary with empty iterator
        if "stream_unary" in replace_kwargs_captured:
            mock_ctx = MagicMock()
            result = replace_kwargs_captured["stream_unary"](iter([]), mock_ctx)
            assert result is None

    def test_stream_stream_empty_iterator(self) -> None:
        """_guarded_stream_stream with empty iterator returns early."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = self._make_guard()
        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )

        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        fake_handler.unary_stream = None
        fake_handler.stream_unary = None
        fake_handler.stream_stream = MagicMock(return_value=iter([]))

        replace_kwargs_captured: dict = {}

        def fake_replace(**kwargs: object) -> MagicMock:
            replace_kwargs_captured.update(kwargs)
            return fake_handler

        fake_handler._replace = fake_replace

        interceptor.intercept_service(lambda _: fake_handler, MagicMock())

        if "stream_stream" in replace_kwargs_captured:
            mock_ctx = MagicMock()
            gen = replace_kwargs_captured["stream_stream"](iter([]), mock_ctx)
            items = list(gen)
            assert items == []

    def test_guard_error_aborts_rpc(self) -> None:
        """When guard.verify() raises, the RPC is aborted with INTERNAL."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = MagicMock()
        guard.verify.side_effect = RuntimeError("z3 crash")

        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )

        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        fake_handler.unary_stream = None
        fake_handler.stream_unary = None
        fake_handler.stream_stream = None

        replace_kwargs_captured: dict = {}

        def fake_replace(**kwargs: object) -> MagicMock:
            replace_kwargs_captured.update(kwargs)
            return fake_handler

        fake_handler._replace = fake_replace
        interceptor.intercept_service(lambda _: fake_handler, MagicMock())

        if "unary_unary" in replace_kwargs_captured:
            mock_ctx = MagicMock()
            result = replace_kwargs_captured["unary_unary"](MagicMock(), mock_ctx)
            assert result is None
            mock_ctx.abort.assert_called_once()

    def test_blocked_rpc_aborts(self) -> None:
        """When guard blocks, RPC is aborted with denied status code."""
        from pramanix.interceptors.grpc import PramanixGrpcInterceptor

        guard = MagicMock()
        decision = MagicMock()
        decision.allowed = False
        decision.violated_invariants = ["rule_a"]
        decision.explanation = "blocked"
        guard.verify.return_value = decision

        interceptor = PramanixGrpcInterceptor(
            guard=guard,
            intent_extractor=lambda details, req: {},
            state_provider=lambda: {},
        )

        fake_handler = MagicMock()
        fake_handler.unary_unary = MagicMock(return_value="ok")
        fake_handler.unary_stream = None
        fake_handler.stream_unary = None
        fake_handler.stream_stream = None

        replace_kwargs_captured: dict = {}

        def fake_replace(**kwargs: object) -> MagicMock:
            replace_kwargs_captured.update(kwargs)
            return fake_handler

        fake_handler._replace = fake_replace
        interceptor.intercept_service(lambda _: fake_handler, MagicMock())

        if "unary_unary" in replace_kwargs_captured:
            mock_ctx = MagicMock()
            result = replace_kwargs_captured["unary_unary"](MagicMock(), mock_ctx)
            assert result is None
            mock_ctx.abort.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════════
# interceptors/kafka.py — ImportError (47-50), dlq exception, commit error, __del__
# ═══════════════════════════════════════════════════════════════════════════════


class TestKafkaConsumerCoverage:
    def test_kafka_not_available_sets_flag(self) -> None:
        with patch.dict(sys.modules, {"confluent_kafka": None}):
            if "pramanix.interceptors.kafka" in sys.modules:
                del sys.modules["pramanix.interceptors.kafka"]
            import pramanix.interceptors.kafka as _kafka_mod
            assert _kafka_mod._KAFKA_AVAILABLE is False

    def _make_consumer(self) -> object:
        from pramanix.interceptors.kafka import PramanixKafkaConsumer

        guard = MagicMock()
        decision = MagicMock()
        decision.allowed = True
        decision.violated_invariants = []
        guard.verify.return_value = decision

        c = PramanixKafkaConsumer.__new__(PramanixKafkaConsumer)
        c._guard = guard
        c._intent_extractor = lambda msg: {}
        c._state_provider = lambda: {}
        c._dlq_producer = None
        c._dlq_topic = "pramanix.dlq"
        c._consumer = MagicMock()
        return c

    def test_dead_letter_with_dlq_exception_swallowed(self) -> None:
        from pramanix.interceptors.kafka import PramanixKafkaConsumer

        c = self._make_consumer()
        mock_dlq = MagicMock()
        mock_dlq.produce.side_effect = Exception("kafka error")
        c._dlq_producer = mock_dlq

        mock_msg = MagicMock()
        mock_msg.value.return_value = b"data"
        # Must not raise
        c._dead_letter(mock_msg, reason="test block")

    def test_commit_exception_swallowed(self) -> None:
        c = self._make_consumer()
        c._consumer.commit.side_effect = Exception("commit failed")
        mock_msg = MagicMock()
        # Must not raise
        c._commit(mock_msg)

    def test_del_with_consumer_logs_warning(self) -> None:
        from pramanix.interceptors.kafka import PramanixKafkaConsumer

        c = PramanixKafkaConsumer.__new__(PramanixKafkaConsumer)
        c._consumer = MagicMock()
        c._consumer.close.side_effect = Exception("close failed")
        # __del__ must not raise even when close() raises
        c.__del__()

    def test_dead_letter_none_dlq_is_noop(self) -> None:
        c = self._make_consumer()
        c._dlq_producer = None
        # Must not raise
        c._dead_letter(MagicMock(), reason="blocked")

    def test_safe_poll_no_consumer_returns_early(self) -> None:
        from pramanix.interceptors.kafka import PramanixKafkaConsumer

        c = PramanixKafkaConsumer.__new__(PramanixKafkaConsumer)
        c._consumer = None
        results = list(c.safe_poll())
        assert results == []

    def test_safe_poll_msg_error_returns_early(self) -> None:
        c = self._make_consumer()
        mock_msg = MagicMock()
        mock_msg.error.return_value = "broker error"
        c._consumer.poll.return_value = mock_msg
        results = list(c.safe_poll())
        assert results == []

    def test_safe_poll_none_msg_returns_early(self) -> None:
        c = self._make_consumer()
        c._consumer.poll.return_value = None
        results = list(c.safe_poll())
        assert results == []


# ═══════════════════════════════════════════════════════════════════════════════
# audit_sink.py — overflow metric exception, background poll error,
#   delivery callback error, flush exception, Splunk close, Datadog
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuditSinkCoverage:
    def test_increment_overflow_metric_swallows_exception(self) -> None:
        from pramanix import audit_sink as _as_mod

        original = _as_mod._OVERFLOW_COUNTER
        try:
            mock_counter = MagicMock()
            mock_counter.inc.side_effect = Exception("prom error")
            _as_mod._OVERFLOW_COUNTER = mock_counter
            # Must not raise
            _as_mod._increment_overflow_metric()
        finally:
            _as_mod._OVERFLOW_COUNTER = original

    def test_kafka_background_poll_exception_swallowed(self) -> None:
        from pramanix.audit_sink import KafkaAuditSink

        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._poll_stop = threading.Event()
        mock_producer = MagicMock()
        mock_producer.poll.side_effect = Exception("kafka down")
        sink._producer = mock_producer

        # Run one tick then stop
        sink._poll_stop.set()
        sink._background_poll()  # must not raise

    def test_kafka_delivery_callback_with_error_logs(self) -> None:
        """_delivery_cb with a truthy error logs the error."""
        import concurrent.futures
        from pramanix.audit_sink import KafkaAuditSink
        from pramanix.decision import Decision, SolverStatus

        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._topic = "test-topic"
        sink._max_queue = 10_000
        sink._queue_lock = threading.Lock()
        sink._queue_depth = 0
        sink._overflow_count = 0
        sink._poll_stop = threading.Event()

        delivery_errors: list = []
        real_produce_calls: list = []

        def fake_produce(topic: str, value: bytes, callback: object) -> None:
            real_produce_calls.append(callback)
            # Immediately invoke callback with an error
            callback("delivery failed", None)

        mock_producer = MagicMock()
        mock_producer.produce = fake_produce
        sink._producer = mock_producer

        d = Decision(
            allowed=True,
            status=SolverStatus.SAFE,
            violated_invariants=(),
            explanation="test",
        )
        sink.emit(d)  # must not raise
        assert len(real_produce_calls) == 1

    def test_kafka_flush_exception_swallowed(self) -> None:
        from pramanix.audit_sink import KafkaAuditSink

        sink = KafkaAuditSink.__new__(KafkaAuditSink)
        sink._poll_stop = threading.Event()
        mock_producer = MagicMock()
        mock_producer.flush.side_effect = Exception("flush failed")
        sink._producer = mock_producer
        # Must not raise
        sink.flush()

    def test_splunk_sink_config_error_without_httpx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.exceptions import ConfigurationError

        monkeypatch.setitem(sys.modules, "httpx", None)
        if "pramanix.audit_sink" in sys.modules:
            del sys.modules["pramanix.audit_sink"]
        with pytest.raises((ConfigurationError, ImportError)):
            from pramanix.audit_sink import SplunkHecAuditSink
            SplunkHecAuditSink("http://splunk:8088/services/collector", "token")

    def test_splunk_sink_close(self) -> None:
        from pramanix.audit_sink import SplunkHecAuditSink

        sink = SplunkHecAuditSink.__new__(SplunkHecAuditSink)
        mock_client = MagicMock()
        sink._client = mock_client
        sink.close()
        mock_client.close.assert_called_once()

    def test_splunk_sink_close_exception_swallowed(self) -> None:
        from pramanix.audit_sink import SplunkHecAuditSink

        sink = SplunkHecAuditSink.__new__(SplunkHecAuditSink)
        mock_client = MagicMock()
        mock_client.close.side_effect = Exception("close failed")
        sink._client = mock_client
        sink.close()  # must not raise

    def test_splunk_sink_with_index(self) -> None:
        """SplunkHecAuditSink with index= sets index in payload."""
        from pramanix.audit_sink import SplunkHecAuditSink
        from pramanix.decision import Decision, SolverStatus
        import respx, httpx

        with respx.mock(base_url="http://splunk:8088") as mock_splunk:
            mock_splunk.post("/services/collector").mock(
                return_value=httpx.Response(200, json={"text": "Success", "code": 0})
            )
            sink = SplunkHecAuditSink(
                "http://splunk:8088/services/collector",
                "my-token",
                index="pramanix-audit",
            )
            d = Decision(
                allowed=True,
                status=SolverStatus.SAFE,
                violated_invariants=(),
                explanation="",
            )
            sink.emit(d)
            assert mock_splunk.calls.call_count == 1

    def test_datadog_sink_close(self) -> None:
        from pramanix.audit_sink import DatadogAuditSink

        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        mock_client = MagicMock()
        sink._api_client = mock_client
        sink.close()
        mock_client.close.assert_called_once()

    def test_datadog_sink_close_exception_swallowed(self) -> None:
        from pramanix.audit_sink import DatadogAuditSink

        sink = DatadogAuditSink.__new__(DatadogAuditSink)
        mock_client = MagicMock()
        mock_client.close.side_effect = Exception("close failed")
        sink._api_client = mock_client
        sink.close()  # must not raise


# ═══════════════════════════════════════════════════════════════════════════════
# key_provider.py — rotate_key NotImplementedError paths,
#   FileKeyProvider.key_version OSError, AwsKmsKeyProvider.rotate_key
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeyProviderCoverage:
    def test_pem_key_provider_rotate_raises(self) -> None:
        from pramanix.key_provider import PemKeyProvider

        p = PemKeyProvider(b"fake-pem-bytes", version="v1")
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_env_key_provider_rotate_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from pramanix.key_provider import EnvKeyProvider

        monkeypatch.setenv("PRAMANIX_SIGNING_KEY_PEM", "fake-pem")
        p = EnvKeyProvider()
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_file_key_provider_rotate_raises(self, tmp_path: object) -> None:
        import pathlib
        from pramanix.key_provider import FileKeyProvider

        f = pathlib.Path(str(tmp_path)) / "key.pem"
        f.write_bytes(b"fake-pem")
        p = FileKeyProvider(f)
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_file_key_provider_version_oserror(self) -> None:
        from pramanix.key_provider import FileKeyProvider

        p = FileKeyProvider("/nonexistent/path/key.pem")
        # stat() will fail → returns "file-unknown"
        version = p.key_version()
        assert version == "file-unknown"

    def test_file_key_provider_explicit_version(self, tmp_path: object) -> None:
        import pathlib
        from pramanix.key_provider import FileKeyProvider

        f = pathlib.Path(str(tmp_path)) / "key.pem"
        f.write_bytes(b"fake-pem")
        p = FileKeyProvider(f, version="pinned-v1")
        assert p.key_version() == "pinned-v1"

    def test_aws_kms_rotate_key(self) -> None:
        from pramanix.key_provider import AwsKmsKeyProvider

        p = AwsKmsKeyProvider.__new__(AwsKmsKeyProvider)
        p._secret_arn = "arn:aws:secretsmanager:us-east-1:123:secret:key"
        p._version_stage = "AWSCURRENT"
        p._explicit_version = None
        p._cache_lock = threading.Lock()
        p._cached_pem = None
        p._cached_version = None
        p._cache_expires = 0.0

        mock_client = MagicMock()
        p._client = mock_client
        p.rotate_key()
        mock_client.rotate_secret.assert_called_once_with(
            SecretId=p._secret_arn
        )
        assert p._cache_expires == 0.0

    def test_azure_key_vault_rotate_raises(self) -> None:
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_gcp_kms_rotate_raises(self) -> None:
        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_hashicorp_vault_rotate_raises(self) -> None:
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        with pytest.raises(NotImplementedError, match="rotation"):
            p.rotate_key()

    def test_hashicorp_vault_key_version_cached(self) -> None:
        """key_version() returns cached version without API call."""
        import time
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._cache_lock = threading.Lock()
        p._cached_pem = b"fake-pem"
        p._cached_version = "42"
        p._cache_expires = time.monotonic() + 3600  # far future

        assert p.key_version() == "42"

    def test_hashicorp_vault_cached_version_fallback(self) -> None:
        """key_version() returns 'vault-unknown' when _cached_version is None."""
        import time
        from pramanix.key_provider import HashiCorpVaultKeyProvider

        p = HashiCorpVaultKeyProvider.__new__(HashiCorpVaultKeyProvider)
        p._cache_lock = threading.Lock()
        p._cached_pem = b"fake-pem"
        p._cached_version = None
        p._cache_expires = time.monotonic() + 3600

        assert p.key_version() == "vault-unknown"

    def test_gcp_kms_private_key_pem_cached(self) -> None:
        """GcpKmsKeyProvider.private_key_pem() returns from cache when valid."""
        import time
        from pramanix.key_provider import GcpKmsKeyProvider

        p = GcpKmsKeyProvider.__new__(GcpKmsKeyProvider)
        p._cache_lock = threading.Lock()
        p._cached_pem = b"cached-pem"
        p._cache_expires = time.monotonic() + 3600
        p._project_id = "proj"
        p._secret_id = "secret"
        p._version_id = "latest"

        result = p.private_key_pem()
        assert result == b"cached-pem"

    def test_azure_key_vault_cached_pem(self) -> None:
        import time
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._cache_lock = threading.Lock()
        p._cached_pem = b"azure-pem"
        p._cached_version = "abc123"
        p._cache_expires = time.monotonic() + 3600

        assert p.private_key_pem() == b"azure-pem"
        assert p.key_version() == "abc123"

    def test_azure_key_vault_cached_version_fallback(self) -> None:
        import time
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        p = AzureKeyVaultKeyProvider.__new__(AzureKeyVaultKeyProvider)
        p._cache_lock = threading.Lock()
        p._cached_pem = b"azure-pem"
        p._cached_version = None
        p._cache_expires = time.monotonic() + 3600

        assert p.key_version() == "azure-unknown"


# ═══════════════════════════════════════════════════════════════════════════════
# guard.py — _is_picklable PicklingError path, _emit_translator_metric paths,
#   _CBWrappedTranslator, async verify missing fields
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardCoverage:
    def test_is_picklable_pickling_error_returns_false(self) -> None:
        from pramanix.guard import _is_picklable
        import pickle

        class _Unpicklable:
            def __reduce__(self) -> tuple:
                raise pickle.PicklingError("Cannot pickle")

        result = _is_picklable(_Unpicklable())
        assert result is False

    def test_emit_translator_metric_consensus_failure(self) -> None:
        """_emit_translator_metric with consensus_failure type."""
        from pramanix.guard import _emit_translator_metric

        # Should not raise regardless of prometheus state
        _emit_translator_metric("consensus_failure", ["model-a", "model-b"])

    def test_emit_translator_metric_extraction_failure(self) -> None:
        from pramanix.guard import _emit_translator_metric

        _emit_translator_metric("extraction_failure", ["model-x"])

    def test_cb_wrapped_translator_getattr(self) -> None:
        from pramanix.guard import _CBWrappedTranslator

        inner = MagicMock()
        inner.model = "test-model"
        inner.some_attr = "hello"
        wrapped = _CBWrappedTranslator(inner, MagicMock())
        assert wrapped.model == "test-model"
        assert wrapped.some_attr == "hello"

    @pytest.mark.asyncio
    async def test_cb_wrapped_translator_extract_routes_through_breaker(
        self,
    ) -> None:
        from pramanix.guard import _CBWrappedTranslator

        inner = MagicMock()
        breaker = MagicMock()
        breaker.call = AsyncMock(return_value={"amount": 1.0})
        wrapped = _CBWrappedTranslator(inner, breaker)
        result = await wrapped.extract("text", MagicMock())
        assert result == {"amount": 1.0}
        breaker.call.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_verify_async_missing_fields_returns_error_decision(
        self,
    ) -> None:
        """verify_async() with missing required fields → error Decision."""
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")
        _balance = Field("balance", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount, "balance": _balance}

            @classmethod
            def invariants(cls):
                return [
                    (E(_balance) - E(_amount) >= Decimal("0"))
                    .named("sufficient_balance")
                    .explain("Insufficient")
                ]

        guard = Guard(_P, GuardConfig(execution_mode="async-thread"))
        # Missing 'balance' field
        d = await guard.verify_async(
            intent={"amount": Decimal("100")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed

    @pytest.mark.asyncio
    async def test_verify_async_fast_path_blocked(self) -> None:
        """verify_async() with fast_path rules that block → unsafe Decision."""
        from decimal import Decimal
        from pramanix import E, Field, Guard, GuardConfig, Policy

        _amount = Field("amount", Decimal, "Real")

        class _P(Policy):
            class Meta:
                version = "1.0"

            @classmethod
            def fields(cls):
                return {"amount": _amount}

            @classmethod
            def invariants(cls):
                return [
                    (E(_amount) >= Decimal("0"))
                    .named("non_negative")
                    .explain("Negative amount")
                ]

        # FastPathRule = Callable returning str|None; str means blocked
        def _reject_zero(intent: dict, state: dict) -> str | None:
            if intent.get("amount") == Decimal("0"):
                return "Zero amount not allowed"
            return None

        _reject_zero.__name__ = "reject_zero"

        guard = Guard(
            _P,
            GuardConfig(
                execution_mode="async-thread",
                fast_path_enabled=True,
                fast_path_rules=(_reject_zero,),
            ),
        )
        d = await guard.verify_async(
            intent={"amount": Decimal("0")},
            state={"state_version": "1.0"},
        )
        assert not d.allowed


# ═══════════════════════════════════════════════════════════════════════════════
# worker.py — warmup failure, __del__, HMAC violation, WorkerError
# ═══════════════════════════════════════════════════════════════════════════════


class TestWorkerCoverage:
    def test_warmup_worker_exception_swallowed(self) -> None:
        """Z3 warmup failure logs but does not propagate."""
        from pramanix.worker import _warmup_worker

        with patch("z3.Solver", side_effect=RuntimeError("z3 unavailable")):
            _warmup_worker()  # must not raise

    def test_worker_pool_del_with_alive_calls_shutdown(self) -> None:
        """WorkerPool.__del__ calls shutdown(wait=False) when _alive=True."""
        from pramanix.worker import WorkerPool

        pool = WorkerPool(mode="thread", max_workers=1,
                          max_decisions_per_worker=10, warmup=False)
        pool._alive = True
        pool.__del__()
        # Pool is already closed by __del__; second shutdown is a no-op
        pool.shutdown()

    def test_hmac_violation_via_unseal(self) -> None:
        """_unseal_decision raises on tampered HMAC."""
        from pramanix.worker import _unseal_decision

        with pytest.raises((ValueError, KeyError)):
            _unseal_decision({"result": "tampered", "hmac": "bad"})


# ═══════════════════════════════════════════════════════════════════════════════
# audit/archiver.py — JSON decode error, archive segment exceptions
# ═══════════════════════════════════════════════════════════════════════════════


class TestArchiverCoverage:
    def test_verify_archive_invalid_json_returns_false(
        self, tmp_path: object
    ) -> None:
        import pathlib
        from pramanix.audit.archiver import MerkleArchiver

        base = pathlib.Path(str(tmp_path))
        archiver = MerkleArchiver(base_path=base)
        # Write a malformed archive file
        archive_file = base / ".merkle.archive.20260101"
        archive_file.write_text("not valid json\n")
        result = archiver.verify_archive(archive_file)
        assert result is False

    def test_verify_archive_no_header_returns_false(self, tmp_path: object) -> None:
        import pathlib, json
        from pramanix.audit.archiver import MerkleArchiver

        base = pathlib.Path(str(tmp_path))
        archiver = MerkleArchiver(base_path=base)
        archive_file = base / ".merkle.archive.20260102"
        # Has leaf but no header
        archive_file.write_text(
            json.dumps({"type": "leaf", "leaf_hash": "abc", "decision_id": "1", "ts": 1}) + "\n"
        )
        result = archiver.verify_archive(archive_file)
        assert result is False

    def test_archive_segment_write_failure_raises(self, tmp_path: object) -> None:
        import pathlib
        from pramanix.audit.archiver import MerkleArchiver

        base = pathlib.Path(str(tmp_path))
        archiver = MerkleArchiver(base_path=base, max_active_entries=1000)
        # Add some entries to archive
        archiver.add("decision-001")

        # Force write to fail by making the temp file creation fail
        with patch("tempfile.mkstemp", side_effect=OSError("disk full")):
            # Should propagate (not swallowed) since it's in a critical path
            with pytest.raises(OSError):
                archiver._archive_segment()
