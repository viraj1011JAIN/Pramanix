# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Dual-model consensus extraction and the RedundantTranslator.

The key public entry-point is :func:`extract_with_consensus` which calls two
translators *concurrently*, validates both responses against the intent schema,
and raises :class:`~pramanix.exceptions.ExtractionMismatchError` if they
disagree on fields required by the configured *agreement_mode*.

This implements Layer 5 of Pramanix's 5-layer prompt-injection defence (see
``docs/security.md``).

Agreement modes
---------------
``strict_keys`` *(default)*
    Every field in the extracted intent must match between both models.  This
    is the recommended mode for financial and medical contexts.

``lenient``
    Only fields listed in *critical_fields* must agree.  Non-critical
    disagreements are logged at WARNING level and the result from model A is
    returned.  Useful when models are known to diverge on low-stakes
    formatting fields (e.g. ``memo``, ``currency_display_name``).

``unanimous``
    Canonical-JSON bitwise equality — the complete serialised dicts must be
    identical.  Functionally equivalent to ``strict_keys`` for flat schemas
    but captures extra-field injection attempts where one model includes
    keys the other omits.
"""
from __future__ import annotations

import asyncio
import enum
import json
import logging
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any, Literal

from pramanix.exceptions import ExtractionFailureError, ExtractionMismatchError, LLMTimeoutError

if TYPE_CHECKING:
    from pydantic import BaseModel

    from pramanix.translator.base import Translator, TranslatorContext

__all__ = [
    "ConsensusStrictness",
    "RedundantTranslator",
    "create_translator",
    "extract_with_consensus",
]

_log = logging.getLogger(__name__)


class ConsensusStrictness(enum.StrEnum):
    """Controls how individual field *values* are compared during consensus.

    ``STRICT``
        Original behaviour — Python ``!=`` equality on model-dumped values.
        ``"500"`` vs ``"500.0"`` → disagree.

    ``SEMANTIC`` *(default)*
        Type-aware comparison:

        * Numeric fields (int, float, Decimal, or string representations
          that parse as Decimal): compared via ``Decimal(str(v))`` so that
          ``"500"``, ``"500.0"``, and ``"5.0E+2"`` are treated as equal.
        * String fields: ``casefold() + strip()`` equality — ``"USD"`` and
          ``"usd"`` agree.
        * Boolean fields: ``bool(v_a) == bool(v_b)``.
        * All other types: falls back to ``==``.
    """

    STRICT = "strict"
    SEMANTIC = "semantic"


# ── Semantic comparison helpers ───────────────────────────────────────────────


def _semantic_field_equal(
    val_a: Any,
    val_b: Any,
    *,
    schema: type[BaseModel] | None = None,
    field_name: str = "",
) -> bool:
    """Compare two field values semantically.

    Resolution order:
    1. Schema annotation (when schema + field_name provided).
    2. Runtime type of the values.
    3. Attempt Decimal conversion (catches numeric string representations).
    4. Exact ``==`` fallback.
    """
    if val_a is None and val_b is None:
        return True
    if val_a is None or val_b is None:
        return False

    # ── Resolve field type from schema annotation ─────────────────────────────
    field_type: type | None = None
    if schema is not None and field_name:
        field_info = schema.model_fields.get(field_name)
        if field_info is not None:
            annotation = field_info.annotation
            # Unwrap Optional[X] → X
            origin = getattr(annotation, "__origin__", None)
            if origin is not None:
                args = getattr(annotation, "__args__", ())
                non_none = [t for t in args if t is not type(None)]
                if len(non_none) == 1:
                    annotation = non_none[0]
            field_type = annotation

    # ── Bool comparison (must precede int check — bool subclasses int) ────────
    if field_type is bool or (isinstance(val_a, bool) and isinstance(val_b, bool)):
        _true_vals = {"true", "1", "yes", "t"}
        _false_vals = {"false", "0", "no", "f"}

        def _norm_bool(v: Any) -> bool | None:
            if isinstance(v, bool):
                return v
            if isinstance(v, int | float):
                return bool(v)
            if isinstance(v, str):
                s = v.strip().lower()
                if s in _true_vals:
                    return True
                if s in _false_vals:
                    return False
            return None

        nb_a = _norm_bool(val_a)
        nb_b = _norm_bool(val_b)
        if nb_a is not None and nb_b is not None:
            return nb_a == nb_b
        return bool(val_a == val_b)

    # ── Numeric type: use Decimal regardless of whether values are strings ────
    # This handles "500" == "500.0" == 500 == 500.0 when the schema says float.
    _numeric = (int, float, Decimal)
    is_numeric_type = field_type in _numeric
    is_numeric_value = isinstance(val_a, _numeric) and isinstance(val_b, _numeric)
    if is_numeric_type or is_numeric_value:
        try:
            return Decimal(str(val_a)) == Decimal(str(val_b))
        except InvalidOperation:
            pass

    # ── String comparison — try Decimal parse first, then casefold ────────────
    # Decimal-first catches numeric-looking strings ("500" vs "500.0") even
    # when the schema annotates the field as str (e.g. a model that serialises
    # amounts as strings).
    if field_type is str or (isinstance(val_a, str) and isinstance(val_b, str)):
        try:
            dec_a = Decimal(str(val_a).strip())
            dec_b = Decimal(str(val_b).strip())
            return dec_a == dec_b
        except InvalidOperation:
            return str(val_a).strip().casefold() == str(val_b).strip().casefold()

    # ── Generic fallback — try Decimal, then exact equality ───────────────────
    try:
        return Decimal(str(val_a)) == Decimal(str(val_b))
    except InvalidOperation:
        pass

    return bool(val_a == val_b)


def _semantic_equal(
    a: dict[str, Any],
    b: dict[str, Any],
    schema: type[BaseModel] | None = None,
) -> tuple[bool, list[str]]:
    """Compare two intent dicts semantically.

    Returns:
        ``(all_equal, disagreeing_fields)`` — a bool and the list of field
        names that differ.  Empty list means full consensus.
    """
    all_keys = set(a.keys()) | set(b.keys())
    disagreeing: list[str] = []

    for key in sorted(all_keys):
        if not _semantic_field_equal(a.get(key), b.get(key), schema=schema, field_name=key):
            disagreeing.append(key)

    return len(disagreeing) == 0, disagreeing


async def extract_with_consensus(
    text: str,
    intent_schema: type[BaseModel],
    translators: tuple[Translator, Translator],
    context: TranslatorContext | None = None,
    *,
    agreement_mode: Literal["strict_keys", "lenient", "unanimous"] = "strict_keys",
    critical_fields: frozenset[str] | None = None,
    injection_threshold: float = 0.5,
    strictness: ConsensusStrictness = ConsensusStrictness.SEMANTIC,
    max_input_chars: int = 512,
    injection_scorer_path: str | None = None,
) -> dict[str, Any]:
    """Call two translators concurrently and require them to agree.

    Both :meth:`~pramanix.translator.base.Translator.extract` calls run via
    ``asyncio.gather`` with ``return_exceptions=True`` so that partial failures
    are diagnosed individually rather than propagating silently from the first
    coroutine to raise.  Both results are independently validated against
    *intent_schema*, then compared according to *agreement_mode*.

    Security pipeline (applied in order):

    1. **Input sanitisation** — Unicode NFKC normalisation, control-char strip,
       injection-pattern detection via :func:`~pramanix.translator._sanitise.sanitise_user_input`.
    2. **Parallel LLM extraction** — both models receive the *sanitised* text.
    3. **Partial-failure gate** — if either model fails, block immediately with
       a diagnostic message naming which model(s) failed.
    4. **Schema validation** — both results must parse against *intent_schema*.
    5. **Consensus check** — fields required by *agreement_mode* must agree.
    6. **Injection confidence gate** — post-consensus heuristic scoring;
       if score ≥ 0.5 the request is blocked with
       :exc:`~pramanix.exceptions.InjectionBlockedError`.

    Args:
        text:            Raw user input (untrusted).
        intent_schema:   Pydantic model class defining the expected output.
        translators:     Exactly two :class:`~pramanix.translator.base.Translator`
                         instances.  They may be of different types (e.g. one
                         OpenAI, one Anthropic).
        context:         Optional host-provided grounding context.
        agreement_mode:  One of ``"strict_keys"`` (default), ``"lenient"``,
                         or ``"unanimous"``.  See module docstring.
        critical_fields: Set of field names that must agree in ``"lenient"``
                         mode.  Ignored for ``"strict_keys"`` and
                         ``"unanimous"``.  When *None* in ``"lenient"`` mode,
                         all fields are treated as critical (same behaviour as
                         ``"strict_keys"``).
        injection_threshold: Post-consensus injection confidence threshold
                         ``[0.0, 1.0]``.  Inputs whose heuristic score meets
                         or exceeds this value are blocked with
                         :exc:`~pramanix.exceptions.InjectionBlockedError`.
                         Raise for stricter deployments (e.g. ``0.3``); lower
                         for domains with legitimate high-entropy inputs such
                         as crypto addresses (e.g. ``0.7``).  Default: ``0.5``.

    Returns:
        A validated ``dict`` from *intent_schema* when consensus is reached.
        In ``"lenient"`` mode the dict from model A is returned when
        non-critical fields differ.

    Raises:
        InjectionBlockedError:   Input was scored as a probable injection attempt.
        ExtractionFailureError:  Either or both models returned invalid JSON,
            failed schema validation, or could not be reached.
        ExtractionMismatchError: The two models disagreed on fields required by
            the configured *agreement_mode*.
        LLMTimeoutError:         One or both models timed out after all retries.
    """
    from pramanix.exceptions import InjectionBlockedError
    from pramanix.translator._sanitise import injection_confidence_score, sanitise_user_input
    from pramanix.translator.injection_filter import InjectionFilter

    # ── Resolve injection scorer (built-in or custom) ─────────────────────────
    # H-16: custom scorers are loaded via importlib entry-points, not exec_module.
    # exec_module allows arbitrary code execution if an attacker controls the path.
    # Callers who need a custom scorer should register it as an entry-point:
    #   [project.entry-points."pramanix.injection_scorers"]
    #   my_scorer = "my_package.scorers:injection_scorer"
    # and pass the entry-point name as injection_scorer_path.
    _scorer_fn = injection_confidence_score
    if injection_scorer_path is not None:
        import importlib.metadata as _meta

        _eps = _meta.entry_points(group="pramanix.injection_scorers")
        _ep = next((e for e in _eps if e.name == injection_scorer_path), None)
        if _ep is None:
            raise ValueError(
                f"No registered injection scorer named {injection_scorer_path!r}. "
                "Register it via the 'pramanix.injection_scorers' entry-point group."
            )
        _scorer_fn = _ep.load()

    # ── Step 0: System 1 fast-path injection filter ───────────────────────────
    # Runs before any LLM call.  Sub-millisecond regex scan; kills obviously
    # malicious prompts without wasting API budget or incurring GPU latency.
    _filter = InjectionFilter()
    _blocked, _reason = _filter.is_injection(text)
    if _blocked:
        raise InjectionBlockedError(
            f"System 1 injection filter blocked input before LLM call. "
            f"{_reason}"
        )

    # ── Step 1: Sanitise input ────────────────────────────────────────────────
    sanitised_text, sanitise_warnings = sanitise_user_input(text, max_length=max_input_chars)

    model_a_name = getattr(translators[0], "model", "translator_a")
    model_b_name = getattr(translators[1], "model", "translator_b")

    # ── Step 2: Parallel extraction with per-failure diagnosis ────────────────
    # return_exceptions=True lets us inspect both outcomes before deciding how
    # to fail.  Without it, a timeout from model A would mask a successful (and
    # potentially suspicious) result from model B.
    raw_results = await asyncio.gather(
        translators[0].extract(sanitised_text, intent_schema, context),
        translators[1].extract(sanitised_text, intent_schema, context),
        return_exceptions=True,
    )
    result_a_raw, result_b_raw = raw_results[0], raw_results[1]

    # ── Step 3: Partial-failure gate ──────────────────────────────────────────
    # Use direct isinstance checks so mypy can narrow the union type
    # (dict[str,Any] | BaseException) to BaseException in each branch.
    if isinstance(result_a_raw, BaseException) and isinstance(result_b_raw, BaseException):
        # Both failed — surface the most actionable exception first
        for exc in (result_a_raw, result_b_raw):
            if isinstance(exc, LLMTimeoutError):
                raise exc
        raise ExtractionFailureError(
            f"Both translators failed — cannot reach consensus. "
            f"[{model_a_name}]: {result_a_raw}. "
            f"[{model_b_name}]: {result_b_raw}."
        ) from result_a_raw

    if isinstance(result_a_raw, BaseException):
        if isinstance(result_a_raw, LLMTimeoutError):
            raise result_a_raw
        raise ExtractionFailureError(
            f"[{model_a_name}] extraction failed while [{model_b_name}] succeeded. "
            "Single-model extraction is insufficient for consensus — blocking. "
            f"Error: {result_a_raw}"
        ) from result_a_raw

    if isinstance(result_b_raw, BaseException):
        if isinstance(result_b_raw, LLMTimeoutError):
            raise result_b_raw
        raise ExtractionFailureError(
            f"[{model_b_name}] extraction failed while [{model_a_name}] succeeded. "
            "Single-model extraction is insufficient for consensus — blocking. "
            f"Error: {result_b_raw}"
        ) from result_b_raw

    # ── Step 4: Schema validation ─────────────────────────────────────────────
    from pydantic import ValidationError as PydanticValidationError

    try:
        instance_a = intent_schema.model_validate(result_a_raw)
    except PydanticValidationError as exc:
        raise ExtractionFailureError(
            f"[{model_a_name}] Schema validation failed after extraction: {exc}"
        ) from exc

    try:
        instance_b = intent_schema.model_validate(result_b_raw)
    except PydanticValidationError as exc:
        raise ExtractionFailureError(
            f"[{model_b_name}] Schema validation failed after extraction: {exc}"
        ) from exc

    # ── Step 5: Consensus check ───────────────────────────────────────────────
    dump_a = instance_a.model_dump()
    dump_b = instance_b.model_dump()

    _enforce_consensus(
        dump_a,
        dump_b,
        model_a_name=model_a_name,
        model_b_name=model_b_name,
        agreement_mode=agreement_mode,
        critical_fields=critical_fields,
        strictness=strictness,
        schema=intent_schema,
    )

    # ── Consensus telemetry ───────────────────────────────────────────────────
    all_checked = set(dump_a.keys()) | set(dump_b.keys())
    if strictness == ConsensusStrictness.STRICT:
        disagreeing_fields = [
            k for k in sorted(all_checked) if dump_a.get(k) != dump_b.get(k)
        ]
    else:
        _, disagreeing_fields = _semantic_equal(dump_a, dump_b, intent_schema)
    _agreed_fields = all_checked - set(disagreeing_fields)
    _log.debug(
        "pramanix.consensus.result",
        extra={
            "consensus_fields_checked": len(all_checked),
            "consensus_fields_agreed": len(_agreed_fields),
            "consensus_fields_disagreed": len(disagreeing_fields),
            "agreement_mode": agreement_mode,
            "strictness": strictness.value,
            "model_a": model_a_name,
            "model_b": model_b_name,
        },
    )

    # ── Step 6: Post-consensus injection confidence gate ─────────────────────
    # Computed *after* both models agree so the actual extracted intent is
    # available as a signal.  This catches adversarial inputs that slip past
    # the injection-pattern regex (e.g. encoded payloads normalised by the LLM).
    score = _scorer_fn(text, dump_a, sanitise_warnings)
    if score >= injection_threshold:
        raise InjectionBlockedError(
            f"Input blocked by injection scorer "
            f"(confidence={score:.2f} ≥ {injection_threshold:.2f}). "
            f"Sanitisation signals: {sanitise_warnings or 'none'}."
        )

    return dump_a


def _enforce_consensus(
    dump_a: dict[str, Any],
    dump_b: dict[str, Any],
    *,
    model_a_name: str,
    model_b_name: str,
    agreement_mode: Literal["strict_keys", "lenient", "unanimous"],
    critical_fields: frozenset[str] | None,
    strictness: ConsensusStrictness = ConsensusStrictness.SEMANTIC,
    schema: type[BaseModel] | None = None,
) -> None:
    """Raise :exc:`ExtractionMismatchError` if consensus requirements are not met.

    Args:
        dump_a:          Validated intent dict from model A.
        dump_b:          Validated intent dict from model B.
        model_a_name:    Display name of model A (for error messages).
        model_b_name:    Display name of model B (for error messages).
        agreement_mode:  Consensus strictness level.
        critical_fields: Fields that must agree in ``"lenient"`` mode.
        strictness:      Whether to compare values semantically (default) or
                         with exact Python equality.
        schema:          Pydantic model class for semantic type resolution.
    """
    all_keys: set[str] = dump_a.keys() | dump_b.keys()

    def _disagrees(k: str) -> bool:
        val_a, val_b = dump_a.get(k), dump_b.get(k)
        if strictness is ConsensusStrictness.SEMANTIC:
            return not _semantic_field_equal(val_a, val_b, schema=schema, field_name=k)
        return val_a != val_b

    if agreement_mode == "unanimous":
        # Bitwise equality on the full canonical dicts.
        # Catches extra-field injection: if one model emits {"amount": 50, "evil": true}
        # and the other emits {"amount": 50}, they disagree → blocked.
        mismatches: dict[str, tuple[object, object]] = {
            k: (dump_a.get(k), dump_b.get(k))
            for k in all_keys
            if _disagrees(k)
        }
        if mismatches:
            field_list = ", ".join(f"'{k}'" for k in mismatches)
            raise ExtractionMismatchError(
                f"Models '{model_a_name}' and '{model_b_name}' disagreed on "
                f"{len(mismatches)} field(s): {field_list}. "
                "Request is ambiguous or potentially adversarial — blocking.",
                model_a=model_a_name,
                model_b=model_b_name,
                mismatches=mismatches,
            )

    elif agreement_mode == "strict_keys":
        # Every declared field must match.  Equivalent to unanimous for flat
        # Pydantic-validated dicts (extra fields are stripped by model_dump()),
        # but documents the intent that each schema field is load-bearing.
        mismatches = {
            k: (dump_a.get(k), dump_b.get(k)) for k in all_keys if _disagrees(k)
        }
        if mismatches:
            field_list = ", ".join(f"'{k}'" for k in mismatches)
            raise ExtractionMismatchError(
                f"Models '{model_a_name}' and '{model_b_name}' disagreed on "
                f"{len(mismatches)} field(s): {field_list}. "
                "Request is ambiguous or potentially adversarial — blocking.",
                model_a=model_a_name,
                model_b=model_b_name,
                mismatches=mismatches,
            )

    elif agreement_mode == "lenient":
        # Only critical_fields must agree; non-critical diffs are logged.
        # When critical_fields is None every field is treated as critical
        # (identical behaviour to strict_keys).
        effective_critical: frozenset[str] = (
            critical_fields if critical_fields is not None else frozenset(all_keys)
        )

        critical_mismatches: dict[str, tuple[object, object]] = {}
        non_critical_mismatches: dict[str, tuple[object, object]] = {}

        for k in all_keys:
            if _disagrees(k):
                if k in effective_critical:
                    critical_mismatches[k] = (dump_a.get(k), dump_b.get(k))
                else:
                    non_critical_mismatches[k] = (dump_a.get(k), dump_b.get(k))

        if non_critical_mismatches:
            _log.warning(
                "pramanix.consensus.lenient_non_critical_mismatch — "
                "non-critical fields differ between models (not blocking): %s",
                {
                    "model_a": model_a_name,
                    "model_b": model_b_name,
                    "mismatches": non_critical_mismatches,
                },
            )

        if critical_mismatches:
            field_list = ", ".join(f"'{k}'" for k in critical_mismatches)
            raise ExtractionMismatchError(
                f"Models '{model_a_name}' and '{model_b_name}' disagreed on "
                f"{len(critical_mismatches)} critical field(s): {field_list}. "
                "Request is ambiguous or potentially adversarial — blocking.",
                model_a=model_a_name,
                model_b=model_b_name,
                mismatches=critical_mismatches,
            )

    else:
        raise ValueError(
            f"Unknown agreement_mode {agreement_mode!r}. "
            "Valid values: 'strict_keys', 'lenient', 'unanimous'."
        )


def create_translator(
    model: str,
    *,
    api_key: str | None = None,
    base_url: str | None = None,
    timeout: float = 30.0,
) -> Translator:
    """Factory: create the correct :class:`~pramanix.translator.base.Translator`
    for *model* based on its name prefix.

    Routing rules:

    * ``"gpt-*"``, ``"o1-*"``, ``"o3-*"``, ``"chatgpt-*"``  → :class:`OpenAICompatTranslator`
    * ``"claude-*"``                                          → :class:`AnthropicTranslator`
    * ``"ollama:<model>"``                                    → :class:`OllamaTranslator`

    Args:
        model:    Model name string.
        api_key:  API key (falls back to the appropriate env var).
        base_url: Base URL override (OpenAI-compatible services only).
        timeout:  Per-request HTTP timeout in seconds.

    Returns:
        A configured translator instance.

    Raises:
        ExtractionFailureError: *model* does not match any known prefix.
    """
    if model.startswith(("gpt-", "o1-", "o3-", "chatgpt-", "text-")):
        from pramanix.translator.openai_compat import OpenAICompatTranslator

        return OpenAICompatTranslator(model, api_key=api_key, base_url=base_url, timeout=timeout)

    if model.startswith("claude-"):
        from pramanix.translator.anthropic import AnthropicTranslator

        return AnthropicTranslator(model, api_key=api_key, timeout=timeout)

    if model.startswith("ollama:"):
        from pramanix.translator.ollama import OllamaTranslator

        # Strip the "ollama:" namespace prefix before passing to OllamaTranslator
        bare_model = model.removeprefix("ollama:")
        return OllamaTranslator(
            bare_model,
            base_url=base_url,
            timeout=timeout,
        )

    if model.startswith("gemini:"):
        from pramanix.translator.gemini import GeminiTranslator

        bare_model = model.removeprefix("gemini:")
        return GeminiTranslator(bare_model, api_key=api_key, timeout=timeout)

    if model.startswith("cohere:"):
        from pramanix.translator.cohere import CohereTranslator

        bare_model = model.removeprefix("cohere:")
        return CohereTranslator(bare_model, api_key=api_key, timeout=timeout)

    if model.startswith("mistral:"):
        from pramanix.translator.mistral import MistralTranslator

        bare_model = model.removeprefix("mistral:")
        return MistralTranslator(bare_model, api_key=api_key, timeout=timeout)

    if model.startswith("llama:"):
        from pramanix.translator.llamacpp import LlamaCppTranslator

        # "llama:" prefix uses the remainder as the model file path.
        model_path = model.removeprefix("llama:")
        return LlamaCppTranslator(model_path)

    raise ExtractionFailureError(
        f"Cannot infer translator for model '{model}'. "
        "Supported prefixes: 'gpt-', 'o1-', 'o3-', 'chatgpt-', 'claude-', 'ollama:', "
        "'gemini:', 'cohere:', 'mistral:', 'llama:'. "
        "Pass an explicit Translator instance to bypass auto-routing."
    )


class RedundantTranslator:
    """Wraps two :class:`~pramanix.translator.base.Translator` instances and
    delegates to :func:`extract_with_consensus`.

    The ``RedundantTranslator`` itself satisfies the
    :class:`~pramanix.translator.base.Translator` protocol, so it can be
    composed or nested.

    Args:
        translator_a:    First translator.
        translator_b:    Second translator.
        agreement_mode:  Consensus strictness level passed to
                         :func:`extract_with_consensus`.  Defaults to
                         ``"strict_keys"``.
        critical_fields: Fields that must agree in ``"lenient"`` mode.
                         Ignored for other modes.

    Example::

        redundant = RedundantTranslator(
            OpenAICompatTranslator("gpt-4o"),
            AnthropicTranslator("claude-opus-4-5"),
            agreement_mode="lenient",
            critical_fields=frozenset({"amount", "recipient_id"}),
        )
        intent_dict = await redundant.extract(prompt, MyIntentSchema)
    """

    def __init__(
        self,
        translator_a: Translator,
        translator_b: Translator,
        *,
        agreement_mode: Literal["strict_keys", "lenient", "unanimous"] = "strict_keys",
        critical_fields: frozenset[str] | None = None,
        injection_threshold: float = 0.5,
        strictness: ConsensusStrictness = ConsensusStrictness.SEMANTIC,
    ) -> None:
        self._a = translator_a
        self._b = translator_b
        self._agreement_mode: Literal["strict_keys", "lenient", "unanimous"] = agreement_mode
        self._critical_fields = critical_fields
        self._injection_threshold = injection_threshold
        self._strictness = strictness
        # Expose a composite model name for logging / error messages
        name_a = getattr(translator_a, "model", "a")
        name_b = getattr(translator_b, "model", "b")
        self.model = f"redundant({name_a}+{name_b})"

    async def extract(
        self,
        text: str,
        intent_schema: type[BaseModel],
        context: TranslatorContext | None = None,
    ) -> dict[str, Any]:
        """Run consensus extraction using both wrapped translators."""
        return await extract_with_consensus(
            text,
            intent_schema,
            (self._a, self._b),
            context,
            agreement_mode=self._agreement_mode,
            critical_fields=self._critical_fields,
            injection_threshold=self._injection_threshold,
            strictness=self._strictness,
        )
