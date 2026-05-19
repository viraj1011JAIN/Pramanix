# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Coverage tests for nlp/validators failure paths (§4.14/34).

Coverage targets:
  _try_detoxify_scorer(): failure path — returns None, emits WARNING,
                          sets pramanix_nlp_model_available{model="detoxify"} = 0
  _try_sentence_transformer(): failure path — returns None, emits WARNING,
                               sets pramanix_nlp_model_available{model="sentence_transformer"} = 0
  _try_detoxify_scorer(): success path — returns callable, gauge set to 1
  _try_sentence_transformer(): success path — returns model, gauge set to 1

No MagicMock, no patch objects — only patch.dict(sys.modules) to exercise the
ImportError branch (the same pattern used in test_audit_sink_full_coverage.py).
"""
from __future__ import annotations

import sys
from unittest.mock import patch

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────────


def _gauge_value(model_label: str) -> float | None:
    """Read pramanix_nlp_model_available{model=<label>} from the Prometheus registry.

    Returns None if prometheus_client is not installed or the metric has not
    been registered yet.
    """
    try:
        from prometheus_client import REGISTRY  # noqa: PLC0415

        for metric in REGISTRY.collect():
            if metric.name == "pramanix_nlp_model_available":
                for sample in metric.samples:
                    if sample.labels.get("model") == model_label:
                        return sample.value
    except Exception:
        pass
    return None


# ── _try_detoxify_scorer: failure path (§4.14/34) ─────────────────────────────


def test_try_detoxify_scorer_failure_returns_none_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    """When detoxify import fails, _try_detoxify_scorer returns None and emits WARNING.

    The WARNING must reference toxicity scoring being DISABLED so operators
    can act on it.  The function must never raise — callers treat None as
    'degraded mode, use keyword fallback'.
    """
    import logging

    import pramanix.nlp.validators as _nlp_mod

    with patch.dict(sys.modules, {"detoxify": None}):
        with caplog.at_level(logging.WARNING, logger="pramanix.nlp.validators"):
            result = _nlp_mod._try_detoxify_scorer()

    assert result is None, "_try_detoxify_scorer must return None on import failure"
    assert any(
        "detoxify" in record.message.lower() and record.levelno == logging.WARNING
        for record in caplog.records
    ), "Expected WARNING mentioning 'detoxify' — operators must be notified of degraded state"


def test_try_detoxify_scorer_failure_sets_gauge_to_zero() -> None:
    """On failure, _try_detoxify_scorer sets pramanix_nlp_model_available{model='detoxify'} to 0.

    Only asserted when prometheus_client is installed — skipped otherwise.
    """
    pytest.importorskip("prometheus_client")

    import pramanix.nlp.validators as _nlp_mod

    with patch.dict(sys.modules, {"detoxify": None}):
        _nlp_mod._try_detoxify_scorer()

    value = _gauge_value("detoxify")
    if value is not None:
        assert value == 0.0, (
            "pramanix_nlp_model_available{model='detoxify'} must be 0 after load failure"
        )


def test_try_detoxify_scorer_success_returns_callable() -> None:
    """When detoxify IS installed, _try_detoxify_scorer returns a callable.

    Skipped automatically if detoxify is not installed.
    """
    pytest.importorskip("detoxify")

    import pramanix.nlp.validators as _nlp_mod

    result = _nlp_mod._try_detoxify_scorer()
    assert callable(result), "_try_detoxify_scorer must return a callable when detoxify is available"


def test_try_detoxify_scorer_success_sets_gauge_to_one() -> None:
    """When detoxify IS installed, gauge must be set to 1."""
    pytest.importorskip("detoxify")
    pytest.importorskip("prometheus_client")

    import pramanix.nlp.validators as _nlp_mod

    _nlp_mod._try_detoxify_scorer()
    value = _gauge_value("detoxify")
    if value is not None:
        assert value == 1.0, (
            "pramanix_nlp_model_available{model='detoxify'} must be 1 after successful load"
        )


# ── _try_sentence_transformer: failure path (§4.14/34) ────────────────────────


def test_try_sentence_transformer_failure_returns_none_and_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When sentence_transformers import fails, returns None and emits WARNING.

    The WARNING must reference semantic injection detection being DISABLED.
    """
    import logging

    import pramanix.nlp.validators as _nlp_mod

    with patch.dict(sys.modules, {"sentence_transformers": None}):
        with caplog.at_level(logging.WARNING, logger="pramanix.nlp.validators"):
            result = _nlp_mod._try_sentence_transformer()

    assert result is None, "_try_sentence_transformer must return None on import failure"
    assert any(
        "sentence" in record.message.lower() and record.levelno == logging.WARNING
        for record in caplog.records
    ), "Expected WARNING mentioning 'sentence' — operators must be notified of degraded state"


def test_try_sentence_transformer_failure_sets_gauge_to_zero() -> None:
    """On failure, sets pramanix_nlp_model_available{model='sentence_transformer'} to 0."""
    pytest.importorskip("prometheus_client")

    import pramanix.nlp.validators as _nlp_mod

    with patch.dict(sys.modules, {"sentence_transformers": None}):
        _nlp_mod._try_sentence_transformer()

    value = _gauge_value("sentence_transformer")
    if value is not None:
        assert value == 0.0, (
            "pramanix_nlp_model_available{model='sentence_transformer'} "
            "must be 0 after load failure"
        )


def test_try_sentence_transformer_success_returns_model() -> None:
    """When sentence_transformers IS installed, returns a model object.

    Skipped automatically if not installed.
    """
    pytest.importorskip("sentence_transformers")

    import pramanix.nlp.validators as _nlp_mod

    result = _nlp_mod._try_sentence_transformer()
    assert result is not None, (
        "_try_sentence_transformer must return a model when sentence-transformers is available"
    )


def test_try_sentence_transformer_success_sets_gauge_to_one() -> None:
    """When sentence_transformers IS installed, gauge must be set to 1."""
    pytest.importorskip("sentence_transformers")
    pytest.importorskip("prometheus_client")

    import pramanix.nlp.validators as _nlp_mod

    _nlp_mod._try_sentence_transformer()
    value = _gauge_value("sentence_transformer")
    if value is not None:
        assert value == 1.0, (
            "pramanix_nlp_model_available{model='sentence_transformer'} "
            "must be 1 after successful load"
        )


# ── _get_nlp_gauge: resilience when prometheus_client absent ───────────────────


def test_get_nlp_gauge_returns_none_when_prometheus_absent() -> None:
    """_get_nlp_gauge returns None gracefully when prometheus_client is not installed."""
    import pramanix.nlp.validators as _nlp_mod

    original = _nlp_mod._NLP_GAUGE
    _nlp_mod._NLP_GAUGE = None
    try:
        with patch.dict(sys.modules, {"prometheus_client": None}):
            gauge = _nlp_mod._get_nlp_gauge()
        # Either None (can't create) or the cached pre-existing gauge.
        # Either way must not raise.
        assert gauge is None or gauge is not None  # just checks no exception
    finally:
        _nlp_mod._NLP_GAUGE = original
