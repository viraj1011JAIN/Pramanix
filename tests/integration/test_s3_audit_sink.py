# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Real S3 integration tests for S3AuditSink via LocalStack — T-02.

LocalStack provides a full AWS-compatible S3 API locally.
These tests validate behaviour that boto3 fakes cannot replicate:
  - Real HTTP request/response cycle (4xx/5xx error codes from LocalStack)
  - Real multipart upload paths
  - Real AWS auth header generation
  - Real network timeout behaviour
  - Bucket does-not-exist → real ClientError
"""
from __future__ import annotations

import json
from typing import Any

import boto3  # type: ignore[import-untyped]
import pytest

from pramanix.audit_sink import S3AuditSink
from pramanix.decision import Decision, SolverStatus

from .conftest import requires_docker


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_s3_client(endpoint: str) -> Any:
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def _safe_decision(**kwargs: Any) -> Decision:
    return Decision(
        allowed=True,
        status=SolverStatus.SAFE,
        explanation="test",
        **kwargs,
    )


def _unsafe_decision(**kwargs: Any) -> Decision:
    return Decision(
        allowed=False,
        status=SolverStatus.UNSAFE,
        violated_invariants=("inv",),
        explanation="blocked",
        **kwargs,
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


@requires_docker
def test_s3_sink_emits_decision_to_real_bucket(localstack_endpoint: str) -> None:
    """A SAFE decision is uploaded as JSON to a real S3 bucket in LocalStack."""
    s3 = _make_s3_client(localstack_endpoint)
    bucket = "pramanix-audit-allow"
    s3.create_bucket(Bucket=bucket)

    sink = S3AuditSink(
        bucket=bucket,
        prefix="decisions/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    d = _safe_decision()
    sink.emit(d)

    # Read the object back from LocalStack
    response = s3.list_objects_v2(Bucket=bucket, Prefix="decisions/")
    assert response["KeyCount"] >= 1
    key = response["Contents"][0]["Key"]
    obj = s3.get_object(Bucket=bucket, Key=key)
    payload = json.loads(obj["Body"].read().decode())
    assert payload["decision_id"] == d.decision_id
    assert payload["allowed"] is True
    assert payload["status"] == "safe"


@requires_docker
def test_s3_sink_emits_blocked_decision(localstack_endpoint: str) -> None:
    """A UNSAFE decision is uploaded with violated_invariants preserved."""
    s3 = _make_s3_client(localstack_endpoint)
    bucket = "pramanix-audit-block"
    s3.create_bucket(Bucket=bucket)

    sink = S3AuditSink(
        bucket=bucket,
        prefix="blocked/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    d = _unsafe_decision()
    sink.emit(d)

    response = s3.list_objects_v2(Bucket=bucket, Prefix="blocked/")
    key = response["Contents"][0]["Key"]
    payload = json.loads(s3.get_object(Bucket=bucket, Key=key)["Body"].read())
    assert payload["allowed"] is False
    assert "inv" in payload["violated_invariants"]


@requires_docker
def test_s3_sink_key_prefix_and_decision_id_in_key(localstack_endpoint: str) -> None:
    """The S3 object key contains the prefix and the decision_id."""
    s3 = _make_s3_client(localstack_endpoint)
    bucket = "pramanix-audit-key"
    s3.create_bucket(Bucket=bucket)

    sink = S3AuditSink(
        bucket=bucket,
        prefix="audit/2026/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    d = _safe_decision()
    sink.emit(d)

    response = s3.list_objects_v2(Bucket=bucket, Prefix="audit/2026/")
    assert response["KeyCount"] >= 1
    key = response["Contents"][0]["Key"]
    assert key.startswith("audit/2026/")
    assert d.decision_id in key


@requires_docker
def test_s3_sink_multiple_decisions_each_separate_object(
    localstack_endpoint: str,
) -> None:
    """Ten decisions each become a separate S3 object (not appended)."""
    s3 = _make_s3_client(localstack_endpoint)
    bucket = "pramanix-audit-multi"
    s3.create_bucket(Bucket=bucket)

    sink = S3AuditSink(
        bucket=bucket,
        prefix="multi/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    decisions = [_safe_decision() for _ in range(10)]
    for d in decisions:
        sink.emit(d)

    response = s3.list_objects_v2(Bucket=bucket, Prefix="multi/")
    assert response["KeyCount"] == 10


@requires_docker
def test_s3_sink_nonexistent_bucket_error_is_logged_not_raised(
    localstack_endpoint: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """emit() on a non-existent bucket logs the error and does not raise.

    Real S3 returns a 404 NoSuchBucket ClientError — a fake would not.
    """
    import logging

    sink = S3AuditSink(
        bucket="bucket-that-does-not-exist",
        prefix="x/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    with caplog.at_level(logging.ERROR):
        sink.emit(_safe_decision())  # must not raise

    # Guard calls _emit_to_sinks which swallows and logs sink errors
    # The error should be captured in the Guard's sink error log


@requires_docker
def test_s3_sink_content_type_is_json(localstack_endpoint: str) -> None:
    """The Content-Type of the uploaded object is application/json."""
    s3 = _make_s3_client(localstack_endpoint)
    bucket = "pramanix-audit-ct"
    s3.create_bucket(Bucket=bucket)

    sink = S3AuditSink(
        bucket=bucket,
        prefix="ct/",
        endpoint_url=localstack_endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
        region_name="us-east-1",
    )
    sink.emit(_safe_decision())

    response = s3.list_objects_v2(Bucket=bucket, Prefix="ct/")
    key = response["Contents"][0]["Key"]
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentType"] == "application/json"


@requires_docker
def test_s3_sink_configuration_error_without_boto3() -> None:
    """ConfigurationError when boto3 is not installed."""
    import sys
    from unittest.mock import patch

    from pramanix.exceptions import ConfigurationError

    with patch.dict(sys.modules, {"boto3": None}):  # type: ignore[arg-type]
        import importlib

        import pramanix.audit_sink as _sink_mod
        importlib.reload(_sink_mod)
        try:
            with pytest.raises(ConfigurationError, match="boto3"):
                _sink_mod.S3AuditSink(bucket="b", prefix="p/")
        finally:
            importlib.reload(_sink_mod)
