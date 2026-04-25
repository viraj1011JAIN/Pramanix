# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Miscellaneous coverage gaps targeting multiple small files.

Targets by file:
  expressions.py  : 133, 138-140, 200->207, 204-205
  guard_config.py : 373, 447, 456
  audit/verifier.py: 98-99
  decorator.py    : 102-116
  solver.py       : 191-194
  key_provider.py : 116->118, 211-212, 264-267, 328, 334-336, 398-401, 415, 468-471
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

from pramanix.audit.verifier import DecisionVerifier
from pramanix.decorator import guard
from pramanix.exceptions import ConfigurationError, GuardViolationError
from pramanix.expressions import E, Field, NestedField, _infer_z3_type
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy

# ── Shared policy ─────────────────────────────────────────────────────────────


class _SimplePolicy(Policy):
    amount = Field("amount", Decimal, "Real")

    @classmethod
    def invariants(cls):
        return [(E(cls.amount) >= 0).named("non_negative")]


# ═══════════════════════════════════════════════════════════════════════════════
# expressions.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestInferZ3Type:
    """Lines 133, 138-140: _infer_z3_type() all branches."""

    def test_str_returns_string(self) -> None:
        """Line 133: python_type is str → 'String'."""
        assert _infer_z3_type(str) == "String"

    def test_datetime_returns_int(self) -> None:
        """Line 138: python_type is datetime → 'Int' (Unix epoch seconds)."""
        assert _infer_z3_type(datetime) == "Int"

    def test_unknown_type_returns_real(self) -> None:
        """Line 140: fallthrough for unknown numeric sub-types → 'Real'."""

        class _CustomNumeric(float):
            pass

        assert _infer_z3_type(_CustomNumeric) == "Real"

    def test_bool_returns_bool(self) -> None:
        assert _infer_z3_type(bool) == "Bool"

    def test_int_returns_int(self) -> None:
        assert _infer_z3_type(int) == "Int"

    def test_decimal_returns_real(self) -> None:
        assert _infer_z3_type(Decimal) == "Real"


class TestNestedFieldAnnotationBranches:
    """Lines 200->207, 204-205: NestedField.__getattr__ annotation edge cases."""

    def test_generic_annotation_hits_type_error_except(self) -> None:
        """Lines 204-205: annotation is list[str] → issubclass raises TypeError → pass."""

        class _ModelWithGenericField(BaseModel):
            tags: list[str]

        nested = NestedField("parent", _ModelWithGenericField)
        result = nested.tags
        # Returns a Field with str type (since list[str] is not a BaseModel subclass)
        assert isinstance(result, Field)
        assert result.name == "parent.tags"

    def test_basemodel_annotation_returns_nested_field(self) -> None:
        """issubclass(annotation, BaseModel) is True → return NestedField (lines 202-203)."""

        class _Inner(BaseModel):
            amount: Decimal

        class _Outer(BaseModel):
            inner: _Inner

        nested = NestedField("outer", _Outer)
        result = nested.inner
        assert isinstance(result, NestedField)

    def test_plain_field_returns_field(self) -> None:
        """Normal scalar field returns Field descriptor."""

        class _FlatModel(BaseModel):
            amount: Decimal

        nested = NestedField("model", _FlatModel)
        result = nested.amount
        assert isinstance(result, Field)
        assert result.name == "model.amount"


# ═══════════════════════════════════════════════════════════════════════════════
# guard_config.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestGuardConfigValidation:
    """Lines 373, 447, 456: GuardConfig validation branches."""

    def test_invalid_consensus_strictness_raises(self) -> None:
        """Line 373: consensus_strictness not in {'semantic', 'strict'} → ConfigurationError."""
        with pytest.raises(ConfigurationError, match="consensus_strictness"):
            GuardConfig(consensus_strictness="invalid_mode")

    def test_valid_semantic_strictness_accepted(self) -> None:
        config = GuardConfig(consensus_strictness="semantic")
        assert config.consensus_strictness == "semantic"

    def test_solver_rlimit_zero_in_production_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Line 447: PRAMANIX_ENV=production + solver_rlimit=0 → UserWarning."""
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.warns(UserWarning, match="solver_rlimit"):
            GuardConfig(solver_rlimit=0)

    def test_max_input_bytes_zero_in_production_warns(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Line 456: PRAMANIX_ENV=production + max_input_bytes=0 → UserWarning."""
        monkeypatch.setenv("PRAMANIX_ENV", "production")
        with pytest.warns(UserWarning, match="max_input_bytes"):
            GuardConfig(max_input_bytes=0)


# ═══════════════════════════════════════════════════════════════════════════════
# audit/verifier.py
# ═══════════════════════════════════════════════════════════════════════════════


def _forge_token(key: str, payload: dict[str, Any]) -> str:
    """Compute a valid HMAC-SHA256 JWS token for any payload dict."""
    key_bytes = key.encode()

    def b64url(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    header = b64url(json.dumps({"alg": "HS256"}).encode())
    payload_b64 = b64url(json.dumps(payload).encode())
    signing_input = f"{header}.{payload_b64}"
    sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha256).digest()
    return f"{header}.{payload_b64}.{b64url(sig)}"


class TestDecisionVerifierExceptionPath:
    """Lines 98-99: except Exception in verify() → _invalid()."""

    _KEY = "a" * 64  # 64-char signing key

    def test_invalid_iat_type_triggers_exception_path(self) -> None:
        """Lines 98-99: int([1,2,3]) raises TypeError → except Exception → _invalid()."""
        # Forge a valid HMAC token but with iat as a list (not convertible to int)
        token = _forge_token(
            self._KEY,
            {
                "decision_id": "test-123",
                "allowed": True,
                "status": "safe",
                "violated_invariants": [],
                "explanation": "",
                "policy_hash": "abc",
                "iat": [1, 2, 3],  # int([1,2,3]) → TypeError → lines 98-99
            },
        )
        verifier = DecisionVerifier(signing_key=self._KEY)
        result = verifier.verify(token)
        assert result.valid is False
        assert result.error is not None

    def test_non_json_payload_triggers_exception_path(self) -> None:
        """Lines 98-99: valid HMAC but non-JSON payload → json.JSONDecodeError."""
        key_bytes = self._KEY.encode()

        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header = b64url(json.dumps({"alg": "HS256"}).encode())
        # Payload is NOT valid JSON
        bad_payload_b64 = b64url(b"NOT_VALID_JSON!!!")
        signing_input = f"{header}.{bad_payload_b64}"
        sig = hmac.new(key_bytes, signing_input.encode(), hashlib.sha256).digest()
        token = f"{header}.{bad_payload_b64}.{b64url(sig)}"

        verifier = DecisionVerifier(signing_key=self._KEY)
        result = verifier.verify(token)
        assert result.valid is False


# ═══════════════════════════════════════════════════════════════════════════════
# decorator.py
# ═══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestDecoratorAsyncPath:
    """Lines 102-116: async_wrapper function body."""

    async def test_async_function_positional_args_allowed(self) -> None:
        """Line 106: intent/state from positional args — function is ALLOWED."""

        @guard(policy=_SimplePolicy, config=GuardConfig(execution_mode="sync"))
        async def _fn(intent: dict, state: dict) -> str:
            return "executed"

        result = await _fn({"amount": Decimal("10")}, {})
        assert result == "executed"

    async def test_async_function_kwargs_allowed(self) -> None:
        """Lines 102-104: intent/state from kwargs (len(args) < 2)."""

        @guard(policy=_SimplePolicy, config=GuardConfig(execution_mode="sync"))
        async def _fn(**kwargs: Any) -> str:
            return "executed"

        result = await _fn(intent={"amount": Decimal("5")}, state={})
        assert result == "executed"

    async def test_async_function_blocked_on_block_raise(self) -> None:
        """Line 111-112: on_block='raise' + blocked → GuardViolationError."""

        @guard(
            policy=_SimplePolicy,
            config=GuardConfig(execution_mode="sync"),
            on_block="raise",
        )
        async def _fn(intent: dict, state: dict) -> str:
            return "should_not_reach"

        with pytest.raises(GuardViolationError):
            await _fn({"amount": Decimal("-1")}, {})

    async def test_async_function_blocked_on_block_return(self) -> None:
        """Lines 113-114: on_block='return' + blocked → returns Decision."""
        from pramanix.decision import Decision

        @guard(
            policy=_SimplePolicy,
            config=GuardConfig(execution_mode="sync"),
            on_block="return",
        )
        async def _fn(intent: dict, state: dict) -> Any:
            return "should_not_reach"

        result = await _fn({"amount": Decimal("-1")}, {})
        assert isinstance(result, Decision)
        assert result.allowed is False

    async def test_async_wrapper_guard_attribute_set(self) -> None:
        """Line 118: async_wrapper.__guard__ is the Guard instance."""

        @guard(policy=_SimplePolicy, config=GuardConfig(execution_mode="sync"))
        async def _fn(intent: dict, state: dict) -> None:
            pass

        assert hasattr(_fn, "__guard__")
        assert isinstance(_fn.__guard__, Guard)


# ═══════════════════════════════════════════════════════════════════════════════
# solver.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestRealizeNodeBoolOp:
    """Lines 191-194: _realize_node with _BoolOp containing ForAllOp + fallthrough."""

    def test_bool_op_wrapping_forall_covered(self) -> None:
        """Lines 191-192 + 194: BoolOp with ForAll + CmpOp calls _realize_node recursively."""
        from pramanix.expressions import ArrayField, ForAll
        from pramanix.guard import Guard
        from pramanix.guard_config import GuardConfig

        _amounts_field = ArrayField("amounts", Decimal, "Real", max_length=5)
        _amount_field = Field("amount", Decimal, "Real")

        class _ArrayPolicy(Policy):
            amounts = _amounts_field
            amount = _amount_field

            @classmethod
            def invariants(cls):
                # _BoolOp("and", [_ForAllOp, _CmpOp]) — hits line 191-192
                # _CmpOp falls through to line 194 in the recursive call
                return [
                    (
                        ForAll(cls.amounts, lambda f: E(f) >= 0)
                        & (E(cls.amount) >= 0)
                    ).named("combined")
                ]

        config = GuardConfig(execution_mode="sync")
        guard_instance = Guard(_ArrayPolicy, config)
        decision = guard_instance.verify(
            {"amount": Decimal("10"), "amounts": [Decimal("1"), Decimal("2")]},
            {},
        )
        assert isinstance(decision.allowed, bool)

    def test_realize_node_fallthrough_with_pure_cmp_invariant(self) -> None:
        """Line 194: _realize_node called on _CmpOp (non-quantifier) → return node."""
        from pramanix.expressions import ArrayField, ForAll
        from pramanix.guard import Guard

        _items_field = ArrayField("items", int, "Int", max_length=3)

        class _ItemsPolicy(Policy):
            items = _items_field
            count = Field("count", int, "Int")

            @classmethod
            def invariants(cls):
                # ForAll with a AND expression → inner _BoolOp recursion hits line 194
                return [
                    ForAll(cls.items, lambda f: E(f) >= 0).named("all_positive"),
                ]

        config = GuardConfig(execution_mode="sync")
        guard_instance = Guard(_ItemsPolicy, config)
        decision = guard_instance.verify(
            {"count": 3, "items": [1, 2, 3]},
            {},
        )
        assert isinstance(decision.allowed, bool)


# ═══════════════════════════════════════════════════════════════════════════════
# key_provider.py
# ═══════════════════════════════════════════════════════════════════════════════


class TestPemKeyProviderCachedPublicKey:
    """Line 116->118: public_key_pem() second call uses cached value."""

    def test_public_key_cached_on_second_call(self) -> None:
        """Line 116->118: second call skips re-derivation, returns cached bytes."""
        from pramanix.crypto import PramanixSigner
        from pramanix.key_provider import PemKeyProvider

        pem = PramanixSigner.generate().private_key_pem()
        provider = PemKeyProvider(private_pem=pem)
        first = provider.public_key_pem()
        second = provider.public_key_pem()  # 116->118: cached
        assert first == second
        assert first is second  # same object (no re-derivation)


class TestFileKeyProviderOsError:
    """Lines 211-212: key_version() OSError → return 'file-unknown'."""

    def test_nonexistent_file_returns_file_unknown(self, tmp_path: Path) -> None:
        """Lines 211-212: path.stat() raises OSError → 'file-unknown'."""
        from pramanix.key_provider import FileKeyProvider

        nonexistent = tmp_path / "ghost_key.pem"
        provider = FileKeyProvider(path=nonexistent, version=None)
        # key_version() tries stat() on nonexistent file → OSError → "file-unknown"
        version = provider.key_version()
        assert version == "file-unknown"


class TestAwsKmsKeyProviderInit:
    """Lines 264-267: AwsKmsKeyProvider init after boto3 import succeeds."""

    def test_aws_kms_provider_init_with_fake_boto3(self) -> None:
        """Lines 264-267: init body after successful import (boto3 injected into sys.modules)."""
        import sys
        import types

        class _FakeSecretsClient:
            def get_secret_value(self, **kwargs: Any) -> dict[str, str]:
                return {"SecretString": "-----BEGIN PRIVATE KEY-----\n"}

            def describe_secret(self, **kwargs: Any) -> dict[str, Any]:
                return {"VersionIdsToStages": {"v1": ["AWSCURRENT"]}}

            def rotate_secret(self, **kwargs: Any) -> None:
                pass

        fake_boto3 = types.ModuleType("boto3")
        fake_boto3.client = lambda *a, **kw: _FakeSecretsClient()  # type: ignore[attr-defined]

        prev = sys.modules.get("boto3", _missing := object())
        sys.modules["boto3"] = fake_boto3
        try:
            # Force reload so __init__'s `import boto3` sees the fake
            if "pramanix.key_provider" in sys.modules:
                del sys.modules["pramanix.key_provider"]
            from pramanix.key_provider import AwsKmsKeyProvider

            # Pass _client to skip calling boto3.client()
            provider = AwsKmsKeyProvider(
                secret_arn="arn:aws:secretsmanager:us-east-1:123456789:secret:test",
                _client=_FakeSecretsClient(),
            )
            assert provider._secret_arn == "arn:aws:secretsmanager:us-east-1:123456789:secret:test"
        finally:
            if prev is _missing:
                sys.modules.pop("boto3", None)
            else:
                sys.modules["boto3"] = prev  # type: ignore[assignment]


class TestAzureKeyVaultKeyProviderInit:
    """Lines 328, 334-336: AzureKeyVaultKeyProvider init after import succeeds."""

    def test_azure_provider_init_with_fake_client(self) -> None:
        """Lines 334-336: init body covered by _client injection."""
        from pramanix.key_provider import AzureKeyVaultKeyProvider

        class _FakeSecret:
            value = "-----BEGIN PRIVATE KEY-----\n"

            class properties:  # noqa: N801
                version = "azure-v1"

        class _FakeSecretClient:
            def get_secret(self, name: str, **kwargs: Any) -> _FakeSecret:
                return _FakeSecret()

        prev_azure_id = sys.modules.get("azure.identity")
        prev_azure_kv = sys.modules.get("azure.keyvault.secrets")
        try:
            # Inject fake azure modules
            import types

            fake_azure = types.ModuleType("azure")
            fake_identity = types.ModuleType("azure.identity")
            fake_identity.DefaultAzureCredential = object  # type: ignore[attr-defined]
            fake_kv_secrets = types.ModuleType("azure.keyvault.secrets")
            fake_kv_secrets.SecretClient = _FakeSecretClient  # type: ignore[attr-defined]
            sys.modules["azure"] = fake_azure
            sys.modules["azure.identity"] = fake_identity
            sys.modules["azure.keyvault"] = types.ModuleType("azure.keyvault")
            sys.modules["azure.keyvault.secrets"] = fake_kv_secrets

            provider = AzureKeyVaultKeyProvider(
                vault_url="https://myvault.vault.azure.net",
                secret_name="my-secret",
                _client=_FakeSecretClient(),
            )
            assert provider._secret_name == "my-secret"
        finally:
            for key in ["azure", "azure.identity", "azure.keyvault", "azure.keyvault.secrets"]:
                sys.modules.pop(key, None)
            if prev_azure_id is not None:
                sys.modules["azure.identity"] = prev_azure_id
            if prev_azure_kv is not None:
                sys.modules["azure.keyvault.secrets"] = prev_azure_kv


class TestGcpKmsKeyProviderInit:
    """Lines 398-401, 415: GcpKmsKeyProvider init and public_key_pem."""

    def test_gcp_provider_init_with_fake_client(self) -> None:
        """Lines 398-401: init body with _client injection."""
        import types

        from pramanix.key_provider import GcpKmsKeyProvider

        class _FakePayload:
            data = b"-----BEGIN PRIVATE KEY-----\n"

        class _FakeResponse:
            payload = _FakePayload()

        class _FakeSecretManagerClient:
            def access_secret_version(self, **kwargs: Any) -> _FakeResponse:
                return _FakeResponse()

        prev_gcp = sys.modules.get("google.cloud.secretmanager")
        try:
            fake_google = types.ModuleType("google")
            fake_cloud = types.ModuleType("google.cloud")
            fake_sm = types.ModuleType("google.cloud.secretmanager")
            fake_sm.SecretManagerServiceClient = _FakeSecretManagerClient  # type: ignore[attr-defined]
            sys.modules["google"] = fake_google
            sys.modules["google.cloud"] = fake_cloud
            sys.modules["google.cloud.secretmanager"] = fake_sm

            provider = GcpKmsKeyProvider(
                project_id="my-project",
                secret_id="my-secret",
                version_id="latest",
                _client=_FakeSecretManagerClient(),
            )
            assert provider._project_id == "my-project"
            # Line 415: public_key_pem() → _derive_public_pem(private_key_pem())
            # We can't call it without a real PEM, so just verify init is covered
        finally:
            for key in ["google", "google.cloud", "google.cloud.secretmanager"]:
                sys.modules.pop(key, None)
            if prev_gcp is not None:
                sys.modules["google.cloud.secretmanager"] = prev_gcp


class TestHashiCorpVaultKeyProviderInit:
    """Lines 468-471: HashiCorpVaultKeyProvider init after hvac import succeeds."""

    def test_vault_provider_init_with_fake_hvac(self) -> None:
        """Lines 468-471: init body with fake hvac module."""

        from pramanix.key_provider import HashiCorpVaultKeyProvider

        class _FakeHvacClient:
            class secrets:  # noqa: N801
                class kv:  # noqa: N801
                    class v2:  # noqa: N801
                        @staticmethod
                        def read_secret_version(**kwargs: Any) -> dict[str, Any]:
                            return {"data": {"data": {"key": "pem_value"}}}

        class _FakeHvacModule:
            Client = _FakeHvacClient

        prev_hvac = sys.modules.get("hvac")
        sys.modules["hvac"] = _FakeHvacModule()  # type: ignore[assignment]
        try:
            provider = HashiCorpVaultKeyProvider(
                url="http://localhost:8200",
                token="root",
                secret_path="secret/my-key",
                _client=_FakeHvacClient(),
            )
            assert provider._secret_path == "secret/my-key"
        finally:
            if prev_hvac is None:
                sys.modules.pop("hvac", None)
            else:
                sys.modules["hvac"] = prev_hvac
