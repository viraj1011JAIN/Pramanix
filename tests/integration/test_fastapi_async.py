# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Integration tests — FastAPI endpoint with async Guard verification.

Tests:
* No asyncio.get_event_loop() errors
* No RuntimeError from nested event loops
* Decision returned correctly to endpoint
* state_version present in response
"""
from __future__ import annotations

from decimal import Decimal

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")
pytest.importorskip("httpx", reason="httpx not installed")

from fastapi import FastAPI  # type: ignore[import-not-found]  # noqa: E402
from fastapi.testclient import TestClient  # type: ignore[import-not-found]  # noqa: E402

from pramanix import E, Field, Guard, GuardConfig, Policy  # noqa: E402
from pramanix.decision import SolverStatus  # noqa: E402
from pramanix.expressions import ConstraintExpr  # noqa: E402

# ── Test policy ───────────────────────────────────────────────────────────────


class TransferPolicy(Policy):
    class Meta:
        name = "fastapi_transfer"
        version = "1.0"

    balance = Field("balance", Decimal, "Real")
    amount = Field("amount", Decimal, "Real")
    daily_limit = Field("daily_limit", Decimal, "Real")

    @classmethod
    def invariants(cls) -> list[ConstraintExpr]:
        return [
            (E(cls.balance) - E(cls.amount) >= 0).named("non_negative_balance"),
            (E(cls.amount) <= E(cls.daily_limit)).named("within_daily_limit"),
        ]


# ── FastAPI app ───────────────────────────────────────────────────────────────

_guard = Guard(TransferPolicy, GuardConfig(execution_mode="sync"))
app = FastAPI(title="Pramanix FastAPI Test")


@app.post("/transfer")  # type: ignore[untyped-decorator]
async def transfer_endpoint(payload: dict[str, object]) -> dict[str, object]:
    """Transfer endpoint — calls verify_async() from an async context."""
    intent = {"amount": Decimal(str(payload["amount"]))}
    state = {
        "balance": Decimal(str(payload["balance"])),
        "daily_limit": Decimal(str(payload["daily_limit"])),
        "state_version": payload.get("state_version", "1.0"),
    }
    decision = await _guard.verify_async(intent=intent, state=state)
    return {
        "allowed": decision.allowed,
        "status": decision.status.value,
        "violated_invariants": list(decision.violated_invariants),
        "explanation": decision.explanation,
        "state_version": payload.get("state_version", "1.0"),
    }


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


class TestFastAPIAsync:
    def test_allowed_transfer(self, client: TestClient) -> None:
        resp = client.post(
            "/transfer",
            json={
                "amount": "100",
                "balance": "1000",
                "daily_limit": "5000",
                "state_version": "1.0",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is True
        assert body["status"] == SolverStatus.SAFE.value

    def test_overdraft_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/transfer",
            json={
                "amount": "5000",
                "balance": "100",
                "daily_limit": "10000",
                "state_version": "1.0",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is False
        assert body["status"] == SolverStatus.UNSAFE.value
        assert "non_negative_balance" in body["violated_invariants"]

    def test_daily_limit_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/transfer",
            json={
                "amount": "6000",
                "balance": "10000",
                "daily_limit": "5000",
                "state_version": "1.0",
            },
        )
        body = resp.json()
        assert body["allowed"] is False
        assert "within_daily_limit" in body["violated_invariants"]

    def test_state_version_in_response(self, client: TestClient) -> None:
        """state_version must always be returned in the response."""
        resp = client.post(
            "/transfer",
            json={
                "amount": "100",
                "balance": "500",
                "daily_limit": "1000",
                "state_version": "1.0",
            },
        )
        body = resp.json()
        assert "state_version" in body
        assert body["state_version"] == "1.0"

    def test_no_event_loop_errors(self, client: TestClient) -> None:
        """Calling verify_async() from an ASGI context must not raise loop errors."""
        # TestClient uses a sync/thread bridge — no nested event loop errors expected
        for _ in range(5):
            resp = client.post(
                "/transfer",
                json={
                    "amount": "50",
                    "balance": "500",
                    "daily_limit": "1000",
                    "state_version": "1.0",
                },
            )
            assert resp.status_code == 200

    def test_stale_state_version_blocked(self, client: TestClient) -> None:
        resp = client.post(
            "/transfer",
            json={
                "amount": "100",
                "balance": "500",
                "daily_limit": "1000",
                "state_version": "99.0",  # wrong version
            },
        )
        body = resp.json()
        assert body["allowed"] is False
        assert body["status"] == SolverStatus.STALE_STATE.value
