# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Unit tests for pramanix.primitives.fintech — 10 FinTech primitives.

Coverage: SAT pass, UNSAT fail, exact boundary for each primitive.
All monetary fields use Decimal / "Real" sort — no float drift.

Primitives under test
---------------------
SufficientBalance, VelocityCheck, AntiStructuring, WashSaleDetection,
CollateralHaircut, MaxDrawdown, SanctionsScreen, KYCTierCheck,
TradingWindowCheck, MarginRequirement
"""
from __future__ import annotations

from decimal import Decimal

import pytest

from pramanix.expressions import Field
from pramanix.primitives.fintech import (
    AntiStructuring,
    CollateralHaircut,
    KYCTierCheck,
    MarginRequirement,
    MaxDrawdown,
    SanctionsScreen,
    SufficientBalance,
    TradingWindowCheck,
    VelocityCheck,
    WashSaleDetection,
)
from pramanix.solver import solve

# ── Field declarations ────────────────────────────────────────────────────────

_balance = Field("balance", Decimal, "Real")
_amount = Field("amount", Decimal, "Real")
_tx_count = Field("tx_count", int, "Int")
_cumulative_amount = Field("cumulative_amount", Decimal, "Real")
_sell_epoch = Field("sell_epoch", int, "Int")
_buy_epoch = Field("buy_epoch", int, "Int")
_collateral = Field("collateral", Decimal, "Real")
_loan = Field("loan", Decimal, "Real")
_current_nav = Field("current_nav", Decimal, "Real")
_peak_nav = Field("peak_nav", Decimal, "Real")
_counterparty_flagged = Field("counterparty_flagged", bool, "Bool")
_kyc_tier = Field("kyc_tier", int, "Int")
_time_of_day_secs = Field("time_of_day_secs", int, "Int")
_account_equity = Field("account_equity", Decimal, "Real")
_position_value = Field("position_value", Decimal, "Real")


# ═══════════════════════════════════════════════════════════════════════════════
# SufficientBalance
# BSA / Reg. E: balance - amount >= 0
# ═══════════════════════════════════════════════════════════════════════════════

_INV_SUFFICIENT_BALANCE = [SufficientBalance(_balance, _amount)]


class TestSufficientBalance:
    def test_sat_balance_exceeds_amount(self) -> None:
        result = solve(
            _INV_SUFFICIENT_BALANCE,
            {"balance": Decimal("500.00"), "amount": Decimal("200.00")},
            timeout_ms=5_000,
        )
        assert result.sat is True
        assert result.violated == []

    def test_unsat_overdraft(self) -> None:
        result = solve(
            _INV_SUFFICIENT_BALANCE,
            {"balance": Decimal("100.00"), "amount": Decimal("200.00")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "sufficient_balance" for v in result.violated)

    def test_boundary_exact_zero_post_balance(self) -> None:
        """Exact zero — constraint is >= 0 so this MUST be SAT."""
        result = solve(
            _INV_SUFFICIENT_BALANCE,
            {"balance": Decimal("100.00"), "amount": Decimal("100.00")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_one_cent_below_fails(self) -> None:
        result = solve(
            _INV_SUFFICIENT_BALANCE,
            {"balance": Decimal("99.99"), "amount": Decimal("100.00")},
            timeout_ms=5_000,
        )
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# VelocityCheck
# EBA PSD2: tx_count <= window_limit
# ═══════════════════════════════════════════════════════════════════════════════

_INV_VELOCITY = [VelocityCheck(_tx_count, window_limit=5)]


class TestVelocityCheck:
    def test_sat_under_limit(self) -> None:
        result = solve(_INV_VELOCITY, {"tx_count": 3}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_over_limit(self) -> None:
        result = solve(_INV_VELOCITY, {"tx_count": 6}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "velocity_check" for v in result.violated)

    def test_boundary_at_exactly_limit(self) -> None:
        result = solve(_INV_VELOCITY, {"tx_count": 5}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# AntiStructuring
# 31 CFR § 1020.320: cumulative_amount < $10,000
# ═══════════════════════════════════════════════════════════════════════════════

_THRESHOLD = Decimal("10000")
_INV_STRUCTURING = [AntiStructuring(_cumulative_amount, _THRESHOLD)]


class TestAntiStructuring:
    def test_sat_below_threshold(self) -> None:
        result = solve(_INV_STRUCTURING, {"cumulative_amount": Decimal("9999.99")}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_at_threshold(self) -> None:
        """Exactly $10,000 triggers CTR — constraint is strictly < threshold."""
        result = solve(_INV_STRUCTURING, {"cumulative_amount": Decimal("10000.00")}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "anti_structuring" for v in result.violated)

    def test_unsat_above_threshold(self) -> None:
        result = solve(_INV_STRUCTURING, {"cumulative_amount": Decimal("10500.00")}, timeout_ms=5_000)
        assert result.sat is False

    def test_boundary_one_cent_below(self) -> None:
        result = solve(_INV_STRUCTURING, {"cumulative_amount": Decimal("9999.99")}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# WashSaleDetection
# IRC § 1091: |sell_epoch - buy_epoch| >= 30 * 86400
# ═══════════════════════════════════════════════════════════════════════════════

_WASH_WINDOW_SECS = 30 * 86_400  # 2_592_000
_INV_WASH_SALE = [WashSaleDetection(_sell_epoch, _buy_epoch, wash_window_days=30)]


class TestWashSaleDetection:
    def test_sat_sale_long_after_buy(self) -> None:
        """Sale is 60 days after buy — safely outside the wash window."""
        buy = 1_700_000_000
        sell = buy + 60 * 86_400
        result = solve(_INV_WASH_SALE, {"sell_epoch": sell, "buy_epoch": buy}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_within_wash_window(self) -> None:
        """Sale is only 10 days after buy — inside the 30-day window."""
        buy = 1_700_000_000
        sell = buy + 10 * 86_400
        result = solve(_INV_WASH_SALE, {"sell_epoch": sell, "buy_epoch": buy}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "wash_sale_detection" for v in result.violated)

    def test_boundary_exactly_30_days_forward(self) -> None:
        """Exactly 30 days ahead — meets >= condition, SAT."""
        buy = 1_700_000_000
        sell = buy + _WASH_WINDOW_SECS
        result = solve(_INV_WASH_SALE, {"sell_epoch": sell, "buy_epoch": buy}, timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_exactly_30_days_reverse(self) -> None:
        """Buy is exactly 30 days after sell — also valid (abs-free DSL OR branch)."""
        sell = 1_700_000_000
        buy = sell + _WASH_WINDOW_SECS
        result = solve(_INV_WASH_SALE, {"sell_epoch": sell, "buy_epoch": buy}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# CollateralHaircut
# Basel III / ISDA CSA: collateral * (1 - haircut) >= loan
# ═══════════════════════════════════════════════════════════════════════════════

_HAIRCUT = Decimal("0.15")  # 15% haircut
_INV_HAIRCUT = [CollateralHaircut(_collateral, _loan, _HAIRCUT)]


class TestCollateralHaircut:
    def test_sat_ample_collateral(self) -> None:
        result = solve(
            _INV_HAIRCUT,
            {"collateral": Decimal("1000000"), "loan": Decimal("800000")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_insufficient_collateral_after_haircut(self) -> None:
        # collateral * 0.85 = 850,000; loan = 900,000 → UNSAT
        result = solve(
            _INV_HAIRCUT,
            {"collateral": Decimal("1000000"), "loan": Decimal("900000")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "collateral_haircut" for v in result.violated)

    def test_boundary_exact_break_even(self) -> None:
        # collateral * 0.85 == loan exactly
        # collateral = 1,000,000; haircut = 0.15; effective = 850,000
        result = solve(
            _INV_HAIRCUT,
            {"collateral": Decimal("1000000"), "loan": Decimal("850000")},
            timeout_ms=5_000,
        )
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# MaxDrawdown
# AIFMD / CPO: (peak - current) <= max_pct * peak
# ═══════════════════════════════════════════════════════════════════════════════

_MAX_DD_PCT = Decimal("0.20")  # 20% max drawdown
_INV_MAX_DD = [MaxDrawdown(_current_nav, _peak_nav, _MAX_DD_PCT)]


class TestMaxDrawdown:
    def test_sat_within_drawdown_limit(self) -> None:
        # peak=100, current=85 → drawdown=15% < 20%
        result = solve(
            _INV_MAX_DD,
            {"current_nav": Decimal("85"), "peak_nav": Decimal("100")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_drawdown_exceeded(self) -> None:
        # peak=100, current=70 → drawdown=30% > 20%
        result = solve(
            _INV_MAX_DD,
            {"current_nav": Decimal("70"), "peak_nav": Decimal("100")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "max_drawdown" for v in result.violated)

    def test_boundary_exact_max_drawdown(self) -> None:
        # peak=100, current=80 → drawdown=20% == 20% → SAT (<=)
        result = solve(
            _INV_MAX_DD,
            {"current_nav": Decimal("80"), "peak_nav": Decimal("100")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_one_below_is_unsat(self) -> None:
        # peak=100, current=79.99 → drawdown=20.01% > 20%
        result = solve(
            _INV_MAX_DD,
            {"current_nav": Decimal("79.99"), "peak_nav": Decimal("100")},
            timeout_ms=5_000,
        )
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# SanctionsScreen
# OFAC SDN / 31 CFR § 501.805: counterparty_flagged == False
# ═══════════════════════════════════════════════════════════════════════════════

_INV_SANCTIONS = [SanctionsScreen(_counterparty_flagged)]


class TestSanctionsScreen:
    def test_sat_clean_counterparty(self) -> None:
        result = solve(_INV_SANCTIONS, {"counterparty_flagged": False}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_sanctioned_counterparty(self) -> None:
        result = solve(_INV_SANCTIONS, {"counterparty_flagged": True}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "sanctions_screen" for v in result.violated)


# ═══════════════════════════════════════════════════════════════════════════════
# KYCTierCheck
# FATF Rec. 10 / FinCEN CDD Rule: kyc_tier >= required_tier
# ═══════════════════════════════════════════════════════════════════════════════

_INV_KYC = [KYCTierCheck(_kyc_tier, required_tier=2)]


class TestKYCTierCheck:
    def test_sat_sufficient_kyc(self) -> None:
        result = solve(_INV_KYC, {"kyc_tier": 3}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_insufficient_kyc(self) -> None:
        result = solve(_INV_KYC, {"kyc_tier": 1}, timeout_ms=5_000)
        assert result.sat is False
        assert any(v.label == "kyc_tier_check" for v in result.violated)

    def test_boundary_exactly_required_tier(self) -> None:
        result = solve(_INV_KYC, {"kyc_tier": 2}, timeout_ms=5_000)
        assert result.sat is True

    def test_unsat_zero_tier(self) -> None:
        result = solve(_INV_KYC, {"kyc_tier": 0}, timeout_ms=5_000)
        assert result.sat is False


# ═══════════════════════════════════════════════════════════════════════════════
# TradingWindowCheck
# SEC Rule 10b5-1: window_open <= time_of_day_secs <= window_close
# NYSE: 09:30–16:00 ET = 34200–57600 seconds
# ═══════════════════════════════════════════════════════════════════════════════

_WINDOW_OPEN = 34_200   # 09:30 ET
_WINDOW_CLOSE = 57_600  # 16:00 ET
_INV_TRADING = [TradingWindowCheck(_time_of_day_secs, _WINDOW_OPEN, _WINDOW_CLOSE)]


class TestTradingWindowCheck:

    def test_sat_within_trading_hours(self) -> None:
        result = solve(_INV_TRADING, {"time_of_day_secs": 43_200}, timeout_ms=5_000)  # noon
        assert result.sat is True

    def test_unsat_before_market_open(self) -> None:
        result = solve(_INV_TRADING, {"time_of_day_secs": 30_000}, timeout_ms=5_000)  # 08:20 ET
        assert result.sat is False
        assert any(v.label == "trading_window_check" for v in result.violated)

    def test_unsat_after_market_close(self) -> None:
        result = solve(_INV_TRADING, {"time_of_day_secs": 60_000}, timeout_ms=5_000)  # 16:40 ET
        assert result.sat is False

    def test_boundary_at_open(self) -> None:
        result = solve(_INV_TRADING, {"time_of_day_secs": _WINDOW_OPEN}, timeout_ms=5_000)
        assert result.sat is True

    def test_boundary_at_close(self) -> None:
        result = solve(_INV_TRADING, {"time_of_day_secs": _WINDOW_CLOSE}, timeout_ms=5_000)
        assert result.sat is True


# ═══════════════════════════════════════════════════════════════════════════════
# MarginRequirement
# Reg. T (12 CFR § 220): account_equity >= 0.50 * position_value
# ═══════════════════════════════════════════════════════════════════════════════

_MIN_MARGIN = Decimal("0.50")
_INV_MARGIN = [MarginRequirement(_account_equity, _position_value, _MIN_MARGIN)]


class TestMarginRequirement:
    def test_sat_equity_above_margin(self) -> None:
        result = solve(
            _INV_MARGIN,
            {"account_equity": Decimal("60000"), "position_value": Decimal("100000")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_unsat_margin_call(self) -> None:
        result = solve(
            _INV_MARGIN,
            {"account_equity": Decimal("40000"), "position_value": Decimal("100000")},
            timeout_ms=5_000,
        )
        assert result.sat is False
        assert any(v.label == "margin_requirement" for v in result.violated)

    def test_boundary_exactly_50_pct(self) -> None:
        result = solve(
            _INV_MARGIN,
            {"account_equity": Decimal("50000"), "position_value": Decimal("100000")},
            timeout_ms=5_000,
        )
        assert result.sat is True

    def test_boundary_one_cent_below_fails(self) -> None:
        result = solve(
            _INV_MARGIN,
            {"account_equity": Decimal("49999.99"), "position_value": Decimal("100000")},
            timeout_ms=5_000,
        )
        assert result.sat is False
