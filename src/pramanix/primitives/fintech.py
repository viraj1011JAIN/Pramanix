# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""HFT / FinTech constraint primitives for Pramanix policies.

.. warning:: **Legal disclaimer — not legal or compliance advice**

   These primitives encode *formal constraint logic* derived from publicly
   available regulatory text (31 CFR, IRC, 12 CFR, etc.).  They are provided
   for illustrative and educational purposes only.  They do **not** constitute
   legal, compliance, or financial advice, and they do **not** guarantee
   compliance with any applicable law or regulation.

   Regulatory requirements differ by jurisdiction, are subject to change, and
   require interpretation by qualified legal and compliance professionals.  You
   are solely responsible for ensuring that your use of these primitives is
   appropriate for your specific context and for obtaining any required legal
   or regulatory review before deploying them in production systems.

   Anthropic, Viraj Jain, and the Pramanix contributors make no representations
   or warranties regarding the accuracy, completeness, or fitness for purpose of
   these primitives, and disclaim all liability for any regulatory penalties,
   losses, or damages arising from their use.

Each factory returns a :class:`~pramanix.expressions.ConstraintExpr` with
``.named()`` and ``.explain()`` pre-set, ready to include in a Policy's
``invariants()`` list.

All monetary fields MUST be declared with ``z3_type="Real"`` to preserve
exact Decimal arithmetic — never use ``"Real"`` with raw Python floats.

Regulatory coverage
-------------------
* ``AntiStructuring``       — 31 CFR § 1020.320 (BSA structuring rule)
* ``WashSaleDetection``     — IRC § 1091 (30-day wash-sale window)
* ``SanctionsScreen``       — OFAC SDN / 31 CFR § 501.805
* ``VelocityCheck``         — EBA PSD2 / Reg. E velocity-monitoring guidance
* ``MarginRequirement``     — Reg. T (12 CFR § 220) initial margin
* ``CollateralHaircut``     — Basel III / ISDA CSA haircut schedule
* ``MaxDrawdown``           — AIFMD Annex IV / CPO drawdown disclosure rule
* ``KYCTierCheck``          — FATF Recommendation 10 / FinCEN CDD rule
* ``TradingWindowCheck``    — SEC Rule 10b5-1 / FINRA MRVP trading window
* ``SufficientBalance``     — BSA / Reg. E pre-authorization balance check

Example::

    from decimal import Decimal
    from pramanix import Policy, Field
    from pramanix.primitives.fintech import (
        SufficientBalance, AntiStructuring, SanctionsScreen,
    )

    class WirePolicy(Policy):
        balance               = Field("balance",               Decimal, "Real")
        amount                = Field("amount",                Decimal, "Real")
        cumulative_amount     = Field("cumulative_amount",     Decimal, "Real")
        counterparty_flagged  = Field("counterparty_flagged",  bool,    "Bool")

        @classmethod
        def invariants(cls):
            return [
                SufficientBalance(cls.balance, cls.amount),
                AntiStructuring(cls.cumulative_amount, Decimal("10000")),
                SanctionsScreen(cls.counterparty_flagged),
            ]
"""
from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from pramanix.expressions import E

if TYPE_CHECKING:
    from pramanix.expressions import ConstraintExpr, Field

__all__ = [
    "AntiStructuring",
    "CollateralHaircut",
    "KYCTierCheck",
    "MarginRequirement",
    "MaxDrawdown",
    "RiskScoreLimit",
    "SanctionsScreen",
    "SufficientBalance",
    "TradingWindowCheck",
    "VelocityCheck",
    "WashSaleDetection",
]


def SufficientBalance(balance: Field, amount: Field) -> ConstraintExpr:
    """Enforce that the post-transfer balance remains non-negative.

    DSL: ``E(balance) - E(amount) >= 0``

    Regulatory: BSA / Reg. E — a payment processor must verify sufficient
    funds before authorising any debit.

    Args:
        balance: Field (Decimal, Real) — current account balance.
        amount:  Field (Decimal, Real) — requested transfer amount.
    """
    return (
        (E(balance) - E(amount) >= Decimal("0"))
        .named("sufficient_balance")
        .explain(
            "Transfer blocked: balance ({balance}) minus amount ({amount}) "
            "would be negative. (BSA / Reg. E pre-authorisation check)"
        )
    )


def VelocityCheck(tx_count: Field, window_limit: int) -> ConstraintExpr:
    """Enforce that transaction velocity does not exceed the rolling window cap.

    DSL: ``E(tx_count) <= window_limit``

    Regulatory: EBA PSD2 / Reg. E velocity-monitoring guidance — SCA-exempt
    low-value transactions must be capped at 5 consecutive or 100 EUR/day.

    Args:
        tx_count:     Field (int, Int) — number of transactions in the window.
        window_limit: Maximum allowed transactions in that window (literal int).
    """
    return (
        (E(tx_count) <= window_limit)
        .named("velocity_check")
        .explain(
            "Velocity limit breached: {tx_count} transactions exceed "
            f"the window cap of {window_limit}. (EBA PSD2 velocity-monitoring)"
        )
    )


def AntiStructuring(cumulative_amount: Field, threshold: Decimal) -> ConstraintExpr:
    """Detect potential structuring below the CTR filing threshold.

    DSL: ``E(cumulative_amount) < threshold``

    Regulatory: 31 CFR § 1020.320 — "structuring" is the practice of breaking
    transactions below $10,000 to evade Currency Transaction Report (CTR) filing.
    This constraint flags any cumulative amount that approaches but stays under
    the threshold, allowing downstream SAR-filing logic to trigger.

    Note: This primitive asserts that the cumulative amount must remain strictly
    *below* threshold.  A violation (SAT=False) signals a structuring pattern
    that warrants Suspicious Activity Report investigation.

    Args:
        cumulative_amount: Field (Decimal, Real) — rolling 24-h aggregate.
        threshold:         CTR filing threshold (default $10,000 per 31 CFR § 1020.320).
    """
    return (
        (E(cumulative_amount) < threshold)
        .named("anti_structuring")
        .explain(
            "Structuring alert: cumulative amount ({cumulative_amount}) "
            f"meets or exceeds CTR threshold of {threshold}. "
            "(31 CFR § 1020.320 — BSA structuring rule)"
        )
    )


def WashSaleDetection(
    sell_epoch: Field,
    buy_epoch: Field,
    wash_window_days: int = 30,
) -> ConstraintExpr:
    """Enforce the 30-day wash-sale disallowance window.

    DSL (abs-free reformulation):
    ``(E(sell) - E(buy) >= window_secs) | (E(buy) - E(sell) >= window_secs)``

    The Z3 DSL has no symbolic ``abs()``, so the absolute-value condition
    ``|sell_epoch - buy_epoch| >= window_secs`` is expressed as a disjunction:
    either the sale was at least *window_secs* after the buy, or the buy was
    at least *window_secs* after the sale.

    Regulatory: IRC § 1091 — If a taxpayer sells or trades a security at a
    loss and buys a "substantially identical" security within 30 days before
    or after the sale, the loss is disallowed.

    Args:
        sell_epoch:        Field (int, Int) — UNIX timestamp of sale.
        buy_epoch:         Field (int, Int) — UNIX timestamp of repurchase.
        wash_window_days:  Wash-sale window in calendar days (default 30).
    """
    window_secs = wash_window_days * 86_400
    return (
        (
            (E(sell_epoch) - E(buy_epoch) >= window_secs)
            | (E(buy_epoch) - E(sell_epoch) >= window_secs)
        )
        .named("wash_sale_detection")
        .explain(
            "Wash-sale violation: buy/sell timestamps ({buy_epoch}, {sell_epoch}) "
            f"are within the {wash_window_days}-day disallowance window. "
            "(IRC § 1091)"
        )
    )


def CollateralHaircut(
    collateral_value: Field,
    loan_value: Field,
    haircut_pct: Decimal,
) -> ConstraintExpr:
    """Enforce that haircutted collateral covers the loan exposure.

    DSL: ``E(collateral) * (1 - haircut_pct) >= E(loan)``

    Regulatory: Basel III LCR / ISDA CSA — a haircut is applied to collateral
    market value to account for price volatility and forced-sale discount.
    Typical haircuts: G10 govvies 0-2 %, IG corps 5-15 %, equities 15-25 %.

    Args:
        collateral_value: Field (Decimal, Real) — current mark-to-market collateral.
        loan_value:       Field (Decimal, Real) — net exposure / loan notional.
        haircut_pct:      Decimal in [0, 1) — Basel III / CSA agreed haircut rate.
    """
    effective_collateral = E(collateral_value) * (Decimal("1") - haircut_pct)
    return (
        (effective_collateral >= E(loan_value))
        .named("collateral_haircut")
        .explain(
            "Collateral shortfall: {collateral_value} after "
            f"{haircut_pct * 100:.2f}% haircut is insufficient for loan {'{loan_value}'}. "
            "(Basel III LCR / ISDA CSA haircut schedule)"
        )
    )


def MaxDrawdown(
    current_nav: Field,
    peak_nav: Field,
    max_drawdown_pct: Decimal,
) -> ConstraintExpr:
    """Enforce that the portfolio drawdown does not exceed the disclosed maximum.

    DSL (reformulated to avoid division): ``E(peak) - E(current) <= max_pct * E(peak)``

    Equivalent to ``(peak - current) / peak <= max_pct`` assuming ``peak > 0``,
    but avoids symbolic division which can cause Z3 non-linear performance issues.

    Regulatory: AIFMD Annex IV (Art. 24) / NFA CFTC CPO drawdown disclosure —
    Alternative Investment Fund Managers must report maximum historical drawdown
    and may not exceed disclosed limits.

    Args:
        current_nav:      Field (Decimal, Real) — current portfolio NAV.
        peak_nav:         Field (Decimal, Real) — rolling high-water-mark NAV.
        max_drawdown_pct: Decimal in (0, 1] — maximum permitted drawdown fraction.
    """
    return (
        (E(peak_nav) - E(current_nav) <= max_drawdown_pct * E(peak_nav))
        .named("max_drawdown")
        .explain(
            "Drawdown limit breached: peak_nav={peak_nav}, current_nav={current_nav} "
            f"exceeds {max_drawdown_pct * 100:.2f}% maximum drawdown. "
            "(AIFMD Annex IV / CPO drawdown disclosure rule)"
        )
    )


def SanctionsScreen(counterparty_status: Field) -> ConstraintExpr:
    """Block transactions with OFAC-sanctioned counterparties.

    DSL: ``E(counterparty_status) != "SANCTIONED"``

    Encoding: The field must be a String-sorted Z3 variable
    (``Field(..., str, "String")``).  Supported states:

    * ``"CLEAR"``      — counterparty passed all watchlist checks.
    * ``"SANCTIONED"`` — counterparty appears on OFAC SDN / EU / UN list.
    * ``"REVIEW"``     — pending manual AML review; treat as blocked.

    This string-based encoding supports multi-state OFAC workflows without
    requiring separate Bool fields per watchlist.

    Regulatory: 31 CFR § 501.805 (OFAC) / OFAC SDN list — US persons are
    prohibited from transacting with SDN-listed parties.  Penalties: up to
    $1M per violation.

    Args:
        counterparty_status: Field (str, String) — OFAC screening result.
            Must be one of ``"CLEAR"``, ``"SANCTIONED"``, or ``"REVIEW"``.
    """
    return (
        (E(counterparty_status) != "SANCTIONED")
        .named("sanctions_screen")
        .explain(
            'Transaction blocked: counterparty_status="{counterparty_status}" '
            "matches OFAC SDN / sanctions watchlist. (31 CFR § 501.805)"
        )
    )


def RiskScoreLimit(risk_score: Field, max_risk: Decimal) -> ConstraintExpr:
    """Enforce that a counterparty or transaction risk score does not exceed
    the configured ceiling.

    DSL: ``E(risk_score) <= max_risk``

    Risk scores are produced by AML/fraud models (range 0-1000 or 0.0-1.0
    depending on the scoring engine).  A score above ``max_risk`` triggers a
    block and routes the transaction to manual review.

    Regulatory: FinCEN CDD Rule (31 CFR § 1010.230) / FATF Recommendation 10
    — covered institutions must apply risk-based customer due diligence and
    may not process transactions whose risk profile exceeds internal limits.

    Args:
        risk_score: Field (Decimal, Real) — numeric risk score from the
            AML / fraud scoring engine.
        max_risk:   Decimal — maximum permitted risk score (inclusive).
    """
    return (
        (E(risk_score) <= max_risk)
        .named("risk_score_limit")
        .explain(
            f"Risk score {{risk_score}} exceeds maximum threshold {max_risk}. "
            "Route to manual AML review. "
            "(FinCEN CDD Rule 31 CFR § 1010.230 / FATF Rec. 10)"
        )
    )


def KYCTierCheck(kyc_tier: Field, required_tier: int) -> ConstraintExpr:
    """Enforce that the customer's KYC tier meets the required level.

    DSL: ``E(kyc_tier) >= required_tier``

    KYC tiers (FATF / FinCEN CDD):
    * 0 — Anonymous (no CDD performed)
    * 1 — Simplified Due Diligence (SDD)
    * 2 — Standard CDD (name, DOB, address verified)
    * 3 — Enhanced Due Diligence (EDD — PEP/adverse media screened)

    Regulatory: FATF Recommendation 10 / 31 CFR § 1020.220 (FinCEN CDD Rule) —
    financial institutions must verify customer identity commensurate with risk.

    Args:
        kyc_tier:      Field (int, Int) — customer's completed KYC tier (0-3).
        required_tier: Minimum KYC tier required for this product/transaction.
    """
    return (
        (E(kyc_tier) >= required_tier)
        .named("kyc_tier_check")
        .explain(
            "KYC tier insufficient: customer tier ({kyc_tier}) is below "
            f"required tier {required_tier}. "
            "(FATF Recommendation 10 / FinCEN CDD Rule 31 CFR § 1020.220)"
        )
    )


def TradingWindowCheck(
    time_of_day_secs: Field,
    window_open_secs: int,
    window_close_secs: int,
) -> ConstraintExpr:
    """Enforce that a trade is placed within the permitted trading window.

    DSL: ``(E(time_of_day_secs) >= window_open) & (E(time_of_day_secs) <= window_close)``

    Note: Modulo arithmetic is not supported in the Z3 DSL.  The caller must
    supply a pre-computed ``time_of_day_secs`` field (``epoch % 86400``).

    Regulatory: SEC Rule 10b5-1(c) / FINRA MRVP — insider-trading prevention
    plans must confine executions to pre-announced trading windows.  Common
    window: NYSE 09:30-16:00 ET = 34200-57600 seconds past midnight UTC-5.

    Args:
        time_of_day_secs: Field (int, Int) — seconds since midnight (caller computes epoch % 86400).
        window_open_secs: Start of trading window in seconds since midnight (inclusive).
        window_close_secs: End of trading window in seconds since midnight (inclusive).
    """
    return (
        ((E(time_of_day_secs) >= window_open_secs) & (E(time_of_day_secs) <= window_close_secs))
        .named("trading_window_check")
        .explain(
            "Trade rejected: time_of_day_secs={time_of_day_secs} is outside the permitted "
            f"window [{window_open_secs}s-{window_close_secs}s]. "
            "(SEC Rule 10b5-1(c) / FINRA MRVP trading window)"
        )
    )


def MarginRequirement(
    account_equity: Field,
    position_value: Field,
    min_margin_pct: Decimal,
) -> ConstraintExpr:
    """Enforce Reg. T initial margin — equity must cover a minimum fraction of position value.

    DSL: ``E(account_equity) >= min_margin_pct * E(position_value)``

    Reg. T sets initial margin at 50 % of long equity positions.  Portfolio
    Margin (SEC Rule 15c3-1a) allows risk-based margin as low as 15 %.

    Regulatory: 12 CFR § 220 (Regulation T — Federal Reserve Board) — brokers
    must require customers to deposit at least 50 % of the purchase price of
    marginable securities on the initial trade.

    Args:
        account_equity:  Field (Decimal, Real) — customer's current equity / buying power.
        position_value:  Field (Decimal, Real) — notional value of the position.
        min_margin_pct:  Decimal in (0, 1] — minimum margin fraction (Reg. T default 0.5).
    """
    return (
        (E(account_equity) >= min_margin_pct * E(position_value))
        .named("margin_requirement")
        .explain(
            "Margin call: account_equity ({account_equity}) is below "
            f"{min_margin_pct * 100:.2f}% of position_value ({{position_value}}). "
            "(Reg. T — 12 CFR § 220)"
        )
    )
