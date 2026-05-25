# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Policy dry-run / simulation mode.

This module provides :class:`PolicyDryRun`, a lightweight wrapper that runs a
:class:`~pramanix.policy.Policy` against a batch of ``(intent, state)`` example
pairs and reports whether each example would be **allowed** or **blocked** —
without side-effects (no audit sinks, no execution tokens, no metrics).

The primary use-cases are:

1. **Policy authorship feedback loop** — authors can rapidly iterate on guard
   expressions by running ``.simulate()`` and inspecting which examples flip
   between allowed/blocked as invariants change.

2. **Pre-deployment smoke-testing** — CI pipelines can assert golden examples
   remain in the expected state before a policy is rolled out.

3. **Documentation generation** — the :class:`DryRunResult` list can be
   serialised to YAML/JSON as human-readable documentation of policy behaviour.

Quick-start::

    from pramanix.dry_run import PolicyDryRun, DryRunResult
    from my_policy import PaymentPolicy

    runner = PolicyDryRun(
        PaymentPolicy,
        examples=[
            ({"action": "transfer"}, {"balance": 500, "limit": 1000}),
            ({"action": "transfer"}, {"balance": 2000, "limit": 1000}),
        ],
    )
    results: list[DryRunResult] = runner.simulate()
    for r in results:
        print(r.would_allow, r.decision.status, r.explanation)

References §6.7 item 9 of flaws.md.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from pramanix.decision import Decision
from pramanix.guard import Guard
from pramanix.guard_config import GuardConfig
from pramanix.policy import Policy

__all__ = ["DryRunResult", "PolicyDryRun"]


@dataclass(frozen=True)
class DryRunResult:
    """Immutable result for one ``(intent, state)`` example in a dry run.

    Attributes:
        index:       Zero-based position of this example in the input list.
        intent:      The raw intent dict or Pydantic model that was verified.
        state:       The raw state dict or Pydantic model that was verified.
        decision:    The :class:`~pramanix.decision.Decision` from the guard.
        would_allow: ``True`` if the policy would permit this example.
        explanation: Human-readable summary from the decision (may be empty).
    """

    index: int
    intent: dict[str, Any] | BaseModel
    state: dict[str, Any] | BaseModel
    decision: Decision
    would_allow: bool
    explanation: str = field(default="")

    def __post_init__(self) -> None:
        # Cross-check: would_allow must agree with decision.allowed.
        if self.would_allow is not self.decision.allowed:
            raise ValueError(
                f"DryRunResult.would_allow ({self.would_allow!r}) disagrees with "
                f"decision.allowed ({self.decision.allowed!r}) — these must match."
            )


_DRY_RUN_CONFIG = GuardConfig(
    execution_mode="sync",
    # Disable timing jitter so dry runs complete without artificial delay.
    min_response_ms=0.0,
    # Disable all audit sinks — dry runs must have zero side-effects.
    audit_sinks=[],
)


class PolicyDryRun:
    """Run a batch of ``(intent, state)`` examples through a policy and report results.

    Instantiate with a :class:`~pramanix.policy.Policy` subclass and a list of
    ``(intent, state)`` pairs.  Call :meth:`simulate` to receive a
    :class:`DryRunResult` for each example.

    Args:
        policy:   A :class:`~pramanix.policy.Policy` subclass (the class, not
                  an instance).
        examples: A sequence of ``(intent, state)`` pairs.  Each element may be
                  a plain ``dict`` or a Pydantic :class:`~pydantic.BaseModel`.
        config:   Optional :class:`~pramanix.guard_config.GuardConfig`.
                  Defaults to a side-effect-free config with no audit sinks and
                  no timing jitter.  Override to inject custom solver factories
                  or clocks in tests.

    Raises:
        TypeError:  If *policy* is not a subclass of
                    :class:`~pramanix.policy.Policy`.
        ValueError: If *examples* is empty.

    Example::

        runner = PolicyDryRun(MyPolicy, examples=[
            ({"action": "read"}, {"role": "admin"}),
            ({"action": "delete"}, {"role": "viewer"}),
        ])
        results = runner.simulate()
        allowed = [r for r in results if r.would_allow]
        blocked = [r for r in results if not r.would_allow]
    """

    def __init__(
        self,
        policy: type[Policy],
        examples: list[tuple[dict[str, Any] | BaseModel, dict[str, Any] | BaseModel]],
        *,
        config: GuardConfig | None = None,
    ) -> None:
        if not (isinstance(policy, type) and issubclass(policy, Policy)):
            raise TypeError(f"policy must be a subclass of Policy, got {policy!r}.")
        if not examples:
            raise ValueError("examples must not be empty — provide at least one pair.")
        self._policy = policy
        self._examples = list(examples)
        self._config = config if config is not None else _DRY_RUN_CONFIG

    @property
    def policy(self) -> type[Policy]:
        """The Policy subclass under simulation."""
        return self._policy

    @property
    def examples(self) -> list[tuple[dict[str, Any] | BaseModel, dict[str, Any] | BaseModel]]:
        """The list of (intent, state) pairs to simulate."""
        return list(self._examples)

    def simulate(self) -> list[DryRunResult]:
        """Verify every ``(intent, state)`` example and return results.

        Each example is run through a fresh :class:`~pramanix.guard.Guard`
        call (sharing the same ``Guard`` instance for efficiency).  The guard
        uses the side-effect-free :data:`_DRY_RUN_CONFIG` unless a custom
        config was passed to the constructor.

        Returns:
            A list of :class:`DryRunResult`, one per example, in input order.

        Raises:
            RuntimeError: If the underlying guard raises an unexpected exception
                          during verification.  Individual decision errors are
                          captured in :attr:`DryRunResult.decision` with
                          ``decision.allowed == False``.
        """
        guard = Guard(self._policy, config=self._config)
        results: list[DryRunResult] = []

        for idx, (intent, state) in enumerate(self._examples):
            decision = guard.verify(intent=intent, state=state)
            results.append(
                DryRunResult(
                    index=idx,
                    intent=intent,
                    state=state,
                    decision=decision,
                    would_allow=decision.allowed,
                    explanation=decision.explanation,
                )
            )

        return results

    def assert_all_allowed(self) -> None:
        """Run simulation and raise ``AssertionError`` if any example is blocked.

        Convenience method for CI golden-path assertions::

            PolicyDryRun(MyPolicy, allowed_examples).assert_all_allowed()

        Raises:
            AssertionError: Lists all blocked examples with their explanations.
        """
        results = self.simulate()
        blocked = [r for r in results if not r.would_allow]
        if blocked:
            lines = [f"  [{r.index}] {r.explanation!r}" for r in blocked]
            msg = f"{len(blocked)} example(s) were blocked:\n" + "\n".join(lines)
            raise AssertionError(msg)

    def assert_all_blocked(self) -> None:
        """Run simulation and raise ``AssertionError`` if any example is allowed.

        Convenience method for CI deny-path assertions::

            PolicyDryRun(MyPolicy, blocked_examples).assert_all_blocked()

        Raises:
            AssertionError: Lists all allowed examples.
        """
        results = self.simulate()
        allowed = [r for r in results if r.would_allow]
        if allowed:
            lines = [f"  [{r.index}] allowed (status={r.decision.status})" for r in allowed]
            msg = f"{len(allowed)} example(s) were allowed:\n" + "\n".join(lines)
            raise AssertionError(msg)
