# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Viraj Jain
"""Kafka consumer interceptor — Phase F-3.

Wraps a ``confluent_kafka.Consumer`` so every polled message is gated by a
``Guard.verify()`` call before being yielded to the application.  Blocked
messages are **never** delivered to the application — they are dead-lettered
(if a DLQ topic is configured) or silently committed to advance the offset.

Install: pip install 'pramanix[kafka]'
Requires: confluent-kafka >= 2.0

Usage::

    from pramanix.interceptors.kafka import PramanixKafkaConsumer

    consumer = PramanixKafkaConsumer(
        kafka_config={"bootstrap.servers": "localhost:9092", "group.id": "mygroup"},
        topics=["transfers"],
        guard=Guard(TransferPolicy, config=GuardConfig(execution_mode="sync")),
        intent_extractor=lambda msg: json.loads(msg.value()),
        state_provider=lambda: fetch_state(),
    )

    for message in consumer.safe_poll(timeout=1.0):
        process(message)
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    from pramanix.guard import Guard

__all__ = ["PramanixKafkaConsumer"]

_log = logging.getLogger(__name__)

try:
    from confluent_kafka import Consumer as _KafkaConsumer
    from confluent_kafka import KafkaException

    _KAFKA_AVAILABLE = True
except ImportError:
    _KAFKA_AVAILABLE = False
    _KafkaConsumer = object
    KafkaException = Exception


class PramanixKafkaConsumer:
    """Kafka consumer wrapper with Z3 formal verification gate.

    Polls messages from Kafka and yields only those that pass the guard.
    Blocked messages are dead-lettered or silently dropped.

    If ``confluent-kafka`` is not installed, the class is still importable
    for unit testing via mock injection.

    Args:
        kafka_config:     ``confluent_kafka.Consumer`` configuration dict.
        topics:           List of topic names to subscribe to.
        guard:            A fully constructed :class:`~pramanix.guard.Guard`.
        intent_extractor: Callable ``(message) → intent dict`` that maps a
                          ``confluent_kafka.Message`` to the policy schema.
        state_provider:   Callable ``() → state dict`` for current system state.
        dlq_producer:     Optional ``confluent_kafka.Producer``-compatible
                          object.  Blocked messages are produced to the DLQ
                          topic when provided.
        dlq_topic:        Topic name for dead-lettered messages.
    """

    def __init__(
        self,
        *,
        kafka_config: dict[str, Any],
        topics: list[str],
        guard: Guard,
        intent_extractor: Callable[[Any], dict[str, Any]],
        state_provider: Callable[[], dict[str, Any]],
        dlq_producer: Any | None = None,
        dlq_topic: str = "pramanix.dlq",
    ) -> None:
        self._guard = guard
        self._intent_extractor = intent_extractor
        self._state_provider = state_provider
        self._dlq_producer = dlq_producer
        self._dlq_topic = dlq_topic
        self._consumer: Any = None

        if _KAFKA_AVAILABLE:
            self._consumer = _KafkaConsumer(kafka_config)
            self._consumer.subscribe(topics)

    def safe_poll(
        self,
        timeout: float = 1.0,
    ) -> Generator[Any, None, None]:
        """Poll and yield only guard-approved messages.

        Args:
            timeout: Poll timeout in seconds per call.

        Yields:
            ``confluent_kafka.Message`` objects that passed guard verification.
        """
        if self._consumer is None:
            return  # confluent-kafka not installed — no-op

        while True:
            msg = self._consumer.poll(timeout=timeout)
            if msg is None:
                return
            if msg.error():
                _log.warning("pramanix.kafka.consumer_error: %s", msg.error())
                return

            try:
                intent = self._intent_extractor(msg)
                state = self._state_provider()
                decision = self._guard.verify(intent=intent, state=state)
            except Exception as exc:
                _log.exception("pramanix.kafka.guard_error: %s", exc)
                self._dead_letter(msg, reason=f"guard_error: {exc}")
                self._commit(msg)
                continue

            if not decision.allowed:
                violated = ", ".join(decision.violated_invariants or [])
                _log.warning(
                    "pramanix.kafka.blocked topic=%s offset=%s violated=[%s]",
                    msg.topic(),
                    msg.offset(),
                    violated,
                )
                self._dead_letter(
                    msg,
                    reason=f"blocked: [{violated}] {decision.explanation or ''}",
                )
                self._commit(msg)
                continue

            yield msg
            self._commit(msg)

    def _dead_letter(self, msg: Any, *, reason: str) -> None:
        if self._dlq_producer is None:
            return
        try:
            headers = [("x-pramanix-block-reason", reason.encode())]
            self._dlq_producer.produce(
                self._dlq_topic,
                value=msg.value(),
                headers=headers,
            )
            self._dlq_producer.flush()
        except Exception as exc:  # pragma: no cover
            _log.exception("pramanix.kafka.dlq_produce_error: %s", exc)

    def _commit(self, msg: Any) -> None:
        try:
            self._consumer.commit(message=msg, asynchronous=False)
        except Exception as exc:  # pragma: no cover
            _log.warning("pramanix.kafka.commit_error: %s", exc)

    def close(self) -> None:
        """Close the underlying Kafka consumer."""
        if self._consumer is not None:
            self._consumer.close()
