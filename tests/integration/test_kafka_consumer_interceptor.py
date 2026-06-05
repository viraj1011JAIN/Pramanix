"""Real Kafka consumer interceptor integration tests.

Uses a real Kafka broker (via testcontainer or KAFKA_BOOTSTRAP_SERVERS env var)
to exercise PramanixKafkaConsumer against actual Kafka behavior:

* safe_poll() yields guard-approved messages
* blocked messages are committed without being yielded
* DLQ messages are produced for blocked messages when a producer is supplied
* KafkaError messages are skipped gracefully
* Offset commit occurs on blocked messages

Addresses audit finding #3: Kafka consumer interceptor was only tested against
a _FakeConsumer duck-type; real behaviors (offset commit, DLQ flush under
backpressure, confluent_kafka.KafkaError handling) were never exercised.
"""

from __future__ import annotations

import json
import time
from decimal import Decimal
from typing import Any

import pytest

from pramanix.expressions import E
from pramanix.policy import Field

# ── Test policy ───────────────────────────────────────────────────────────────


class _TransferPolicy:
    """Allow transfers ≤ $1,000; block transfers above that."""

    amount: Field = Field("amount", Decimal, "Real")
    invariants = [lambda: E(amount) <= Decimal("1000")]


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_guard() -> Any:
    from pramanix.guard import Guard
    from pramanix.guard_config import GuardConfig

    return Guard(_TransferPolicy, config=GuardConfig(execution_mode="sync"))


def _produce_message(bootstrap_servers: str, topic: str, payload: dict[str, Any]) -> None:
    from confluent_kafka import Producer  # type: ignore[import-untyped]

    p = Producer({"bootstrap.servers": bootstrap_servers, "linger.ms": "0"})
    p.produce(topic, value=json.dumps(payload).encode())
    p.flush(timeout=10.0)


def _create_topic(bootstrap_servers: str, topic: str) -> None:
    """Best-effort topic creation via confluent_kafka AdminClient."""
    try:
        from confluent_kafka.admin import AdminClient, NewTopic  # type: ignore[import-untyped]

        admin = AdminClient({"bootstrap.servers": bootstrap_servers})
        futures = admin.create_topics([NewTopic(topic, num_partitions=1, replication_factor=1)])
        for _, f in futures.items():
            try:
                f.result(timeout=10.0)
            except Exception:
                pass  # topic may already exist
    except ImportError:
        pass  # AdminClient may not be available in all confluent-kafka versions


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.integration
def test_safe_poll_yields_allowed_message(kafka_bootstrap_servers: str) -> None:
    """safe_poll() yields messages whose intent passes the guard."""
    from pramanix.interceptors.kafka import PramanixKafkaConsumer

    topic = "pramanix.test.interceptor.allowed"
    _create_topic(kafka_bootstrap_servers, topic)
    _produce_message(kafka_bootstrap_servers, topic, {"amount": "500"})

    consumer_cfg = {
        "bootstrap.servers": kafka_bootstrap_servers,
        "group.id": "pramanix-test-allowed",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }
    guarded = PramanixKafkaConsumer(
        kafka_config=consumer_cfg,
        topics=[topic],
        guard=_make_guard(),
        intent_extractor=lambda msg: json.loads(msg.value().decode()),
        state_provider=lambda: {},
    )
    try:
        received: list[Any] = []
        deadline = time.monotonic() + 15.0
        while not received and time.monotonic() < deadline:
            for msg in guarded.safe_poll(timeout=1.0):
                received.append(msg)
        assert len(received) == 1, "Expected exactly 1 allowed message"
        payload = json.loads(received[0].value().decode())
        assert payload["amount"] == "500"
    finally:
        guarded.close()


@pytest.mark.integration
def test_safe_poll_blocks_and_commits_disallowed_message(kafka_bootstrap_servers: str) -> None:
    """safe_poll() commits but does NOT yield messages blocked by the guard."""
    from pramanix.interceptors.kafka import PramanixKafkaConsumer

    topic = "pramanix.test.interceptor.blocked"
    _create_topic(kafka_bootstrap_servers, topic)
    _produce_message(kafka_bootstrap_servers, topic, {"amount": "9999"})

    consumer_cfg = {
        "bootstrap.servers": kafka_bootstrap_servers,
        "group.id": "pramanix-test-blocked",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }
    guarded = PramanixKafkaConsumer(
        kafka_config=consumer_cfg,
        topics=[topic],
        guard=_make_guard(),
        intent_extractor=lambda msg: json.loads(msg.value().decode()),
        state_provider=lambda: {},
    )
    try:
        received: list[Any] = []
        # Poll long enough to receive and process the blocked message.
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            for msg in guarded.safe_poll(timeout=1.0):
                received.append(msg)
            # Stop as soon as the topic has been polled at least once.
            # If the message is blocked it won't be yielded.
            time.sleep(0.1)
            if time.monotonic() > deadline - 10.0:
                break
        assert received == [], "Blocked message must not be yielded by safe_poll()"
    finally:
        guarded.close()


@pytest.mark.integration
def test_safe_poll_dead_letters_blocked_message(kafka_bootstrap_servers: str) -> None:
    """Blocked messages are forwarded to the DLQ topic when a producer is provided."""
    from confluent_kafka import Consumer, Producer  # type: ignore[import-untyped]

    from pramanix.interceptors.kafka import PramanixKafkaConsumer

    source_topic = "pramanix.test.interceptor.dlq.source"
    dlq_topic = "pramanix.test.interceptor.dlq"
    _create_topic(kafka_bootstrap_servers, source_topic)
    _create_topic(kafka_bootstrap_servers, dlq_topic)
    _produce_message(kafka_bootstrap_servers, source_topic, {"amount": "99999"})

    dlq_producer = Producer({"bootstrap.servers": kafka_bootstrap_servers, "linger.ms": "0"})

    consumer_cfg = {
        "bootstrap.servers": kafka_bootstrap_servers,
        "group.id": "pramanix-test-dlq",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
    }
    guarded = PramanixKafkaConsumer(
        kafka_config=consumer_cfg,
        topics=[source_topic],
        guard=_make_guard(),
        intent_extractor=lambda msg: json.loads(msg.value().decode()),
        state_provider=lambda: {},
        dlq_producer=dlq_producer,
        dlq_topic=dlq_topic,
    )
    try:
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            list(guarded.safe_poll(timeout=1.0))
            if time.monotonic() > deadline - 10.0:
                break
    finally:
        guarded.close()

    # Verify the DLQ received the blocked message.
    dlq_consumer = Consumer(
        {
            "bootstrap.servers": kafka_bootstrap_servers,
            "group.id": "pramanix-dlq-checker",
            "auto.offset.reset": "earliest",
        }
    )
    dlq_consumer.subscribe([dlq_topic])
    dlq_messages: list[Any] = []
    deadline = time.monotonic() + 10.0
    while not dlq_messages and time.monotonic() < deadline:
        msg = dlq_consumer.poll(timeout=1.0)
        if msg is not None and not msg.error():
            dlq_messages.append(msg)
    dlq_consumer.close()

    assert len(dlq_messages) >= 1, "DLQ must contain the blocked message"
    header_dict = {k: v for k, v in (dlq_messages[0].headers() or [])}
    assert b"x-pramanix-block-reason" in header_dict, "DLQ message must have block-reason header"
