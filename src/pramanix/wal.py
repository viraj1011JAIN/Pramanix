# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Viraj Jain
# For architectural decisions and proof of correctness, please refer to:
# - docs/THESIS.tex
# - docs/PROOF_DOSSIER.md
"""Write-Ahead Log (WAL) sinks — synchronous, durable audit writes.

Closes the "Ephemeral Active Ledger" gap: every ALLOW decision is
mathematically incapable of reaching the caller until its audit record is
confirmed durably written to the backing store.

Design contract
---------------
:meth:`WalAuditSink.write` MUST block until the backing store confirms
durability (Postgres WAL flush, Kafka ``acks=all``).  Any exception
propagates to :class:`~pramanix.guard.Guard`, which force-converts the
decision to BLOCK — fail-closed, never fail-open.

Built-in sinks
--------------
- :class:`PostgresWalSink`  — asyncpg pool + ``synchronous_commit=local``;
  schema auto-created on first :meth:`~PostgresWalSink.initialize` call.
- :class:`KafkaWalSink`     — confluent-kafka ``acks=all`` + blocking
  :func:`flush`; durable across Kafka broker failures.
- :class:`CompositeWalSink` — fan-out; all sinks must succeed or the
  entire write fails (dual-writer redundancy for SOC 2 requirements).
- :class:`InMemoryWalSink`  — in-process list; for testing only.

WAL table layout (Postgres)
----------------------------
::

    pramanix_decision_wal (
        seq         BIGSERIAL PRIMARY KEY          -- monotone write order
        decision_id TEXT UNIQUE NOT NULL           -- correlation with audit trail
        policy_name TEXT NOT NULL DEFAULT ''
        allowed     BOOLEAN NOT NULL
        status      TEXT NOT NULL
        payload     JSONB NOT NULL                 -- full decision wire format
        written_at  DOUBLE PRECISION NOT NULL      -- Unix epoch (UTC)
        exported    BOOLEAN NOT NULL DEFAULT FALSE -- set TRUE by background exporter
    )

The ``exported`` flag supports a background process that batch-transfers
confirmed WAL entries to long-term storage (S3, BigQuery, Splunk) after
verifying durability at the destination, then marks them ``exported=TRUE``.
This two-phase approach means the WAL is also a recovery buffer: if the
long-term sink is unavailable, no audit records are lost.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
from typing import TYPE_CHECKING, Any, Protocol, cast, runtime_checkable

from pramanix.exceptions import ConfigurationError, WalWriteError

if TYPE_CHECKING:
    from pramanix.decision import Decision

__all__ = [
    "CompositeWalSink",
    "InMemoryWalSink",
    "KafkaWalSink",
    "PostgresWalSink",
    "WalAuditSink",
]

_log = logging.getLogger(__name__)


# ── Protocol ──────────────────────────────────────────────────────────────────


@runtime_checkable
class WalAuditSink(Protocol):
    """Synchronous, durable audit-write protocol.

    Every :class:`~pramanix.guard.Guard` with a configured ``wal_sink`` calls
    :meth:`write` on every decision **before** returning to the caller.  If
    :meth:`write` raises, Guard force-converts the decision to BLOCK.

    Implementors MUST:
    * Block until the backing store confirms durability.
    * Raise :exc:`~pramanix.exceptions.WalWriteError` (or any exception) on
      failure — Guard treats any exception as a WAL failure.
    * Be thread-safe — Guard's worker pool calls ``write`` concurrently.
    """

    def write(self, decision: Decision) -> None:
        """Write *decision* durably.  Blocks until confirmed.  Raises on failure."""
        ...


# ── PostgresWalSink ───────────────────────────────────────────────────────────

_POSTGRES_WAL_DDL = """
CREATE TABLE IF NOT EXISTS pramanix_decision_wal (
    seq         BIGSERIAL        PRIMARY KEY,
    decision_id TEXT             NOT NULL UNIQUE,
    policy_name TEXT             NOT NULL DEFAULT '',
    allowed     BOOLEAN          NOT NULL,
    status      TEXT             NOT NULL,
    payload     JSONB            NOT NULL,
    written_at  DOUBLE PRECISION NOT NULL,
    exported    BOOLEAN          NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_pdw_unexported
    ON pramanix_decision_wal (seq) WHERE NOT exported;
CREATE INDEX IF NOT EXISTS idx_pdw_written_at
    ON pramanix_decision_wal (written_at);
"""


class PostgresWalSink:
    """Postgres-backed WAL sink using asyncpg with ``synchronous_commit=local``.

    Each :meth:`write` call executes an ``INSERT`` inside a transaction that
    sets ``synchronous_commit = local``, blocking until Postgres has flushed
    the WAL record to local disk before the commit returns.  This guarantees
    durability against process crashes and OOM-kills on the application server
    while keeping latency low (no standby sync required).

    The asyncpg pool runs on a dedicated background event loop so that
    :meth:`write` is callable from any synchronous context.

    Args:
        dsn:            asyncpg connection string,
                        e.g. ``"postgresql://user:pass@host/db"``.
        pool_min:       Minimum pool connections. Default: 1.
        pool_max:       Maximum pool connections. Default: 4.
        write_timeout:  Seconds to wait for the INSERT before raising.
                        Default: 5.0.
        _pool:          Pre-built asyncpg pool (for integration tests).

    Requires:
        ``pip install 'pramanix[postgres]'`` (asyncpg ≥ 0.29).

    Example::

        sink = PostgresWalSink("postgresql://pramanix:secret@db:5432/pramanix")
        sink.initialize()  # create table once at startup
        config = GuardConfig(wal_sink=sink)
    """

    def __init__(
        self,
        dsn: str = "",
        *,
        pool_min: int = 1,
        pool_max: int = 4,
        write_timeout: float = 5.0,
        _pool: Any = None,
    ) -> None:
        if _pool is None:
            try:
                import importlib as _il
                _il.import_module("asyncpg")
            except ImportError as exc:
                raise ConfigurationError(
                    "asyncpg is required for PostgresWalSink. "
                    "Install it with: pip install 'pramanix[postgres]'"
                ) from exc
        self._dsn = dsn
        self._pool: Any = _pool
        self._pool_min = pool_min
        self._pool_max = pool_max
        self._write_timeout = write_timeout
        self._loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None
        self._loop_ready = threading.Event()
        if _pool is None:
            self._start_loop_thread()
        else:
            try:
                self._loop = asyncio.get_event_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def _start_loop_thread(self) -> None:
        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            self._loop_ready.set()
            loop.run_forever()

        self._loop_thread = threading.Thread(
            target=_run, daemon=True, name="pramanix-wal-pg-loop"
        )
        self._loop_thread.start()
        self._loop_ready.wait(timeout=10.0)

    def _run_coro(self, coro: Any) -> Any:
        if self._loop is None:
            raise WalWriteError(
                "PostgresWalSink: event loop not started.",
                backend="PostgresWalSink",
            )
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        try:
            return future.result(timeout=self._write_timeout + 1.0)
        except TimeoutError as exc:
            raise WalWriteError(
                f"PostgresWalSink: write timed out after {self._write_timeout}s.",
                backend="PostgresWalSink",
            ) from exc

    async def _get_pool(self) -> Any:
        if self._pool is not None:
            return self._pool
        import asyncpg as _asyncpg
        self._pool = await _asyncpg.create_pool(
            self._dsn, min_size=self._pool_min, max_size=self._pool_max
        )
        return self._pool

    async def _initialize_async(self) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(_POSTGRES_WAL_DDL)

    def initialize(self) -> None:
        """Create the WAL table and indexes.  Safe to call multiple times."""
        self._run_coro(self._initialize_async())

    def close(self) -> None:
        """Close the asyncpg pool and stop the background event loop."""
        async def _close() -> None:
            if self._pool is not None:
                await self._pool.close()
                self._pool = None

        try:
            self._run_coro(_close())
        except Exception as exc:
            _log.warning("PostgresWalSink.close: pool close error: %s", exc)
        if self._loop is not None and self._loop_thread is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop_thread.join(timeout=5.0)

    # ── Core write ────────────────────────────────────────────────────────────

    async def _write_async(self, decision: Decision) -> None:
        pool = await self._get_pool()
        payload = json.dumps(decision.to_dict(), default=str)
        decision_id = str(getattr(decision, "decision_id", ""))
        policy_name = str(getattr(decision, "policy_name", ""))
        allowed = bool(getattr(decision, "allowed", False))
        status = str(getattr(decision, "status", ""))

        async with pool.acquire() as conn:  # noqa: SIM117
            async with conn.transaction():
                # Force WAL flush to local disk before commit returns.
                # synchronous_commit=local: durable against OOM-kill / process crash.
                # synchronous_commit=on:    additionally waits for streaming standbys.
                await conn.execute("SET LOCAL synchronous_commit = local")
                await conn.execute(
                    """
                    INSERT INTO pramanix_decision_wal
                        (decision_id, policy_name, allowed, status, payload, written_at)
                    VALUES ($1, $2, $3, $4, $5::jsonb, $6)
                    ON CONFLICT (decision_id) DO NOTHING
                    """,
                    decision_id,
                    policy_name,
                    allowed,
                    status,
                    payload,
                    time.time(),
                )

    def write(self, decision: Decision) -> None:
        """Insert *decision* into the WAL table.  Blocks until durable.

        Raises:
            WalWriteError: On Postgres error, connection failure, or timeout.
        """
        decision_id = str(getattr(decision, "decision_id", ""))
        try:
            self._run_coro(self._write_async(decision))
        except WalWriteError:
            raise
        except Exception as exc:
            raise WalWriteError(
                f"PostgresWalSink: INSERT failed for decision_id={decision_id!r}: "
                f"{type(exc).__name__}: {exc}",
                decision_id=decision_id,
                backend="PostgresWalSink",
            ) from exc

    def mark_exported(self, decision_ids: list[str]) -> int:
        """Mark a batch of WAL entries as exported to long-term storage.

        Args:
            decision_ids: List of decision UUIDs confirmed durable in the
                          long-term sink.

        Returns:
            Number of rows updated.
        """
        return cast(int, self._run_coro(self._mark_exported_async(decision_ids)))

    async def _mark_exported_async(self, decision_ids: list[str]) -> int:
        if not decision_ids:
            return 0
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE pramanix_decision_wal SET exported=TRUE "
                "WHERE decision_id = ANY($1::text[]) AND NOT exported",
                decision_ids,
            )
        # asyncpg returns "UPDATE N" as a string
        try:
            return int(str(result).split()[-1])
        except (ValueError, IndexError):
            return 0

    def pending_export(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Return up to *limit* WAL entries not yet exported."""
        return cast(list[dict[str, Any]], self._run_coro(self._pending_export_async(limit)))

    async def _pending_export_async(self, limit: int) -> list[dict[str, Any]]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT seq, decision_id, policy_name, allowed, status, payload, written_at
                FROM pramanix_decision_wal
                WHERE NOT exported
                ORDER BY seq ASC
                LIMIT $1
                """,
                limit,
            )
        return [dict(row) for row in rows]


# ── KafkaWalSink ──────────────────────────────────────────────────────────────


class KafkaWalSink:
    """Kafka-backed WAL sink using ``acks=all`` + synchronous ``flush()``.

    Each :meth:`write` call produces the decision payload to Kafka with
    ``acks=all`` (all in-sync replicas must acknowledge) and then calls
    :func:`flush` to block until delivery is confirmed.  This guarantees
    durability even when a Kafka broker fails mid-write.

    Requires the Kafka topic to be configured with
    ``min.insync.replicas ≥ 2`` (recommended ``replication.factor=3``) so
    that ``acks=all`` provides meaningful durability guarantees.

    Args:
        topic:          Kafka topic name.
        producer_conf:  confluent-kafka ``Producer`` config dict.  Must
                        include ``bootstrap.servers``.  ``acks`` is forced
                        to ``"all"`` regardless of what is passed.
        flush_timeout:  Seconds to block on :func:`flush` before raising.
                        Default: 5.0.
        _producer:      Pre-built producer (for integration tests).

    Requires:
        ``pip install 'pramanix[kafka]'`` (confluent-kafka ≥ 2.3).

    Example::

        sink = KafkaWalSink(
            topic="pramanix.wal",
            producer_conf={"bootstrap.servers": "kafka:9092"},
        )
        config = GuardConfig(wal_sink=sink)
    """

    def __init__(
        self,
        topic: str,
        producer_conf: dict[str, Any],
        *,
        flush_timeout: float = 5.0,
        _producer: Any = None,
        _kafka_factory: Any = None,
    ) -> None:
        self._topic = topic
        self._flush_timeout = flush_timeout
        self._delivery_error: Exception | None = None
        self._lock = threading.Lock()

        if _producer is None:
            try:
                if _kafka_factory is not None:
                    Producer = _kafka_factory()
                else:
                    from confluent_kafka import Producer
            except ImportError as exc:
                raise ConfigurationError(
                    "confluent-kafka is required for KafkaWalSink. "
                    "Install it with: pip install 'pramanix[kafka]'"
                ) from exc
            # Force acks=all regardless of caller config — mandatory for WAL.
            conf = dict(producer_conf)
            conf["acks"] = "all"
            self._producer: Any = Producer(conf)
        else:
            self._producer = _producer

    def _delivery_cb(self, err: Any, _msg: Any) -> None:
        if err is not None:
            with self._lock:
                self._delivery_error = err

    def write(self, decision: Decision) -> None:
        """Produce *decision* to Kafka and block until ``acks=all`` confirmed.

        Raises:
            WalWriteError: On produce error, delivery failure, or flush timeout.
        """
        decision_id = str(getattr(decision, "decision_id", ""))
        payload = json.dumps(decision.to_dict(), default=str).encode()

        with self._lock:
            self._delivery_error = None

        try:
            self._producer.produce(
                self._topic,
                value=payload,
                key=decision_id.encode(),
                callback=self._delivery_cb,
            )
        except Exception as exc:
            raise WalWriteError(
                f"KafkaWalSink: produce() failed for decision_id={decision_id!r}: "
                f"{type(exc).__name__}: {exc}",
                decision_id=decision_id,
                backend="KafkaWalSink",
            ) from exc

        # flush() blocks until delivery callbacks have fired or timeout expires.
        remaining = self._producer.flush(timeout=self._flush_timeout)
        if remaining > 0:
            raise WalWriteError(
                f"KafkaWalSink: flush() timed out after {self._flush_timeout}s; "
                f"{remaining} messages still queued (decision_id={decision_id!r}).",
                decision_id=decision_id,
                backend="KafkaWalSink",
            )

        with self._lock:
            err = self._delivery_error
        if err is not None:
            raise WalWriteError(
                f"KafkaWalSink: delivery failed for decision_id={decision_id!r}: {err}",
                decision_id=decision_id,
                backend="KafkaWalSink",
            )

        _log.debug(
            "pramanix.wal.kafka.write: decision_id=%s topic=%s",
            decision_id,
            self._topic,
        )


# ── CompositeWalSink ──────────────────────────────────────────────────────────


class CompositeWalSink:
    """Fan-out WAL sink — writes to all configured sinks; fails if any fail.

    Provides dual-writer redundancy: the same audit record is written to two
    independent durable stores (e.g. Postgres primary + Kafka).  Guard blocks
    until ALL sinks confirm durability.  If any sink raises, the write is
    treated as failed and Guard forces BLOCK.

    Args:
        sinks: Sequence of :class:`WalAuditSink` implementations.

    Example::

        sink = CompositeWalSink([
            PostgresWalSink("postgresql://..."),
            KafkaWalSink("pramanix.wal", {"bootstrap.servers": "kafka:9092"}),
        ])
        config = GuardConfig(wal_sink=sink)
    """

    def __init__(self, sinks: list[WalAuditSink]) -> None:
        if not sinks:
            raise ConfigurationError(
                "CompositeWalSink requires at least one WalAuditSink."
            )
        self._sinks = list(sinks)

    def write(self, decision: Decision) -> None:
        """Write to all sinks.  Raises :exc:`WalWriteError` if any sink fails."""
        errors: list[str] = []
        decision_id = str(getattr(decision, "decision_id", ""))
        for sink in self._sinks:
            try:
                sink.write(decision)
            except Exception as exc:
                errors.append(f"{type(sink).__name__}: {exc}")
        if errors:
            raise WalWriteError(
                f"CompositeWalSink: {len(errors)} sink(s) failed for "
                f"decision_id={decision_id!r}: " + "; ".join(errors),
                decision_id=decision_id,
                backend="CompositeWalSink",
            )


# ── InMemoryWalSink ───────────────────────────────────────────────────────────


class InMemoryWalSink:
    """In-process WAL sink for testing.

    Appends decisions to a thread-safe list.  Raises
    :exc:`~pramanix.exceptions.ConfigurationError` when instantiated in a
    ``PRAMANIX_ENV=production`` process.

    Args:
        max_entries: Maximum number of entries before evicting oldest.
                     Default: unlimited (None).
        raise_after: Simulate WAL failure after this many successful writes.
                     Default: None (never fail).
    """

    def __init__(
        self,
        *,
        max_entries: int | None = None,
        raise_after: int | None = None,
    ) -> None:
        if os.environ.get("PRAMANIX_ENV", "").lower() == "production":
            raise ConfigurationError(
                "InMemoryWalSink is not permitted when PRAMANIX_ENV=production. "
                "Configure PostgresWalSink or KafkaWalSink."
            )
        import warnings as _w
        _w.warn(
            "InMemoryWalSink is for testing only — all WAL entries are lost on "
            "process restart. Use PostgresWalSink or KafkaWalSink in production.",
            UserWarning,
            stacklevel=2,
        )
        self._lock = threading.Lock()
        self._entries: list[Decision] = []
        self._max_entries = max_entries
        self._raise_after = raise_after
        self._write_count = 0

    @property
    def entries(self) -> list[Decision]:
        """Thread-safe snapshot of all written decisions."""
        with self._lock:
            return list(self._entries)

    def write(self, decision: Decision) -> None:
        """Append *decision* to the in-memory list.

        Raises:
            WalWriteError: If ``raise_after`` writes have already succeeded.
        """
        decision_id = str(getattr(decision, "decision_id", ""))
        with self._lock:
            if self._raise_after is not None and self._write_count >= self._raise_after:
                raise WalWriteError(
                    f"InMemoryWalSink: simulated failure at write #{self._write_count + 1}.",
                    decision_id=decision_id,
                    backend="InMemoryWalSink",
                )
            self._entries.append(decision)
            self._write_count += 1
            if self._max_entries is not None and len(self._entries) > self._max_entries:
                self._entries.pop(0)

    def clear(self) -> None:
        """Remove all entries."""
        with self._lock:
            self._entries.clear()
            self._write_count = 0

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
