# Pramanix SDK — Exhaustive Gap & Technical Debt Audit
> **Scan date:** 2026-05-06  |  **Source:** Live deep-read of `src/pramanix/**`  
> **Status:** Living document — update as items are resolved.

---

## 1. Silent Exception Swallowing (`except Exception: pass`)

These are the most dangerous patterns — errors vanish without trace.

| # | File | Line(s) | Context | Risk |
|---|------|---------|---------|------|
| S-01 | `guard_pipeline.py` | 87–88 | Non-numeric `balance` fallback: `except Exception: pass` — silently skips balance enforcement when balance cannot be parsed | Medium — Z3 backstop, but malformed balance could slip semantic pre-screening |
| S-02 | `guard_pipeline.py` | 103–104 | Non-numeric `daily_limit/daily_spent` fallback: `except Exception: pass` | Medium |
| S-03 | `guard_pipeline.py` | 127–128 | Healthcare dosage `max_daily_dose` check: `except Exception: pass` | Medium |
| S-04 | `guard_pipeline.py` | 153–158 | Infra `max_replicas`, CPU/memory checks: `except Exception: pass` | Medium |
| S-05 | `worker.py` | 244–246 | PPID watchdog loop: `except Exception: pass` — prevents detection of watchdog failure | Low — intentional |
| S-06 | `worker.py` | 358–359 | Prometheus counter increment in warmup failure: `except Exception: pass` | Low |
| S-07 | `worker.py` | 624–638 | `WorkerPool.__del__` three nested bare-pass blocks | Low — GC context |
| S-08 | `translator/_cache.py` | 179–180 | `_RedisCache.clear`: silent Redis SCAN/DEL failure | Low — cache is best-effort |
| S-09 | `translator/_cache.py` | 278–293 | `IntentCache.get/set`: silent cache failures | Low — best-effort |
| S-10 | `audit_sink.py` | 135–136 | Prometheus overflow counter init: `except Exception: pass` | Low |

**Recommended action for S-01 through S-04:** Change `except Exception: pass` to `except Exception as exc: _log.debug(...)` so failures are traceable without breaking the fallback-to-Z3 contract.

---

## 2. `NotImplementedError` Stubs (Runtime Traps)

| # | File | Line | Method | Notes |
|---|------|------|--------|-------|
| N-01 | `integrations/langchain.py` | 141 | `PramanixGuardedTool._arun` | Raises when `execute_fn=None` and guard ALLOWS — constructor warns (line 79) but it is still a runtime crash |
| N-02 | `integrations/crewai.py` | 180 | `PramanixCrewAITool._execute` | Same pattern — raises when `underlying_fn=None` and guard ALLOWS |
| N-03–N-08 | `key_provider.py` | 143, 196, 252, 466, 561, 674 | `rotate_key()` on Pem/Env/File/Azure/Gcp/Vault providers | Intentional — `supports_rotation=False` on all; documented |
| N-09 | `policy.py` | 364 | `Policy.invariants` base | Correct design — forces subclass override |

**Critical:** N-01 and N-02 are the only production-dangerous stubs. An ALLOW decision crashes the tool call. Consider making `execute_fn`/`underlying_fn` required parameters, or returning a structured error string instead of raising.

---

## 3. `type: ignore` Suppressions — Risk Assessment

### 3a. Structural / Necessary (accept as-is)
| Files | Reason |
|-------|--------|
| All `integrations/*.py` with `[misc]` | Dynamic base class `(X if available else object)` — unavoidable pattern |
| `expressions.py` `[override]` ×4 | `__eq__/__ne__/__pow__/__rpow__` return `ConstraintExpr` — intentional DSL design |
| `guard_config.py` `[assignment]` ×4 | Optional Prometheus counters init as `None` |

### 3b. Potentially Hiding Real Bugs
| # | File | Line | Suppression | Risk |
|---|------|------|-------------|------|
| T-01 | `key_provider.py` | 342, 446, 544, 654 | `[return-value]` on `self._cached_pem` | Cache is `bytes \| None`; returning `None` typed as `bytes` causes obscure `AttributeError` in callers |
| T-02 | `policy.py` | 227, 546 | `[misc]` on `@classmethod` | May indicate metaclass conflict that Mypy flags but Python silently accepts |
| T-03 | `policy.py` | 290 | `[method-assign, assignment]` | Patching `cls.invariants` directly — fragile under Python method-resolution changes |
| T-04 | `guard.py` | 173 | `[union-attr]` on `REGISTRY._names_to_collectors` | Accessing private Prometheus internal — will break on any prometheus-client version update |
| T-05 | `translator/injection_scorer.py` | 294 | `[misc]` on `instance.__init__()` | Calling `__init__` on an already-constructed instance post-`__new__` — fragile pickle restoration |

---

## 4. Concurrency & Distributed Safety Gaps

| # | Location | Issue | Severity |
|---|----------|-------|----------|
| C-01 | `execution_token.py` (`InMemoryExecutionTokenVerifier`) | Not safe for multi-worker/multi-process deployments. Module emits its own warning. Any Gunicorn/uvicorn multi-worker setup has TOCTOU replay-attack windows. | **Critical for multi-worker prod** |
| C-02 | `circuit_breaker.py` | Distributed state merge conflicts are logged but no alert/metric is emitted. Split-brain scenarios are handled silently. | High |
| C-03 | `worker.py` (`WorkerPool._recycle`) | `should_recycle` flag set outside the lock (line 743), re-checked inside it (line 783). Two threads could both pass the outer check before either acquires the lock, triggering two concurrent recycles. | Medium |
| C-04 | `audit_sink.py` (`KafkaAuditSink`) | `_queue_depth` decremented in both `except` block (line 240) and delivery callback (line 233). A failed `produce()` that also fires a callback could double-decrement; `max(0, ...)` guards underflow but the logic is error-prone. | Medium |
| C-05 | `translator/_cache.py` | `_hits` and `_misses` incremented outside the lock in `IntentCache.get` — racy across threads under CPython GIL. | Low |
| C-06 | `audit_sink.py` (`S3AuditSink`) | Line 300: `self._executor = threading.Thread` — assigns the `Thread` class itself as a dead placeholder. Misleading dead code. | Low — no runtime impact |

---

## 5. Architectural & Design Gaps

| # | Area | Gap | Impact |
|---|------|-----|--------|
| A-01 | `audit/archiver.py` | `MerkleArchiver` active chain is **in-memory only** — a crash before `flush_archive()` loses all un-archived entries. No WAL or journal. | High for compliance |
| A-02 | `audit/archiver.py` | Archive files written in **plaintext NDJSON**. The archiver itself warns at line 119–124. SOC 2 / HIPAA / PCI DSS requires external encryption. | High for regulated deployments |
| A-03 | `translator/_cache.py` | Redis fallback silently swallows the connection error (line 236). Operators have no visibility into why the LRU fallback was activated. Log the exception at WARNING. | Medium — operability |
| A-04 | `guard_pipeline.py` | `_semantic_post_consensus_check` is a hardcoded domain list (fintech, healthcare, infra). No plugin/hook mechanism for custom domain semantic rules. | Medium — extensibility |
| A-05 | `memory/store.py` | `SecureMemoryStore` is entirely in-process. No Redis-backed or distributed implementation. Multi-worker agents cannot share memory across workers. | High — agentic multi-worker |
| A-06 | `integrations/langchain.py` | `_run` creates a new event loop per invocation via `asyncio.run()` in a thread. High-frequency agents pay event-loop creation cost on every call. | Medium — performance |
| A-07 | `integrations/fastapi.py` | Timing pad applied to ALLOW responses too. Correct for security but unexpected developer experience — document prominently. | Low — documentation |

---

## 6. Security Gaps

| # | Area | Gap | Severity |
|---|------|-----|----------|
| SEC-01 | `audit/archiver.py` | No encryption at rest (see A-02). | High |
| SEC-02 | `key_provider.py` | Cloud provider caches cache plaintext private key PEM in memory for 300 s. A memory dump exposes the signing key during the TTL window. Consider zeroing on expiry or reducing TTL. | High |
| SEC-03 | `translator/injection_scorer.py` | `CalibratedScorer.load` uses `pickle.loads` after HMAC verification (`# noqa: S301`). HMAC key management is entirely caller responsibility with no SDK-level guidance. A weak/reused HMAC key negates the protection. | Medium |
| SEC-04 | `audit_sink.py` (`SplunkHecAuditSink`) | `emit()` uses synchronous `httpx.Client.post` — blocks calling thread for up to 5 s per decision if Splunk is slow. No async path or background queue. | Medium — availability |
| SEC-05 | `audit_sink.py` (`DatadogAuditSink`) | `LogsApi.submit_log` is synchronous. Same blocking concern as SEC-04. | Medium — availability |
| SEC-06 | `guard.py` | `_PROM_AVAILABLE` silently falls to `False` on any Prometheus import error (not just `ImportError`). Metrics disabled with no operator warning. | Low |

---

## 7. Observability & Telemetry Gaps

| # | Location | Gap |
|---|----------|-----|
| O-01 | `worker.py` | `AdaptiveConcurrencyLimiter.shed_count` tracked internally but **never exported to Prometheus**. |
| O-02 | `worker.py` | `WorkerPool._recycle` logs INFO only — no Prometheus counter for recycle frequency. |
| O-03 | `translator/_cache.py` | `IntentCache.stats` (hits/misses/hit_rate) in-memory only — no Prometheus exposure. |
| O-04 | `audit_sink.py` | `KafkaAuditSink.overflow_count` not broken out per-sink in Prometheus. |
| O-05 | `audit/archiver.py` | No metrics on archive events (segment count, entry count, archive latency). |
| O-06 | `memory/store.py` | No metrics on partition count, `MemoryViolationError` rate, or evictions. |

---

## 8. Line-Ending Inconsistency

Several files use Windows CRLF while others use Unix LF.

**CRLF:** `integrations/crewai.py`, `integrations/langchain.py`, `integrations/fastapi.py`, `memory/store.py`, `translator/_cache.py`, `key_provider.py`  
**LF:** `worker.py`, `guard_pipeline.py`, `audit/archiver.py`, `audit_sink.py`, `translator/injection_scorer.py`

**Fix:** Add `.gitattributes` rule `*.py text eol=lf` and run `git add --renormalize .`

---

## 9. Minor Code Quality Issues

| # | File | Line | Issue |
|---|------|------|-------|
| Q-01 | `audit_sink.py` | 300 | `self._executor = threading.Thread` — dead assignment of the `Thread` class as a placeholder. Remove it. |
| Q-02 | `key_provider.py` | 342, 446, 544, 654 | Add `assert self._cached_pem is not None` before the `# type: ignore[return-value]` returns to make the invariant explicit. |
| Q-03 | `guard.py` | 173 | `REGISTRY._names_to_collectors` accesses a Prometheus private internal. Use `try: REGISTRY.unregister(...) except: pass` pattern instead. |
| Q-04 | `translator/injection_scorer.py` | 294 | `instance.__init__()` post-`__new__` is unorthodox. Use direct attribute assignment (`instance._pipeline = ...; instance._is_fitted = True`) without calling `__init__` again. |

---

## 10. Production-Readiness Checklist

| Item | Status | Notes |
|------|--------|-------|
| Multi-worker execution token safety | ❌ Gap | Use `RedisExecutionTokenVerifier` in prod |
| Distributed memory store | ❌ Not implemented | `SecureMemoryStore` is in-process only |
| Archive encryption at rest | ❌ Not implemented | External encryption required |
| Async audit sinks (Splunk, Datadog) | ❌ Blocking | Synchronous HTTP calls in `emit()` |
| CRLF normalisation | ❌ Inconsistent | Need `.gitattributes` |
| Prometheus shed/recycle/cache metrics | ❌ Missing | Not exported |
| Key material zeroing on expiry | ❌ Not implemented | Plaintext PEM cached 300 s |
| Azure/GCP/Vault/Pem/Env/File key rotation | ❌ Not implemented | All raise `NotImplementedError` |
| Plugin system for semantic domain rules | ❌ Not implemented | `_semantic_post_consensus_check` hardcoded |
| `execute_fn` required in integrations | ⚠️ Soft-warn | `NotImplementedError` at runtime on ALLOW |
| Timing pad on ALLOW responses | ✅ Correct | `PramanixMiddleware` pads all responses |
| HMAC-sealed IPC results | ✅ Implemented | `_worker_solve_sealed` / `_unseal_decision` |
| Fail-closed circuit breaker | ✅ Correct | OPEN state → `Decision.error` |
| Atomic archive writes | ✅ Implemented | fsync + `os.replace()` pattern |
| TOCTOU mitigation (single-process) | ✅ Implemented | `ExecutionToken` HMAC + single-use registry |

---

## 11. Priority Remediation Order

1. **C-01** — Deploy `RedisExecutionTokenVerifier` for any multi-worker production service.
2. **SEC-01/A-02** — Encrypt archive directory or implement AES-256-GCM archiver wrapper.
3. **T-01** — Add `assert self._cached_pem is not None` before cloud-provider cache returns.
4. **N-01/N-02** — Make `execute_fn`/`underlying_fn` required, or return structured error on ALLOW with no handler.
5. **SEC-02** — Reduce `_DEFAULT_KEY_CACHE_TTL`, or zero-fill cached PEM on expiry.
6. **SEC-04/SEC-05** — Background-queue the Splunk and Datadog `emit()` calls.
7. **O-01/O-02** — Export shed count and recycle events to Prometheus.
8. **A-05** — Design Redis-backed `SecureMemoryStore` for multi-worker agentic deployments.
9. **S-01–S-04** — Replace `except Exception: pass` in `guard_pipeline.py` with debug logging.
10. **Q-01** — Remove dead `self._executor = threading.Thread` placeholder in `S3AuditSink`.
11. **Line-endings** — Add `.gitattributes` and renormalise all `.py` files to LF.
