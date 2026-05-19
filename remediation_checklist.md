# Pramanix Tier-1 SDK Remediation Checklist

To elevate Pramanix to the enterprise maturity level of **LangChain, NVIDIA NeMo, or Guardrails AI**, you must eliminate the structural "fake" logic and technical debt that prevents it from being a safe, scalable, and zero-debt production dependency. 

This is your definitive, action-oriented checklist to systematically purge all flaws.

---

## 🎯 Phase 1: Purge "Fake" Stubs & Implement Reality
*Tier-1 SDKs do not lie to the type checker. They use explicit `Protocols` or raise clear, immediate `ImportErrors` when dependencies are missing.*

- [ ] **`src/pramanix/integrations/langchain.py`**: Remove `BaseTool if _LANGCHAIN_AVAILABLE else object`. Define a proper Python `Protocol` or raise an immediate `ImportError` if the user tries to instantiate `PramanixGuardedTool` without `langchain-core` installed.
- [ ] **`src/pramanix/integrations/crewai.py`**: Remove the `object` inheritance stub.
- [ ] **`src/pramanix/integrations/llamaindex.py`**: Remove internal placeholder classes (`ToolMetadata`, `ToolOutput`).
- [ ] **`src/pramanix/k8s/webhook.py`**: Remove the `FastAPI` stub (`class FastAPI: pass`).
- [ ] **`src/pramanix/key_provider.py`**: Implement actual Key Rotation for `AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`, `FileKeyProvider`, and `PemKeyProvider`. If rotation is genuinely unsupported by the provider, raise a domain-specific `UnsupportedOperationError` instead of the generic `NotImplementedError`.

## 🎯 Phase 2: Eliminate Silent Failures & Telemetry Blindspots
*Enterprise frameworks must be 100% observable. Swallowing exceptions or erasing stack traces prevents enterprise teams from debugging production outages.*

- [ ] **Global Traceback Erasure**: Search the `src/` directory for `_log.error(..., exc)` and `_log.warning(..., exc)`. Replace the `%s` interpolation with explicit `exc_info=True`. (Found in `worker.py`, `translator/_cache.py`, `lifecycle/diff.py`, `oversight/workflow.py`, `provenance.py`).
- [ ] **`src/pramanix/worker.py` (Prometheus)**: Remove `except Exception: pass` around Prometheus metric registration. If metrics collide, the system should log a severe warning or fail loudly.
- [ ] **`src/pramanix/translator/_cache.py` (Redis)**: Remove `except Exception: pass` on cache `set()`, `clear()`, and `invalidate()`. Log the explicit connection error so operators know the cache is degraded.
- [ ] **`src/pramanix/guard_config.py` (Warnings)**: Replace `warnings.warn()` with actual standard `logging.getLogger().warning()` so that security advisories aren't silenced by Docker's default `PYTHONWARNINGS=ignore` environment variable.

## 🎯 Phase 3: Resolve Blocking I/O in Async Hot Paths
*SDKs designed for high-throughput (like FastAPI/LangGraph) cannot afford to stall the main event loop. Blocking calls in `async def` functions destroy concurrency.*

- [ ] **`src/pramanix/mesh/authenticator.py`**: Refactor `_fetch_jwks()` to use `httpx.AsyncClient().get()` instead of the synchronous `httpx.get()`.
- [ ] **`src/pramanix/audit_sink.py`**: Update `SplunkHecAuditSink` and `DatadogAuditSink` to use asynchronous HTTP requests (`httpx.AsyncClient`) inside the async `Guard.verify_async` path, or offload emission to a background worker thread.
- [ ] **`src/pramanix/guard.py`**: Ensure `time.sleep()` is never used in the async loop. (See Line 443 padding delays).

## 🎯 Phase 4: Eradicate Memory Leaks (OOM Vectors)
*Long-running agentic loops (like LangGraph or CrewAI swarms) will run indefinitely. Unbounded data structures will crash the host pod.*

- [ ] **`src/pramanix/oversight/workflow.py`**: Refactor `InMemoryApprovalWorkflow`. Introduce a maximum capacity (TTL or `maxlen`) to `self._records` and `self._decisions`.
- [ ] **`src/pramanix/worker.py`**: Add `maxlen=...` to `collections.deque()` on line 172.
- [ ] **`src/pramanix/transpiler.py`**: Add `maxlen=...` to the `_access_order: ClassVar[deque]` cache tracking on line 836.

## 🎯 Phase 5: Destroy Thread-Safety Violations & Global Mutation
*SDKs must support parallel execution (e.g., Celery, Gunicorn, xdist). Global state mutation prevents safe concurrency.*

- [ ] **`src/pramanix/provenance.py`**: Remove `global _PROVENANCE_KEY`. Pass the key via dependency injection or a class instance.
- [ ] **`src/pramanix/oversight/workflow.py`**: Remove `global _PROCESS_KEY`.
- [ ] **`src/pramanix/crypto.py` & `audit/signer.py`**: Remove `global _signing_failure_counter`. Move this state into a dedicated metrics class or singleton.

## 🎯 Phase 6: Code Hardening & Type Safety
*To be a tier-1 dependency, the SDK must not rely on production `assert` statements or `# type: ignore` blindfolds.*

- [ ] **Remove `assert` outside tests**: Replace all `assert` statements in `oversight/workflow.py`, `crypto.py`, `audit_sink.py`, and `provenance.py` with `if not condition: raise PramanixSecurityError(...)`.
- [ ] **Remove `# type: ignore`**: Systematically audit the 50 remaining suppressions (heavily concentrated in `compiler.py` and `expressions.py`). Write explicit type guards or type casting to satisfy Pyright/Mypy.
- [ ] **Remove `__del__` Destructors**: Replace Python `__del__` destructors in `worker.py`, `interceptors/kafka.py`, and `circuit_breaker.py` with explicit `.close()` methods or `weakref.finalize`.
- [ ] **Remove Debug Prints**: Remove rogue `print()` statements from `translator/injection_scorer.py`, `nlp/validators.py`, and `crypto.py`.
- [ ] **Upgrade Deprecated APIs**: Replace `datetime.utcnow()` in `audit/merkle.py` with `datetime.now(datetime.UTC)`.

## 🎯 Phase 7: Deep Systems Engineering & Concurrency Bugs (The Final Frontier)
*SDKs used in distributed microservices will inevitably crash clusters if OS-level process bounds are mishandled.*

- [ ] **CRITICAL BUG: The Zombie Worker Leak**: In `src/pramanix/worker.py` (Line 310), the `_ppid_watchdog` daemon thread calls `sys.exit(0)` to terminate the child worker when the parent process dies. **This is a fatal Python threading bug.** `sys.exit()` merely raises a `SystemExit` exception, which only kills the *thread*, leaving the main child process alive as an immortal zombie. This must be changed to `os._exit(0)` to actually kill the OS process.
- [ ] **Traceback Erasure via `logging`**: In `worker.py` (Lines ~430, 650, 737, 838, etc.), `logging.error("Failed: %s", exc)` is used. In Python logging, `%s` strips the stack trace entirely. Production crashes will be impossible to debug. These must be replaced with `exc_info=True` to retain the stack trace.
- [ ] **Clock Drift Desyncs**: Replace instances of `time.time()` used for computing time intervals (e.g., in `circuit_breaker.py` or `worker.py`) with `time.monotonic()`. `time.time()` is subject to NTP clock jumps, which can cause negative latency spikes or infinite loops.

---

**How to Execute this Remediation:**
I recommend we take this systematically, Phase by Phase. Tell me which Phase you want to start with (e.g., *"Let's fix the Zombie Worker bug in Phase 7"* or *"Let's remove all asserts in Phase 6"*), and I will start rewriting the files to achieve enterprise-grade perfection.
