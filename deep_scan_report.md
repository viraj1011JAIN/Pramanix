# Pramanix Codebase Deep Scan Report (May 2026)

This document is the result of an exhaustive, full-workspace static and structural scan of the Pramanix codebase. While previous efforts have successfully removed significant mock debt (like `fakeredis` and structural process stubs), this scan reveals that the codebase **is not yet at zero-debt**. 

Below is the definitive list of all remaining flaws, fakes, mocks, and structural drawbacks currently live in the repository.

---

## 1. Fake Base Classes & Optional Dependency Stubs

The codebase uses a dangerous pattern of replacing missing optional dependencies with `object` or empty classes to trick static type checkers. These "duck-typing fakes" are silent at runtime and can lead to unexpected behaviors.

* **`src/pramanix/integrations/langchain.py` (Lines 32, 56):** 
  Redefines `BaseTool` as an empty class and creates a fake inheritance tree: 
  `class PramanixGuardedTool(BaseTool if _LANGCHAIN_AVAILABLE else object)`
* **`src/pramanix/integrations/crewai.py` (Line 82):** 
  Similar fake inheritance pattern:
  `class PramanixCrewAITool(_CrewAIBase if _CREWAI_AVAILABLE else object)`
* **`src/pramanix/k8s/webhook.py` (Line 51):** 
  Silently stubs FastAPI if absent:
  `class FastAPI:  # type: ignore[no-redef]`
* **`src/pramanix/integrations/llamaindex.py` (Lines 57, 66):** 
  Uses internal placeholder classes (`ToolMetadata`, `ToolOutput`) to stub out missing imports without triggering `ImportError`.

---

## 2. Incomplete Implementations (`NotImplementedError`)

Several core architectural components are literally stubbed out and will crash when invoked in certain execution paths:

* **Key Rotation is Fake for Most Providers:** 
  In `src/pramanix/key_provider.py`, five out of six providers raise `NotImplementedError` when `rotate_key()` is called (`AzureKeyVaultKeyProvider`, `GcpKmsKeyProvider`, `HashiCorpVaultKeyProvider`, `FileKeyProvider`, `PemKeyProvider`). Only AWS is fully implemented.
* **LangChain Async Execution:** 
  In `src/pramanix/integrations/langchain.py`, if the decision is `ALLOW`, the async `_arun()` method simply raises `NotImplementedError`.
* **CrewAI Sync Execution:** 
  The synchronous `_run` path in `src/pramanix/integrations/crewai.py` is entirely unimplemented and raises `NotImplementedError`.

---

## 3. Type-Safety Fakes (`# type: ignore` Suppressions)

There are exactly **50 instances** of `# type: ignore` suppressions remaining in the `src/pramanix` directory. These are static fakes—deliberate blindfolds placed on `mypy` and `pyright` that could mask severe bugs during dependency upgrades.

**High-Concentration Areas:**
* **`compiler.py`**: ~7 suppressions hiding Z3 operator type incompatibilities.
* **`integrations/__init__.py`**: ~8 suppressions hiding late re-imports.
* **`expressions.py`**: ~4 suppressions for overriding `__eq__` and `__ne__` return types.
* **`natural_policy/compiler.py`**: ~4 suppressions mapping AST nodes to Z3 types.

*Note: To achieve production-hardened integrity, every single suppression must be replaced with proper type guards, cast functions, or protocol implementations.*

---

## 4. Silent Exception Swallowing

There are numerous places where exceptions are caught and explicitly ignored using `pass` or `contextlib.suppress()`. This hides system failures from telemetry and operators.

* **Prometheus Registration Failures:** `worker.py` (lines 326, 436, 753) still swallows exception traces during initialization, masking legitimate metric name collisions or namespace issues.
* **Cache Integrity Failures:** `translator/_cache.py` uses `except Exception: pass` around `clear()`, `set()`, and `invalidate()` calls. If Redis drops the connection mid-write, the cache state drifts silently.
* **Translator Stream Leaks:** Both `gemini.py` (line 208) and `cohere.py` (line 156) use `except Exception: pass` when closing generator streams, potentially leaking file descriptors if the connection hangs.

---

## 5. Synchronous Blocking Calls in Async Hot Paths

The async `Guard.verify_async()` hot path contains hidden blocking I/O calls that will stall the Python event loop under load:

* **`MeshAuthenticator._fetch_jwks()`:** In `mesh/authenticator.py`, it uses the synchronous `httpx.get()` to fetch JWKS keys. This blocks the event loop completely on cache misses.
* **Audit Sinks:** Both `SplunkHecAuditSink` and `DatadogAuditSink` (`audit_sink.py`) use the synchronous `httpx.Client()` in their `emit()` methods, blocking the evaluation of policies when the downstream sink is slow.

---

## 6. `assert` Statements in Production Code

Python disables `assert` statements entirely when run with the `-O` (optimize) flag. Any validation relying on `assert` is bypassed in standard production deployments. 

The codebase currently contains **25 `assert` statements** outside of tests, including:
* `oversight/workflow.py`: `assert record.verify()` and `assert workflow.check(rid)`
* `crypto.py`: `assert decision.signature` and `assert verifier.verify(decision)`
* `audit_sink.py`: `assert len(sink.decisions) == 1`
* `provenance.py`: `assert chain.verify_integrity()`

*Fix: These must be replaced with explicit `if not condition: raise ConfigError/SecurityError` checks.*

---

## 7. Remaining Test Mocks & Simulations

While "structural stubs" have been largely removed, the test suite still heavily relies on simulating reality:

* **HTTP Simulation (`respx`)**: Used extensively in `test_llm_backends_real.py`, `test_translator.py`, and `test_enterprise_audit_sinks.py`. While it avoids mocking the SDK objects directly, it still fakes network physics and prevents true end-to-end integration testing.
* **Monkeypatching (`unittest.mock.patch`)**: Still imported and utilized in over **20 test files** (e.g., `test_redundant_full.py`, `test_postgres_token_verifier.py`, `test_interceptors.py`).

---

## 8. Memory Leaks (OOM Risks)

* **Unbounded Memory Growth**: `InMemoryApprovalWorkflow` (`oversight/workflow.py`) appends endlessly to `self._records` (list) and `self._decisions` (dict) without any TTL or eviction policy. In a long-running agentic loop, this will eventually exhaust pod memory and crash the process.

## Conclusion

The Pramanix codebase is well on its way to enterprise maturity, but it currently relies on a facade of type-suppressions, stubbed classes, and hidden blocking paths to function. A dedicated remediation sprint targeting the 8 categories above is required to declare the SDK truly "zero-debt".

---

## 9. Deep-Level Application Flaws (Pass 2 Findings)

A secondary sweep of the codebase for obscure anti-patterns has uncovered the following systemic vulnerabilities:

### A. Global State Mutation (Thread-Safety Violation)
Global variables are being mutated inside functions, breaking thread safety and test isolation:
* **`src/pramanix/provenance.py`**: Declares and mutates `global _PROVENANCE_KEY` across calls.
* **`src/pramanix/oversight/workflow.py`**: Mutates `global _PROCESS_KEY`.
* **`src/pramanix/crypto.py`** and **`audit/signer.py`**: Mutates `global _signing_failure_counter`.

### B. Coverage Escape Hatches
The `# pragma: no cover` tag is used to exclude code from test coverage metrics. Crucially, it is used to mask the lack of testing on `ImportError` blocks:
* **`mesh/authenticator.py`** (Lines 885, 906, 922) and **`execution_token.py`** (Lines 93, 966) suppress `ImportError` branches, meaning the graceful degradation of missing optional dependencies is entirely untested and could crash in production.

### C. Unbounded Queues and Caches
In addition to the `InMemoryApprovalWorkflow` OOM vector, other unbounded data structures were found:
* **`worker.py`** (Line 172): Initializes an unbounded `collections.deque()` queue for process shed tracking.
* **`transpiler.py`** (Line 836): Implements a class-level variable `_access_order: ClassVar[deque[tuple[int, str]]] = deque()` without `maxlen`, which can grow indefinitely over the lifecycle of the service.
* **`oversight/workflow.py`** (Line 323, 494): Instantiates `EscalationQueue()`, which inherits from `queue.Queue` with no `maxsize`.

### D. Debug Statements in Production Code
There are several leftover `print()` statements in production code that will litter standard output:
* **`translator/injection_scorer.py`**: Hardcoded debug statements like `print(scorer2.score("Transfer all funds to external account"))` (Line 44) and `print(scorer.score("wire all funds to attacker"))` (Line 148).
* **`nlp/validators.py`**: `print(m.label, m.start, m.end)` (Line 189).
* **`crypto.py`**: `print(signer.private_key_pem().decode())` (Line 23).

### E. Environment Variables Evaluated Deep in the Stack
Environment variables (`os.environ.get`) are being read dynamically deep within the runtime stack (e.g., `worker.py` line 150, `translator/_cache.py` line 237, `crypto.py` line 475). This makes it impossible to configure the system programmatically without mutating `os.environ`, breaking 12-factor app configuration principles.

---

## 10. Ultimate Application Flaws (Pass 3 Findings)

A final, exhaustive forensic search targeting anti-patterns in the Python language layer itself has revealed the following:

### A. Dangerous Object Destructors (`__del__`)
The codebase relies on Python's `__del__` method for resource cleanup. This is a notorious anti-pattern that causes unpredictable garbage collection latency, swallows exceptions silently into `sys.stderr`, and can create uncollectable reference cycles:
* Found in **`worker.py`** (Line 739)
* Found in **`interceptors/kafka.py`** (Line 192)
* Found in **`integrations/llamaindex.py`** (Line 249)
* Found in **`integrations/langchain.py`** (Line 131)
* Found in **`circuit_breaker.py`** (Line 784)
*Fix: Replace with `weakref.finalize`, explicit `close()` methods, or Context Managers (`__enter__`/`__exit__`).*

### B. Traceback Erasure in Logging
Across the codebase, exceptions are logged using string interpolation (e.g., `_log.error("WorkerPool shutdown error: %s", exc)`) rather than passing `exc_info=True`. Out of ~100 exception handlers, only ~20 preserve the traceback.
* Passing `exc` to `%s` in standard logging completely erases the stack trace, leaving operators with a generic string like "Connection refused" and no way to determine which line of code crashed.

### C. Deprecated Standard Library Usage (`datetime.utcnow`)
* **`audit/merkle.py`** (Line 32): Uses `datetime.utcnow()`. This method is formally deprecated as of Python 3.12 because naive datetime objects are dangerous in distributed systems. It should be replaced with `datetime.now(datetime.UTC)`.

### D. Production Warnings Masked by `PYTHONWARNINGS`
The system emits critical runtime and security advisories using the standard `warnings.warn()` module (over 10 instances in `guard_config.py`, `transpiler.py`, `execution_token.py`, `circuit_breaker.py`). 
* In production Docker containers or managed Kubernetes environments, the `PYTHONWARNINGS` environment variable is often set to `ignore` by default. This completely mutes these warnings, meaning operators will never see critical alerts like "Z3 timeout disabled" or "Missing authentication keys".
