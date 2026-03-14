# Pramanix — Operations Handbook

> **Audience:** Platform engineers responsible for deploying, operating, and monitoring Pramanix in production.
> **Prerequisite:** Read [architecture.md](architecture.md) for the Five-Layer Defence overview.

---

## 1. Environment Variables

All configuration is read from environment variables at `GuardConfig()` construction
time. Explicit constructor arguments take precedence over environment variables;
environment variables take precedence over coded defaults.

Every variable is prefixed `PRAMANIX_`.

| Variable | Default | Type | Description |
|---|---|---|---|
| `PRAMANIX_EXECUTION_MODE` | `sync` | string | `sync` \| `async-thread` \| `async-process` |
| `PRAMANIX_SOLVER_TIMEOUT_MS` | `5000` | int (ms) | Per-solver Z3 timeout. Kill and BLOCK if exceeded. |
| `PRAMANIX_MAX_WORKERS` | `4` | int | Worker pool size (thread or process). |
| `PRAMANIX_MAX_DECISIONS_PER_WORKER` | `10000` | int | Decisions before worker pool recycled. Bounds RSS growth to < 50 MB. |
| `PRAMANIX_WORKER_WARMUP` | `true` | bool | Run a dummy Z3 solve on worker startup to eliminate cold-start JIT spikes. |
| `PRAMANIX_LOG_LEVEL` | `INFO` | string | Structured log level: `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` |
| `PRAMANIX_METRICS_ENABLED` | `false` | bool | Enable Prometheus metrics export (future milestone). |
| `PRAMANIX_OTEL_ENABLED` | `false` | bool | Enable OpenTelemetry trace export (future milestone). |
| `PRAMANIX_TRANSLATOR_ENABLED` | `false` | bool | Enable LLM-based intent translation (Neuro-Symbolic mode). |

**Boolean parsing:** `"1"`, `"true"`, `"yes"` (case-insensitive) → `True`. All
other values (including missing) → `False`. Invalid integers silently fall back
to the coded default.

### Recommended production baseline

```bash
PRAMANIX_EXECUTION_MODE=async-thread
PRAMANIX_SOLVER_TIMEOUT_MS=5000
PRAMANIX_MAX_WORKERS=8
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000
PRAMANIX_WORKER_WARMUP=true
PRAMANIX_LOG_LEVEL=INFO
```

For adversarial or regulated environments (e.g., banking):

```bash
PRAMANIX_EXECUTION_MODE=async-process   # subprocess isolation
PRAMANIX_SOLVER_TIMEOUT_MS=3000         # tighter DoS bound
PRAMANIX_MAX_DECISIONS_PER_WORKER=5000  # more frequent recycle = lower RSS peak
```

---

## 2. Container Image — The Alpine Ban

> **Critical:** Do not use Alpine Linux as the base image for any container
> running Pramanix.

### Why Alpine is banned

Alpine Linux uses **musl libc** instead of the standard GNU libc (glibc). The
Z3 SMT solver's native library (`libz3.so`) is compiled against glibc and
exhibits two failure modes under musl:

1. **Segmentation faults** — musl's stack-growth semantics differ from glibc's.
   Z3's recursive term-rewriting code can exhaust the musl stack and segfault
   at unpredictable depths, producing silent BLOCK decisions at best and process
   crashes at worst.

2. **Performance degradation** — musl's `malloc`/`free` implementation is
   optimised for small allocations; Z3's allocator pattern (rapid allocation and
   deallocation of large expression trees) can be 3–10× slower under musl,
   breaking the P99 < 10 ms SLA.

These failure modes are **non-deterministic** — the issue may not reproduce in
unit tests but manifests under load in production. There is no practical
workaround short of recompiling Z3 from source against musl, which is
unsupported by the Z3 project.

### Required base image

Use a **glibc-based slim image**:

```dockerfile
# ✅ CORRECT
FROM python:3.13-slim          # Debian bookworm slim — glibc, minimal footprint

# ❌ BANNED
FROM python:3.13-alpine        # musl libc — segfaults and performance degradation
FROM alpine:3.x                # same problem
```

The `python:3.13-slim` image adds approximately 45 MB over `alpine` but
eliminates the entire class of musl-related Z3 failures. This is a non-negotiable
architectural constraint documented in Blueprint §48.

### Dockerfile template

```dockerfile
FROM python:3.13-slim

# Install system dependencies (z3-solver wheels require no native deps on slim-debian)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ src/
COPY pramanix_hardened.py pramanix_llm_hardened.py pramanix_telemetry.py ./

# Allow non-root execution
RUN useradd -m pramanix
USER pramanix

ENV PRAMANIX_EXECUTION_MODE=async-thread \
    PRAMANIX_WORKER_WARMUP=true \
    PRAMANIX_LOG_LEVEL=INFO

ENTRYPOINT ["python", "-m", "your_app"]
```

---

## 3. Telemetry Integration

### 3.1 Overview

`pramanix_telemetry.py` exposes three red-flag counters in a 300-second rolling
window and a `StructuredLogEmitter` that writes newline-delimited JSON to any
writable stream.

The workflow to get telemetry data into Grafana or Datadog is:

```
Pramanix process                Log aggregator         Dashboard
  StructuredLogEmitter  ──►  stdout / file  ──►  Fluentd / Vector  ──►  Grafana / Datadog
                                               (or Datadog Agent)
```

### 3.2 Wiring the emitter

```python
from pramanix_telemetry import get_telemetry, StructuredLogEmitter

# Option A — write to stdout (Docker / Kubernetes log capture):
get_telemetry().add_red_flag_listener(StructuredLogEmitter())

# Option B — write to a named log file:
import sys
log_file = open("/var/log/pramanix/redflag.jsonl", "a", buffering=1)  # line-buffered
get_telemetry().add_red_flag_listener(StructuredLogEmitter(stream=log_file, prefix="pramanix"))

# Option C — custom callback (push directly to an HTTP endpoint):
def my_listener(event_type: str, **payload) -> None:
    requests.post("https://ingest.example.com/events",
                  json={"event": event_type, **payload}, timeout=1)

get_telemetry().add_red_flag_listener(my_listener)
```

### 3.3 Event schema

Every event emitted by `StructuredLogEmitter` is a single JSON line:

```jsonc
// Injection spike
{"event": "pramanix.injection_spike", "ts_mono": 1234567.890, "score": 0.90}

// Consensus mismatch
{"event": "pramanix.consensus_mismatch", "ts_mono": 1234567.891}

// Z3 timeout
{"event": "pramanix.z3_timeout", "ts_mono": 1234567.892}
```

| Field | Type | Description |
|---|---|---|
| `event` | string | `<prefix>.<event_type>`. Default prefix: `pramanix`. |
| `ts_mono` | float | `time.monotonic()` value at event time. Not wall-clock. |
| `score` | float | (injection_spike only) The computed injection confidence score. |

### 3.4 Snapshot endpoint

`emit_snapshot()` returns a point-in-time dict suitable for serving from a
`/metrics/pramanix` HTTP endpoint:

```python
from pramanix_telemetry import emit_snapshot
import json

# FastAPI example:
@app.get("/metrics/pramanix")
def pramanix_metrics():
    return emit_snapshot()
```

```json
{
  "window_s": 300.0,
  "injection_spikes":     {"window_count": 3, "window_rate": 0.75, "total_events": 3, "total_attempts": 4},
  "consensus_mismatches": {"window_count": 2, "window_rate": 0.67, "total_events": 2, "total_attempts": 3},
  "z3_timeouts":          {"window_count": 0, "window_rate": 0.00, "total_events": 0, "total_attempts": 0}
}
```

| Field | Description |
|---|---|
| `window_count` | Events in the last `window_s` seconds (300 s default). Primary alert metric. |
| `window_rate` | `window_count / window_attempts` — fraction of evaluations that triggered the flag. |
| `total_events` | All events since process start. Long-running forensics. |
| `total_attempts` | All evaluations since process start. |

### 3.5 Grafana / Datadog integration

#### Option A — Fluentd / Vector (stdout scrape)

1. Configure your container runtime to capture stdout as a log stream.
2. Deploy a Fluentd or Vector sidecar that tails the application log.
3. Add a JSON parse filter to extract `event`, `ts_mono`, and `score`.
4. Forward to Grafana Loki (for log-based dashboards) or Datadog Logs.

**Vector config snippet:**

```toml
[sources.pramanix_stdout]
type = "docker_logs"
include_containers = ["pramanix-*"]

[transforms.parse_pramanix]
type        = "remap"
inputs      = ["pramanix_stdout"]
source      = '''
  . = parse_json!(.message)
  .source = "pramanix"
'''

[sinks.datadog]
type    = "datadog_logs"
inputs  = ["parse_pramanix"]
api_key = "${DD_API_KEY}"
```

#### Option B — Prometheus scrape (snapshot endpoint)

Expose `emit_snapshot()` behind an HTTP endpoint and configure a Prometheus
scrape job:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: pramanix
    static_configs:
      - targets: ["your-service:8080"]
    metrics_path: /metrics/pramanix
    scrape_interval: 15s
```

Convert the snapshot JSON to Prometheus gauges with a small middleware:

```python
from prometheus_client import Gauge

INJECTION_SPIKE_RATE  = Gauge("pramanix_injection_spike_rate",  "5-min injection spike rate")
CONSENSUS_MISS_RATE   = Gauge("pramanix_consensus_mismatch_rate", "5-min consensus mismatch rate")
Z3_TIMEOUT_RATE       = Gauge("pramanix_z3_timeout_rate",       "5-min Z3 timeout rate")

@app.get("/metrics/pramanix")
def pramanix_metrics():
    snap = emit_snapshot()
    INJECTION_SPIKE_RATE.set(snap["injection_spikes"]["window_rate"])
    CONSENSUS_MISS_RATE.set(snap["consensus_mismatches"]["window_rate"])
    Z3_TIMEOUT_RATE.set(snap["z3_timeouts"]["window_rate"])
    return snap
```

### 3.6 Recommended alerting thresholds

| Metric | Warning | Critical | Meaning |
|---|---|---|---|
| `injection_spike_rate` (5 min) | > 0.10 | > 0.30 | > 10 % of evaluations → active scan; > 30 % → automated attack campaign |
| `consensus_mismatch_rate` (5 min) | > 0.05 | > 0.20 | Adversarial model-probing attempts |
| `z3_timeout_rate` (5 min) | > 0.01 | > 0.10 | Constraint-complexity DoS; consider lowering `SOLVER_TIMEOUT_MS` |

---

## 4. Health Checks

### Readiness probe

The readiness probe must not pass until the worker pool has completed warmup.
Expose a `/health/ready` endpoint that returns `503` until the guard is
initialised:

```python
_guard_ready = False

@app.on_event("startup")
async def startup():
    global _guard_ready
    guard.start()       # calls WorkerPool.spawn() internally
    _guard_ready = True

@app.get("/health/ready")
def ready():
    if not _guard_ready:
        raise HTTPException(status_code=503, detail="Guard not yet initialised")
    return {"status": "ready"}
```

### Liveness probe

Any `Decision` with `reason="worker_error"` or `reason="solver_timeout"` at a
sustained rate indicates a systemic failure. Log these and optionally push them
to the liveness endpoint:

```python
@app.get("/health/live")
def live():
    snap = emit_snapshot()
    z3_rate = snap["z3_timeouts"]["window_rate"]
    if z3_rate > 0.50:
        raise HTTPException(status_code=503, detail=f"Z3 timeout rate critical: {z3_rate:.2%}")
    return {"status": "live"}
```

---

## 5. Security Hardening Checklist

Before deploying to production:

- [ ] Base image is `python:3.x-slim` (Debian) — **not** Alpine
- [ ] `PRAMANIX_WORKER_WARMUP=true` (prevents cold-start SLA breach)
- [ ] `PRAMANIX_SOLVER_TIMEOUT_MS` is set (defend against Z3 DoS)
- [ ] `PRAMANIX_MAX_DECISIONS_PER_WORKER` is set (prevents RSS memory leak)
- [ ] `StructuredLogEmitter` is wired to a persistent log aggregator
- [ ] Alerting thresholds are configured in Grafana / Datadog
- [ ] `_HUMAN_APPROVAL_GATEWAY._backend` is wired for any policy that allows full-drain transfers
- [ ] Container runs as a non-root user (`USER pramanix`)
- [ ] `PRAMANIX_LOG_LEVEL=INFO` (do not use `DEBUG` in production — may expose field values)
- [ ] Readiness probe is gated on `Guard` initialisation

---

## 6. Upgrade Runbook

### Minor version upgrades (patch releases)

1. Pull the new image / wheel.
2. Run `python -m pytest tests/ -q --tb=short`.
3. Run `python radar_test.py` — confirm 13/13 pass.
4. Deploy with a rolling update (zero-downtime).

### Major version upgrades (policy invariant changes)

1. Increment `Meta.version` in all affected policies.
2. Run the full regression suite + property-based tests.
3. Run `radar_test.py`.
4. Deploy to a staging environment and run a shadow-mode comparison:
   route 10 % of production traffic to the new version and compare decisions
   against the old version for 24 hours.
5. If decision distributions are stable, proceed with full rollout.

### Emergency rollback

If a deployment produces an unexpected BLOCK rate spike:

```bash
# Kubernetes — roll back to the previous deployment
kubectl rollout undo deployment/pramanix-guard

# Verify the rollback
kubectl rollout status deployment/pramanix-guard
```

The `total_events` counter in `emit_snapshot()` does not reset on rollback
(it is in-process state). After rollback, monitor `window_rate` (not
`total_events`) to assess whether the anomaly has cleared.

---

## 7. Container Image Security — Trivy Scan Policy

### 7.1 Gate policy

Every release build of `pramanix:latest` (and release-tagged images) **must pass**:

```bash
trivy image --exit-code 1 --severity CRITICAL,HIGH pramanix:latest
```

**Policy:** `0 CRITICAL, 0 HIGH OS-level vulnerabilities`.

The CI release pipeline (`release.yml`) runs this scan as a blocking gate before
the GitHub Release is created. Any CRITICAL or HIGH finding fails the pipeline
and blocks publication.

### 7.2 How to run the scan locally

```bash
# Install trivy (https://aquasecurity.github.io/trivy/)
brew install trivy                        # macOS
sudo apt-get install -y trivy             # Debian/Ubuntu

# Build the image (requires VERSION build-arg)
docker build \
  --build-arg VERSION=$(poetry version -s) \
  -f Dockerfile.production \
  -t pramanix:local .

# Run the full vulnerability scan
trivy image \
  --exit-code 1 \
  --severity CRITICAL,HIGH \
  --format table \
  pramanix:local

# Run with SARIF output (for GitHub Security tab)
trivy image \
  --exit-code 0 \
  --severity CRITICAL,HIGH,MEDIUM,LOW \
  --format sarif \
  --output trivy-results.sarif \
  pramanix:local
```

### 7.3 Accepted LOW / MEDIUM findings with rationale

The following LOW and MEDIUM severity findings are **accepted** as of v0.5.0.
Each is reviewed on every release and re-evaluated when a fix becomes available.

> **Reviewer protocol:** Run `trivy image --severity LOW,MEDIUM pramanix:latest`
> before each release. Compare findings against the table below.  Any new finding
> not in this table must be triaged before the release proceeds.

---

#### OS-level findings — `python:3.11-slim-bookworm` base

| CVE | Package | Severity | Status | Rationale |
|---|---|---|---|---|
| CVE-2023-4039 | `gcc` (build stage only) | MEDIUM | **Accepted — build-stage only** | `gcc` is installed in the *builder* stage only and is **not copied** to the runner image. The runner stage copies only `/opt/venv` and application code; `gcc` is absent from the final layer. Trivy finds this only when scanning multi-stage images with `--include-non-union-layers` (not the default). |
| CVE-2024-0684 | `coreutils` | LOW | **Accepted — no attack path** | `coreutils` is used during image build (`RUN cp`, `chmod`). The known issue requires a local attacker with shell access; the container runs as UID 10001 with read-only filesystem and no shell login (`/sbin/nologin`). No credible exploit path exists in the Pramanix threat model. |
| — | General `libc6` patch-level | LOW | **Accepted — Debian patching cadence** | Debian bookworm-slim receives security patches on a 1–4 week cadence. LOW severity `libc6` findings at release time are expected to be patched within the next base-image rebuild. Images are rebuilt on every Pramanix release to pick up debian security updates. |

#### Python-level findings — pip wheel dependencies

| Package | Version | Severity | Status | Rationale |
|---|---|---|---|---|
| `certifi` | latest | LOW | **Accepted — auto-updated** | `certifi` is pinned to the latest version at build time via `pip install --upgrade`. Any CVE is typically resolved within 24 hours of disclosure by a new release. The Dockerfile runs `pip install --upgrade pip setuptools wheel` before installing dependencies. |
| `setuptools` | build-time only | MEDIUM | **Accepted — not in runtime image** | `setuptools` is used only in the builder stage to compile wheels. It is not installed in the runner venv (runner stage uses `--no-deps` copy). Confirmed absent with `pip show setuptools` inside runner. |

### 7.4 Remediation SLAs

| Severity | SLA |
|---|---|
| **CRITICAL** | Immediate — block the release, hotfix within 24 hours, re-release |
| **HIGH** | Block the release — fix in the next patch release (≤ 7 days) |
| **MEDIUM** | Triage within 14 days; add to acceptance table if no fix available |
| **LOW** | Triage within 30 days; add to acceptance table if no fix available; accept if no credible exploit path |
| **NEGLIGIBLE** | Log only; no SLA |

### 7.5 Keeping the base image fresh

The `Dockerfile.production` uses `python:3.11-slim-bookworm` as the base.
Debian security advisories and CVE patches reach `python:3.x-slim` within 1–4 weeks
via official Docker Hub base-image rebuilds.

**Recommended practice:** Rebuild the production image **weekly** (or on every
Pramanix release) using the digest-pinning workflow:

```bash
# Pull latest base (picks up Debian security patches)
docker pull python:3.11-slim-bookworm

# Rebuild pramanix with the refreshed base
docker build --no-cache \
  --build-arg VERSION=$(poetry version -s) \
  -f Dockerfile.production \
  -t pramanix:$(poetry version -s) .

# Scan and confirm zero CRITICAL/HIGH
trivy image --exit-code 1 --severity CRITICAL,HIGH pramanix:$(poetry version -s)
```

To pin to a deterministic digest for reproducible builds:

```bash
# Get the current digest
docker inspect python:3.11-slim-bookworm --format '{{ index .RepoDigests 0 }}'
# → python@sha256:<digest>

# Use the digest in Dockerfile.production for reproducibility:
# FROM python@sha256:<digest> AS builder
```

---

