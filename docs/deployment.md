# Pramanix -- Operations and Deployment Guide

> **Version:** v0.8.0
> **Audience:** Platform engineers deploying and operating Pramanix in production.
> **Prerequisite:** Read [architecture.md](architecture.md) for the pipeline overview.

---

## 1. Environment Variables

All configuration is read at `GuardConfig()` construction time. Explicit constructor arguments take precedence over env vars; env vars take precedence over coded defaults.

All variables are prefixed `PRAMANIX_`.

**Boolean parsing:** `"1"`, `"true"`, `"yes"` (case-insensitive) = `True`. All other values = `False`.

### Core Variables

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PRAMANIX_EXECUTION_MODE` | `sync` | string | `sync` / `async-thread` / `async-process` |
| `PRAMANIX_SOLVER_TIMEOUT_MS` | `5000` | int (ms) | Per-solver Z3 timeout. Kill and BLOCK if exceeded. |
| `PRAMANIX_MAX_WORKERS` | `4` | int | Worker pool size (thread or process). |
| `PRAMANIX_MAX_DECISIONS_PER_WORKER` | `10000` | int | Decisions before worker pool recycled. Bounds RSS growth to < 50 MiB. |
| `PRAMANIX_WORKER_WARMUP` | `true` | bool | Run a dummy Z3 solve on worker startup to eliminate cold-start JIT spikes. |
| `PRAMANIX_LOG_LEVEL` | `INFO` | string | `DEBUG` / `INFO` / `WARNING` / `ERROR`. Never use DEBUG in production -- may expose field values. |
| `PRAMANIX_METRICS_ENABLED` | `false` | bool | Enable Prometheus metrics export. |
| `PRAMANIX_OTEL_ENABLED` | `false` | bool | Enable OpenTelemetry trace export. |
| `PRAMANIX_TRANSLATOR_ENABLED` | `false` | bool | Enable LLM-based intent translation (NLP mode). |
| `PRAMANIX_FAST_PATH_ENABLED` | `false` | bool | Enable O(1) pre-Z3 screening. |
| `PRAMANIX_SHED_LATENCY_THRESHOLD_MS` | `200` | float (ms) | Circuit breaker latency threshold for load shedding. |
| `PRAMANIX_SHED_WORKER_PCT` | `90` | float (%) | Worker utilization percentage at which shedding begins. |

### Phase 12 Hardening Variables

| Variable | Default | Type | Description |
|----------|---------|------|-------------|
| `PRAMANIX_SOLVER_RLIMIT` | `10000000` | int | Z3 operation cap per solve call. Prevents non-linear logic bombs. `0` = disabled. |
| `PRAMANIX_MAX_INPUT_BYTES` | `65536` | int | Serialized intent + state size cap in bytes (64 KiB). Rejects before Z3. `0` = disabled. |

**Note:** `min_response_ms`, `redact_violations`, and `expected_policy_hash` are constructor-only arguments -- no env var equivalent. Set them in code.

### Recommended Production Baseline

```bash
# Standard web API (async-thread)
PRAMANIX_EXECUTION_MODE=async-thread
PRAMANIX_SOLVER_TIMEOUT_MS=5000
PRAMANIX_MAX_WORKERS=8
PRAMANIX_MAX_DECISIONS_PER_WORKER=10000
PRAMANIX_WORKER_WARMUP=true
PRAMANIX_LOG_LEVEL=INFO
PRAMANIX_SOLVER_RLIMIT=10000000
PRAMANIX_MAX_INPUT_BYTES=65536
```

```bash
# High-security environment (async-process with subprocess isolation)
PRAMANIX_EXECUTION_MODE=async-process
PRAMANIX_SOLVER_TIMEOUT_MS=3000
PRAMANIX_MAX_WORKERS=4
PRAMANIX_MAX_DECISIONS_PER_WORKER=5000
PRAMANIX_WORKER_WARMUP=true
PRAMANIX_SOLVER_RLIMIT=5000000
PRAMANIX_MAX_INPUT_BYTES=32768
```

---

## 2. Container Image -- The Alpine Ban

> **Critical: Do not use Alpine Linux as the base image for any container running Pramanix.**

**Why Alpine is banned:**
- Alpine Linux uses **musl libc** instead of glibc (GNU libc).
- Z3's native library (`libz3.so`) is compiled against glibc.
- Under musl, two failure modes occur:
  - **Segmentation faults:** musl's stack-growth semantics differ from glibc's. Z3's recursive term-rewriting code can exhaust the musl stack and segfault at unpredictable depths.
  - **Performance degradation:** musl's `malloc/free` pattern is 3-10x slower than glibc for Z3's rapid large-tree allocation pattern, breaking the P99 < 10 ms SLA.
- These failures are non-deterministic -- they may not reproduce in unit tests but manifest under load in production.
- There is no practical workaround short of recompiling Z3 from source against musl, which is unsupported by the Z3 project.

**Required base image:**
```dockerfile
# CORRECT
FROM python:3.13-slim          # Debian bookworm slim -- glibc, ~45 MB over Alpine

# BANNED
FROM python:3.13-alpine        # musl libc -- segfaults and 3-10x performance degradation
FROM alpine:3.x                # same problem
```

### Development Dockerfile (`Dockerfile.dev`)

```dockerfile
FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Poetry
RUN pip install --no-cache-dir poetry==1.8.3

COPY pyproject.toml poetry.lock* ./
RUN poetry install --with dev

COPY . .

ENV PRAMANIX_EXECUTION_MODE=sync \
    PRAMANIX_LOG_LEVEL=DEBUG

CMD ["poetry", "run", "pytest", "tests/", "-v"]
```

### Production Dockerfile (`Dockerfile.production`)

```dockerfile
FROM python:3.13-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home pramanix
USER pramanix

WORKDIR /app

# Install production dependencies only
COPY pyproject.toml ./
RUN pip install --no-cache-dir pramanix[all]

COPY src/ src/

ENV PRAMANIX_EXECUTION_MODE=async-thread \
    PRAMANIX_WORKER_WARMUP=true \
    PRAMANIX_LOG_LEVEL=INFO \
    PRAMANIX_SOLVER_RLIMIT=10000000 \
    PRAMANIX_MAX_INPUT_BYTES=65536

ENTRYPOINT ["python", "-m", "your_app"]
```

**Security notes for Dockerfile:**
- Always run as non-root user (`useradd + USER pramanix`)
- Use `--no-install-recommends` to minimize attack surface
- Never install `curl`, `wget`, or `ssh` in production images unless required
- Run `trivy image your-image:tag` before deploying -- target: 0 CRITICAL, 0 HIGH CVEs

---

## 3. Kubernetes Deployment

All K8s manifests live in `deploy/k8s/`.

### Deployment (`deploy/k8s/deployment.yaml`)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pramanix-guard
  namespace: pramanix
spec:
  replicas: 2          # minimum 2 for HA
  selector:
    matchLabels:
      app: pramanix-guard
  template:
    metadata:
      labels:
        app: pramanix-guard
    spec:
      containers:
      - name: pramanix-guard
        image: pramanix/pramanix:0.8.0
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: pramanix-config
        env:
        - name: PRAMANIX_SIGNING_KEY_PEM
          valueFrom:
            secretKeyRef:
              name: pramanix-signing-key
              key: private-key-pem
        resources:
          requests:
            cpu: "500m"
            memory: "512Mi"
          limits:
            cpu: "2000m"
            memory: "1Gi"
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 15    # warmup takes up to 15s on cold start
          periodSeconds: 5
          failureThreshold: 3
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
          failureThreshold: 3
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
```

### HorizontalPodAutoscaler (`deploy/k8s/hpa.yaml`)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: pramanix-guard-hpa
  namespace: pramanix
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: pramanix-guard
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300    # 5-minute stabilization prevents flapping
```

### NetworkPolicy (`deploy/k8s/networkpolicy.yaml`)

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: pramanix-guard-netpol
  namespace: pramanix
spec:
  podSelector:
    matchLabels:
      app: pramanix-guard
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: your-service-namespace
    ports:
    - protocol: TCP
      port: 8080
  egress:
  # LLM API (NLP mode only -- remove if not using translator_enabled)
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - protocol: TCP
      port: 443
  # Redis (for RedisExecutionTokenVerifier, if used)
  - to:
    - namespaceSelector:
        matchLabels:
          name: redis-namespace
    ports:
    - protocol: TCP
      port: 6379
```

### ConfigMap (`deploy/k8s/configmap.yaml`)

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pramanix-config
  namespace: pramanix
data:
  PRAMANIX_EXECUTION_MODE: "async-thread"
  PRAMANIX_SOLVER_TIMEOUT_MS: "5000"
  PRAMANIX_MAX_WORKERS: "8"
  PRAMANIX_MAX_DECISIONS_PER_WORKER: "10000"
  PRAMANIX_WORKER_WARMUP: "true"
  PRAMANIX_LOG_LEVEL: "INFO"
  PRAMANIX_METRICS_ENABLED: "true"
  PRAMANIX_OTEL_ENABLED: "false"
  PRAMANIX_TRANSLATOR_ENABLED: "false"
  PRAMANIX_SOLVER_RLIMIT: "10000000"
  PRAMANIX_MAX_INPUT_BYTES: "65536"
```

---

## 4. Health Probes

### Readiness Probe (`/health/ready`)

**Must not pass until worker pool warmup is complete.** The first ~15 seconds after startup, Z3 is still loading. A request that arrives during this window gets the full cold-start JIT spike.

```python
_guard_ready = False

@app.on_event("startup")
async def startup():
    global _guard_ready
    # Guard.__init__ triggers WorkerPool.spawn() which runs warmup
    guard.start()
    _guard_ready = True

@app.get("/health/ready")
def ready():
    if not _guard_ready:
        return JSONResponse({"status": "initializing"}, status_code=503)
    return {"status": "ready"}
```

**Kubernetes probe settings:**
- `initialDelaySeconds: 15` -- wait 15 seconds before first probe (allows warmup)
- `periodSeconds: 5` -- check every 5 seconds
- `failureThreshold: 3` -- remove from load balancer after 3 consecutive failures

### Liveness Probe (`/health/live`)

Checks that Z3 is not experiencing sustained timeout failures.

```python
@app.get("/health/live")
def live():
    snap = emit_snapshot()
    z3_rate = snap["z3_timeouts"]["window_rate"]
    if z3_rate > 0.50:
        return JSONResponse(
            {"status": "unhealthy", "z3_timeout_rate": z3_rate},
            status_code=503
        )
    return {"status": "live", "z3_timeout_rate": z3_rate}
```

---

## 5. Observability

### Structured Logs (structlog)

- All `Guard.verify()` calls emit a structured JSON log line.
- Secret-key redaction processor runs first -- keys matching `secret|api_key|token|hmac|password|passwd|credential|private_key` are replaced with `<redacted>`.
- Log format: newline-delimited JSON (`structlog.processors.JSONRenderer()`).

**Example log line:**
```json
{"event": "decision", "policy": "TransferPolicy", "decision_id": "550e8400-...", "allowed": true, "status": "SAFE", "latency_ms": 6.2, "timestamp": "2026-03-22T04:59:23Z"}
```

**Ship stdout to aggregators:**
- **Kubernetes:** Use `kubectl logs` or sidecar containers (Fluentd, Vector) to capture stdout.
- **Vector config:** Parse JSON from stdout, forward to Grafana Loki or Datadog Logs.

### Prometheus Metrics

Enable with `PRAMANIX_METRICS_ENABLED=true` or `GuardConfig(metrics_enabled=True)`.

| Metric | Type | Description |
|--------|------|-------------|
| `pramanix_decisions_total` | Counter | Total decisions by `policy` and `status` labels |
| `pramanix_decision_latency_seconds` | Histogram | End-to-end `verify()` latency by `policy` label. Buckets: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s |
| `pramanix_solver_timeouts_total` | Counter | Z3 solver timeouts by `policy` label |
| `pramanix_validation_failures_total` | Counter | Intent/state validation failures by `policy` label |

### Red-Flag Telemetry (NLP mode)

Three rolling-window counters with 300-second window:

| Counter | Trigger | Operational meaning |
|---------|---------|---------------------|
| `injection_spikes` | `injection_confidence_score >= 0.5` | Automated attack campaign in progress |
| `consensus_mismatches` | Dual-model extraction disagrees | Adversarial model-probing |
| `z3_timeouts` | Z3 subprocess killed after timeout | Constraint-complexity DoS |

**Recommended alerting thresholds:**

| Metric | Warning | Critical |
|--------|---------|----------|
| `injection_spike_rate` (5 min) | > 0.10 | > 0.30 |
| `consensus_mismatch_rate` (5 min) | > 0.05 | > 0.20 |
| `z3_timeout_rate` (5 min) | > 0.01 | > 0.10 |

---

## 6. Security Hardening Checklist

Before deploying to production:

- [ ] Base image is `python:3.13-slim` (Debian) -- NOT Alpine
- [ ] `PRAMANIX_WORKER_WARMUP=true` -- prevents cold-start SLA breach
- [ ] `PRAMANIX_SOLVER_TIMEOUT_MS` is set -- prevents Z3 DoS
- [ ] `PRAMANIX_MAX_DECISIONS_PER_WORKER` is set -- prevents RSS memory leak
- [ ] `PRAMANIX_SOLVER_RLIMIT` is set -- prevents logic-bomb DoS within timeout window (H08)
- [ ] `PRAMANIX_MAX_INPUT_BYTES` is set -- prevents big-data DoS before Z3 (H06)
- [ ] `GuardConfig(signer=PramanixSigner.from_pem(...))` enabled -- Ed25519-signed decisions
- [ ] `GuardConfig(expected_policy_hash=fingerprint)` set -- detects silent policy drift (H09)
- [ ] `GuardConfig(min_response_ms=50.0)` set for external APIs -- timing oracle prevention (H13)
- [ ] `GuardConfig(redact_violations=True)` for external APIs -- oracle attack prevention (H04)
- [ ] Signing private key stored in AWS KMS / HashiCorp Vault / Kubernetes Secret -- never in source code
- [ ] Container runs as non-root user (`runAsNonRoot: true`)
- [ ] `PRAMANIX_LOG_LEVEL=INFO` -- never DEBUG in production
- [ ] Readiness probe gated on Guard initialization (`initialDelaySeconds: 15`)
- [ ] `trivy image your-image:tag` -- 0 CRITICAL, 0 HIGH CVEs
- [ ] Decision log shipped to immutable storage (S3 Object Lock, Azure Blob Immutable)
- [ ] `pramanix audit verify` runs nightly against the decision log

---

## 7. Upgrade Runbook

### Patch releases (x.y.Z)

- Pull the new image or wheel
- Run `pytest tests/ -q --tb=short`
- Deploy with rolling update (zero downtime)

### Minor releases with invariant changes (x.Y.z)

- Increment `Meta.version` in all affected policies
- Run the full test suite (705+ tests) + Hypothesis property tests
- Deploy to staging first
- Route 10% of production traffic to new version for 24 hours
- Compare decision distributions (ALLOW/BLOCK ratio) between versions
- Full rollout if distributions are stable

### Emergency rollback

```bash
# Kubernetes rolling rollback
kubectl rollout undo deployment/pramanix-guard

# Verify rollback complete
kubectl rollout status deployment/pramanix-guard
```

**After rollback:**
- Identify which decisions may have been made under the new policy version
- Use `policy_hash` in decision audit logs to identify affected decisions
- Report to compliance if the policy change affected a regulated workflow

---

## 8. Ed25519 Key Management

### Generating Keys

```python
from pramanix.crypto import PramanixSigner

# Generate once
signer = PramanixSigner.generate()
private_pem = signer.private_key_pem()   # store in secrets manager
public_pem  = signer.public_key_pem()    # distribute to audit tools, never expires
print(private_pem.decode())
print(public_pem.decode())
```

### Loading in Production

```python
import os
from pramanix.crypto import PramanixSigner

# Load from env var (Kubernetes Secret injected as env var)
signer = PramanixSigner.from_pem(
    os.environ["PRAMANIX_SIGNING_KEY_PEM"].encode()
)
config = GuardConfig(signer=signer)
```

### Key Rotation

- Generate a new key pair
- Archive the old public key -- decisions signed with the old key remain verifiable forever
- The `key_id` in each signed decision identifies which public key to use
- Deploy new `GuardConfig(signer=new_signer)` with rolling update
- After all in-flight requests complete (max: `solver_timeout_ms`), the old private key can be destroyed
