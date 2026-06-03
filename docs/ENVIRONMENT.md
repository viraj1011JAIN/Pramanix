# ENVIRONMENT.md — Pramanix Development & Deployment Environment Guide

> **Purpose**: Single reference for every environment variable, service dependency, and API key
> needed to run Pramanix in production, development, or CI. Supersedes `docs/ENVIRONMENT_SETUP.md`.
>
> **Last Updated**: 2026-06-03

---

## Quick Start (Development)

```powershell
# Windows (PowerShell)
cd C:\Pramanix
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[all]"
cp .env.example .env
# Fill in API keys you need
```

```bash
# Linux / macOS
cd /path/to/pramanix
python -m venv .venv
source .venv/bin/activate
pip install -e ".[all]"
cp .env.example .env
```

### Minimum Installation (Z3 core only — no LLM, no Redis)

```bash
pip install pramanix
# or
pip install -e .
```

This installs: `pydantic`, `z3-solver`, `structlog`, `google-re2`.
The formal verification core is fully functional with no external services.

---

## Python Version

| Version | Status |
| --------- |--------|
| 3.11 | ✅ Supported (declared minimum) |
| 3.12 | ✅ Supported |
| 3.13 | ✅ CI-tested (primary) |
| 3.10 and below | ❌ Not supported |
| 4.0 and above | ❌ Excluded (`<4.0` upper bound) |

---

## LLM API Keys (Optional — only needed for `translator` extra)

### Anthropic Claude (`AnthropicTranslator`)

```env
ANTHROPIC_API_KEY=sk-ant-...
```

Install: `pip install 'pramanix[translator]'`

### OpenAI / Azure OpenAI (`OpenAICompatTranslator`)

```env
OPENAI_API_KEY=sk-...
# Azure / vLLM / LMStudio override:
OPENAI_BASE_URL=https://your-deployment.openai.azure.com/...
```

### Google Gemini (`GeminiTranslator`)

```env
GOOGLE_API_KEY=AIza...
```

Install: `pip install 'pramanix[gemini]'`

### Mistral AI (`MistralTranslator`)

```env
MISTRAL_API_KEY=...
```

Install: `pip install 'pramanix[mistral]'`

### Cohere (`CohereTranslator`)

```env
COHERE_API_KEY=...
```

Install: `pip install 'pramanix[cohere]'`

### AWS Bedrock (`BedrockTranslator`)

Uses the standard AWS credential chain — no Pramanix-specific variable.
Configure via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / IAM role / instance profile.

Install: `pip install 'pramanix[bedrock]'`

### Google Vertex AI (`VertexAITranslator`)

Uses Application Default Credentials (ADC).

```bash
gcloud auth application-default login
# or
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

Install: `pip install 'pramanix[vertexai]'`

### Ollama (local, `OllamaTranslator`)

No API key needed. Ollama must be running locally.

```env
OLLAMA_BASE_URL=http://localhost:11434  # default
```

---

## Audit Sinks (Optional)

### Datadog (`DatadogAuditSink`)

```env
DD_API_KEY=...
DD_SITE=datadoghq.com  # optional, default: datadoghq.com
```

Install: `pip install 'pramanix[datadog]'`

### Splunk HEC (`SplunkHecAuditSink`)

Pass via constructor (store token in secrets manager):

```python
SplunkHecAuditSink(
    hec_url=os.environ["PRAMANIX_SPLUNK_HEC_URL"],
    hec_token=os.environ["PRAMANIX_SPLUNK_HEC_TOKEN"],
)
```

Install: `pip install 'pramanix[splunk]'`

### Amazon S3 (`S3AuditSink`)

Uses standard AWS credential chain.

```env
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1  # optional
```

Install: `pip install 'pramanix[s3]'`

### Apache Kafka (`KafkaAuditSink`)

Pass `producer_conf` dict to constructor:

```python
KafkaAuditSink(producer_conf={
    "bootstrap.servers": "kafka:9092",
    "security.protocol": "SASL_SSL",
    "sasl.mechanism": "PLAIN",
})
```

Install: `pip install 'pramanix[kafka]'`

---

## Cryptographic Signing (Optional)

### Ed25519 (`PramanixSigner`)

```env
PRAMANIX_SIGNING_KEY_PEM=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----
```

Generate:

```python
from pramanix.crypto import PramanixSigner
signer = PramanixSigner.generate()
print(signer.private_key_pem().decode())   # store in secrets manager
print(signer.public_key_pem().decode())    # publish for verifiers
```

Install: `pip install 'pramanix[crypto]'`

### RS256 (`RS256Signer`)

```env
PRAMANIX_RS256_SIGNING_KEY_PEM=-----BEGIN PRIVATE KEY-----\n...
```

### ES256 (`ES256Signer`)

```env
PRAMANIX_ES256_SIGNING_KEY_PEM=-----BEGIN EC PRIVATE KEY-----\n...
```

---

## Distributed State (Optional)

### Redis (Circuit Breaker + Intent Cache)

```env
PRAMANIX_REDIS_URL=redis://localhost:6379/0
# With auth:
PRAMANIX_REDIS_URL=redis://:password@host:6379/0
```

Used by:
- `RedisDistributedBackend` (distributed circuit breaker)
- `IntentCache` (LLM response caching)
- `RedisExecutionTokenVerifier` (anti-replay)

Install: `pip install 'pramanix[redis]'`

### PostgreSQL (Execution Tokens)

```env
# Passed to asyncpg.connect() via constructor
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

Install: `pip install 'pramanix[postgres]'`

---

## Key Management (Optional)

### AWS Secrets Manager

```env
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
```

Install: `pip install 'pramanix[aws]'`

### Azure Key Vault

```env
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
AZURE_TENANT_ID=...
```

Install: `pip install 'pramanix[azure]'`

### GCP Secret Manager

```env
GOOGLE_APPLICATION_CREDENTIALS=/path/to/sa.json
```

Install: `pip install 'pramanix[gcp]'`

### HashiCorp Vault

```env
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=hvs...
```

Install: `pip install 'pramanix[vault]'`

---

## Observability (Optional)

### Prometheus

```env
PRAMANIX_METRICS_ENABLED=true
```

Install: `pip install 'pramanix[metrics]'`

Metrics are exposed for scraping; you must configure your Prometheus instance.

### OpenTelemetry

```env
PRAMANIX_OTEL_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317  # default
```

Install: `pip install 'pramanix[otel]'`

---

## Guard Tuning Variables

| Variable | Default | Description |
| ---------- |---------| ------------- |
| `PRAMANIX_ENV` | `development` | Set to `production` to block InMemory* sinks |
| `PRAMANIX_LOG_LEVEL` | `INFO` | structlog level |
| `PRAMANIX_SOLVER_TIMEOUT_MS` | `5000` | Z3 solver timeout per call (ms) |
| `PRAMANIX_MAX_WORKERS` | `4` | Worker pool size |
| `PRAMANIX_SOLVER_RLIMIT` | `10000000` | Z3 resource limit (elementary operations) |
| `PRAMANIX_MAX_INPUT_BYTES` | `65536` | Max serialised intent+state payload (bytes) |
| `PRAMANIX_MAX_INPUT_CHARS` | `512` | Max raw NL input (chars) |
| `PRAMANIX_INJECTION_THRESHOLD` | `0.5` | Injection detection threshold [0.0, 1.0] |
| `PRAMANIX_FAST_PATH_ENABLED` | `false` | Enable numeric fast-path pre-check |
| `PRAMANIX_MERKLE_ARCHIVE_KEY` | (unset) | 64-char hex key for AES-256-GCM Merkle archive encryption. **Required for HIPAA/PCI compliance** — plaintext archives are written when this variable is absent. |
| `PRAMANIX_MERKLE_SEGMENT_DAYS` | `30` | Days per Merkle archive segment |
| `PRAMANIX_MERKLE_MAX_ACTIVE_ENTRIES` | `100000` | Max in-memory Merkle entries before auto-archival |

---

## CI / Testing Requirements

### Minimum (unit tests only — no external services)

```bash
# No env vars required. All unit tests use real in-process Z3 + fakeredis.
pytest tests/unit tests/adversarial tests/property -q
```

### Full suite including integration tests

```bash
# LLM keys (skip if absent — translator tests will be skipped)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-...
GOOGLE_API_KEY=AIza...

# Redis (required for distributed circuit breaker integration tests)
PRAMANIX_REDIS_URL=redis://localhost:6379/0

# AWS (LocalStack or real; required for AWS integration tests)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1

# PostgreSQL (required for postgres token tests)
DATABASE_URL=postgresql://test:test@localhost:5432/pramanix_test
```

### Docker / Kubernetes

See `deploy/k8s/` for Kubernetes manifests:
- `namespace.yaml`, `configmap.yaml`, `service.yaml`, `hpa.yaml`, `networkpolicy.yaml`

Production Docker image: `python:3.13-slim-bookworm` base (with SHA256 digest pinning). Alpine banned (z3-solver musl incompatibility). Both `Dockerfile.production` and `Dockerfile.dev` use Python 3.13 Debian Bookworm slim.

---

## Security Notes

1. **Never commit `.env`** — it is listed in `.gitignore`
2. **Use a secrets manager** in production (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets)
3. **Rotate keys** when team members leave or keys are exposed
4. **Archive public keys** — decisions signed with old keys remain verifiable indefinitely
5. **Set `PRAMANIX_ENV=production`** to prevent accidental use of InMemory* sinks
6. **`google-re2` is a required (non-optional) dependency** — it replaces stdlib `re` for all regex operations to prevent ReDoS attacks. Do not remove it.
