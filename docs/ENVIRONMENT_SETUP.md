# Pramanix Environment Setup

Complete guide to every environment variable, external service, and API key
required to run Pramanix in production, development, and CI.

---

## Quick Start

```bash
cp .env.example .env
# Fill in the values you need for your deployment
source .env   # or use python-dotenv / direnv
```

---

## LLM API Keys

### Anthropic Claude (`AnthropicTranslator`)

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | Anthropic API key from [console.anthropic.com](https://console.anthropic.com) |

```bash
ANTHROPIC_API_KEY=sk-ant-...
```

### OpenAI / Azure OpenAI (`OpenAICompatTranslator`)

| Variable | Required | Description |
|---|---|---|
| `OPENAI_API_KEY` | Yes | OpenAI API key from [platform.openai.com](https://platform.openai.com) |
| `OPENAI_BASE_URL` | No | Override for Azure OpenAI, vLLM, LMStudio, or any compatible endpoint |

```bash
OPENAI_API_KEY=sk-...
# Azure example:
OPENAI_BASE_URL=https://your-deployment.openai.azure.com/openai/deployments/gpt-4o
```

### Google Gemini (`GeminiTranslator`)

| Variable | Required | Description |
|---|---|---|
| `GOOGLE_API_KEY` | Yes | Google AI Studio key from [aistudio.google.com](https://aistudio.google.com) |

```bash
GOOGLE_API_KEY=AIza...
```

### Mistral AI (`MistralTranslator`)

| Variable | Required | Description |
|---|---|---|
| `MISTRAL_API_KEY` | Yes | Mistral API key from [console.mistral.ai](https://console.mistral.ai) |

### Cohere (`CohereTranslator`)

| Variable | Required | Description |
|---|---|---|
| `COHERE_API_KEY` | Yes | Cohere API key from [dashboard.cohere.com](https://dashboard.cohere.com) |

### AWS Bedrock (`BedrockTranslator`)

Uses standard AWS credential chain — no Pramanix-specific variable needed.
Configure via `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / IAM role.

### Google Vertex AI (`VertexAITranslator`)

Uses Application Default Credentials (ADC).
Run `gcloud auth application-default login` or set `GOOGLE_APPLICATION_CREDENTIALS`.

---

## Audit Sinks

### Datadog (`DatadogAuditSink`)

| Variable | Required | Description |
|---|---|---|
| `DD_API_KEY` | Yes | Datadog API key |
| `DD_SITE` | No | Datadog site (default: `datadoghq.com`) |

Install: `pip install 'pramanix[datadog]'`

### Splunk HEC (`SplunkHecAuditSink`)

Configure via constructor arguments — no env var fallback. Store the HEC token
in your secrets manager and pass it at runtime:

```python
SplunkHecAuditSink(
    hec_url=os.environ["PRAMANIX_SPLUNK_HEC_URL"],
    hec_token=os.environ["PRAMANIX_SPLUNK_HEC_TOKEN"],
)
```

Install: `pip install 'pramanix[splunk]'`

### Amazon S3 (`S3AuditSink`)

| Variable | Required | Description |
|---|---|---|
| `AWS_ACCESS_KEY_ID` | Yes (or IAM) | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | Yes (or IAM) | AWS secret key |
| `AWS_DEFAULT_REGION` | No | AWS region (default: `us-east-1`) |

Install: `pip install 'pramanix[s3]'`

### Apache Kafka (`KafkaAuditSink`)

Configure via `producer_conf` dict passed to the constructor.
Typical keys: `bootstrap.servers`, `security.protocol`, `sasl.mechanism`.

Install: `pip install 'pramanix[kafka]'`

---

## Cryptographic Signing

### Ed25519 (`PramanixSigner`)

| Variable | Required | Description |
|---|---|---|
| `PRAMANIX_SIGNING_KEY_PEM` | Yes (or pass directly) | PEM-encoded Ed25519 private key |

Generate a key pair:

```python
from pramanix.crypto import PramanixSigner
signer = PramanixSigner.generate()
print(signer.private_key_pem().decode())   # store in secrets manager
print(signer.public_key_pem().decode())    # publish for verifiers
```

Install: `pip install 'pramanix[crypto]'`

### RS256 (`RS256Signer`)

| Variable | Required | Description |
|---|---|---|
| `PRAMANIX_RS256_SIGNING_KEY_PEM` | Yes (or pass directly) | PEM-encoded RSA-2048+ private key |

---

## Distributed State

### Redis (Circuit Breaker + Intent Cache)

| Variable | Required | Description |
|---|---|---|
| `PRAMANIX_REDIS_URL` | Yes | Redis connection URL (e.g. `redis://localhost:6379/0`) |

Used by:
- `RedisDistributedBackend` (distributed circuit breaker)
- `IntentCache` (LLM response caching)

Install: `pip install 'pramanix[redis]'`

---

## Observability

### Prometheus

| Variable | Default | Description |
|---|---|---|
| `PRAMANIX_METRICS_ENABLED` | `false` | Enable Prometheus `/metrics` endpoint |

Install: `pip install 'pramanix[metrics]'`

### OpenTelemetry

| Variable | Default | Description |
|---|---|---|
| `PRAMANIX_OTEL_ENABLED` | `false` | Enable OTel tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4317` | OTLP gRPC collector endpoint |

Install: `pip install 'pramanix[otel]'`

---

## Guard Tuning

| Variable | Default | Description |
|---|---|---|
| `PRAMANIX_ENV` | `development` | Set to `production` to block in-memory sinks |
| `PRAMANIX_LOG_LEVEL` | `INFO` | Structured log level |
| `PRAMANIX_SOLVER_TIMEOUT_MS` | `5000` | Z3 solver timeout per call (ms) |
| `PRAMANIX_MAX_WORKERS` | `4` | Worker pool size |
| `PRAMANIX_SOLVER_RLIMIT` | `10000000` | Z3 resource limit (elementary operations) |
| `PRAMANIX_MAX_INPUT_BYTES` | `65536` | Max serialised intent+state payload size |
| `PRAMANIX_MAX_INPUT_CHARS` | `512` | Max raw NL input characters |
| `PRAMANIX_INJECTION_THRESHOLD` | `0.5` | Injection detection threshold [0.0, 1.0] |
| `PRAMANIX_FAST_PATH_ENABLED` | `false` | Enable numeric fast-path pre-check |

---

## CI / Testing

For CI environments, the minimum required variables are:

```bash
# Only needed if running translator tests
ANTHROPIC_API_KEY=sk-ant-test-placeholder
OPENAI_API_KEY=sk-test-placeholder
GOOGLE_API_KEY=AIza-test-placeholder

# Only needed if running distributed circuit breaker tests
PRAMANIX_REDIS_URL=redis://localhost:6379/0
```

Most unit tests use real in-process components (Z3, real dependencies) and
do not require any API keys. Integration tests that call external LLMs will
be skipped if the API key is not set.

---

## Security Notes

1. **Never commit `.env`** — add it to `.gitignore`
2. **Use a secrets manager** in production (AWS Secrets Manager, HashiCorp Vault, Kubernetes Secrets)
3. **Rotate keys** when team members leave or keys are exposed
4. **Archive public keys** — decisions signed with old keys remain verifiable indefinitely
5. **Set `PRAMANIX_ENV=production`** to prevent accidental use of in-memory sinks
