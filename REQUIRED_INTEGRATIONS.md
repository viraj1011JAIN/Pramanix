# Required Integrations for Full Real-Backend Testing

All infrastructure in this list is consumed by the automated test suite.
Tests that require a live backend are guarded by `@requires_docker` (unit
tests) or `@pytest.mark.integration` (integration tests).  Without the
prerequisites below the guarded tests are **skipped**, not failed.

---

## Auto-provisioned via Testcontainers (Docker required)

The following services are started automatically when Docker is running.
No credentials or environment variables are needed.

| Service | Image | Scope | Used by |
|---------|-------|-------|---------|
| Redis 7 | `redis:7-alpine` | session | all unit + integration tests touching Redis |
| PostgreSQL 16 | `postgres:16-alpine` | session | `tests/integration/test_postgres_token.py` |
| Apache Kafka | `confluentinc/cp-kafka:7.6.1` | session | `tests/integration/test_kafka_*.py` |
| HashiCorp Vault | `hashicorp/vault:1.16` (dev mode) | session | `tests/integration/test_vault_*.py` |
| LocalStack | `localstack/localstack:latest` | session | `tests/integration/test_aws_*.py` |

---

## Cloud credentials (optional — tests skipped when absent)

### AWS / AWS KMS / Secrets Manager
```
AWS_ACCESS_KEY_ID=<your key>
AWS_SECRET_ACCESS_KEY=<your secret>
AWS_DEFAULT_REGION=us-east-1
# For AwsKmsKeyProvider integration tests:
PRAMANIX_TEST_AWS_SECRET_ARN=arn:aws:secretsmanager:us-east-1:<acct>:secret:<name>
```
Python package required: `boto3` — `pip install 'pramanix[aws]'`

### Azure Key Vault
```
AZURE_VAULT_URL=https://<vault-name>.vault.azure.net
AZURE_CLIENT_ID=<service-principal app-id>
AZURE_TENANT_ID=<tenant-id>
AZURE_CLIENT_SECRET=<service-principal secret>
# For AzureKeyVaultKeyProvider integration tests:
PRAMANIX_TEST_AZURE_SECRET_NAME=<secret-name-in-vault>
```
Python packages required: `azure-keyvault-secrets azure-identity` — `pip install 'pramanix[azure]'`

### GCP Secret Manager
```
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
GOOGLE_CLOUD_PROJECT=<gcp-project-id>
# For GcpKmsKeyProvider integration tests:
PRAMANIX_TEST_GCP_SECRET_ID=<secret-id>
```
Python package required: `google-cloud-secret-manager` — `pip install 'pramanix[gcp]'`

### HashiCorp Vault (production, not dev-mode)
```
VAULT_ADDR=https://vault.example.com:8200
VAULT_TOKEN=<root-or-app-token>
PRAMANIX_TEST_VAULT_SECRET_PATH=pramanix/key
```
Python package required: `hvac` — `pip install 'pramanix[vault]'`

---

## AI/LLM Translator credentials (optional — tests skipped when absent)

### Google Gemini
```
GOOGLE_API_KEY=<gemini-api-key>
# or equivalently:
GEMINI_API_KEY=<gemini-api-key>
```
Python package required: `google-generativeai` — `pip install 'pramanix[gemini]'`

### Anthropic Claude
```
ANTHROPIC_API_KEY=sk-ant-...
```
Python package required: `anthropic` — `pip install 'pramanix[anthropic]'`

### OpenAI
```
OPENAI_API_KEY=sk-...
```
Python package required: `openai` — `pip install 'pramanix[openai]'`

### Cohere
```
COHERE_API_KEY=<key>
```
Python package required: `cohere` — `pip install 'pramanix[cohere]'`

### Mistral
```
MISTRAL_API_KEY=<key>
```
Python package required: `mistralai` — `pip install 'pramanix[mistral]'`

---

## Framework integration credentials (optional)

### Datadog (audit sink)
```
DD_API_KEY=<datadog-api-key>
DD_SITE=datadoghq.com   # or eu1, etc.
```

### Prometheus (metrics)
No credentials needed — Prometheus scrapes the `/metrics` endpoint.
Set `metrics_enabled=True` in `GuardConfig` to expose metrics.

---

## Quick start (local Docker)

```bash
# Install all optional deps for full test coverage
pip install 'pramanix[all]'

# Run unit tests (Docker required for Redis-backed tests)
pytest tests/unit/

# Run integration tests (Docker required for all)
pytest tests/integration/

# Run only tests that don't require Docker
pytest tests/unit/ -m "not docker"
```

---

## CI / CD environment variables summary

```bash
# Minimum for unit tests with Docker
# (no cloud credentials needed — testcontainers handle Redis/Postgres/Kafka/Vault)

# Full CI with all cloud integrations:
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_DEFAULT_REGION
PRAMANIX_TEST_AWS_SECRET_ARN
AZURE_VAULT_URL
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_CLIENT_SECRET
PRAMANIX_TEST_AZURE_SECRET_NAME
GOOGLE_APPLICATION_CREDENTIALS
GOOGLE_CLOUD_PROJECT
PRAMANIX_TEST_GCP_SECRET_ID
VAULT_ADDR
VAULT_TOKEN
PRAMANIX_TEST_VAULT_SECRET_PATH
GOOGLE_API_KEY
ANTHROPIC_API_KEY
OPENAI_API_KEY
COHERE_API_KEY
MISTRAL_API_KEY
DD_API_KEY
DD_SITE
```
