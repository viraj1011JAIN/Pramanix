# Pramanix -- Integrations Guide

> **Version:** v1.0.0
> **Prerequisite:** Read [architecture.md](architecture.md) for the pipeline overview and [policy_authoring.md](policy_authoring.md) to write policies.

---

## Installation

```bash
# Core SDK only
pip install pramanix

# With FastAPI/Starlette integration
pip install 'pramanix[fastapi]'

# With LangChain integration
pip install 'pramanix[langchain]'

# All optional dependencies
pip install 'pramanix[all]'
```

---

## 1. FastAPI / Starlette

**Module:** `pramanix.integrations.fastapi`
**Exports:** `PramanixMiddleware`, `pramanix_route`

Two integration points are available:
- `PramanixMiddleware` -- ASGI middleware that guards every request to a route prefix
- `pramanix_route` -- per-route decorator that guards a single async handler

### 1.1 PramanixMiddleware

Intercepts every request before it reaches your route handlers. Returns 403 on BLOCK.

**Request pipeline per call:**
- Check `Content-Type: application/json` -- return 415 if absent
- Read body -- return 413 if it exceeds `max_body_bytes`
- Parse JSON body -- return 422 if invalid JSON
- Validate intent via `intent_model.model_validate(raw, strict=True)` -- return 422 if validation fails
- Load state via `await state_loader(request)` -- return 500 if it raises
- Run `decision = await guard.verify_async(intent=intent_dict, state=state)`
- If BLOCK: apply timing pad (`timing_budget_ms`), return 403 with decision JSON
- If ALLOW: forward to the next ASGI handler

```python
from fastapi import FastAPI
from pramanix.integrations.fastapi import PramanixMiddleware
from pramanix.guard import GuardConfig
from my_policies import TransferPolicy, TransferIntent

app = FastAPI()

async def load_account_state(request):
    # Load account state from your database
    account_id = request.headers["X-Account-Id"]
    return await db.get_account(account_id)

app.add_middleware(
    PramanixMiddleware,
    policy=TransferPolicy,
    intent_model=TransferIntent,
    state_loader=load_account_state,
    config=GuardConfig(execution_mode="async-thread"),
    # Security options:
    max_body_bytes=65_536,        # 64 KiB body cap (default)
    timing_budget_ms=50.0,        # pad BLOCK responses to 50 ms (H13 -- timing oracle)
)

@app.post("/transfer")
async def transfer(request: Request):
    # Guard.verify() already ran. This handler only runs on ALLOW.
    body = await request.json()
    return {"status": "transfer queued"}
```

**Security properties of PramanixMiddleware:**
- Guard instance is created once at startup, reused for all requests (no per-request policy compilation)
- `timing_budget_ms` pads BLOCK responses to prevent timing side-channels
- `max_body_bytes` prevents memory exhaustion from oversized bodies before any parsing
- Content-type enforcement rejects non-JSON bodies before parsing

---

### 1.2 pramanix_route

Per-route decorator. Creates a Guard once at decoration time. Guard is accessible on the decorated function as `fn.__guard__`.

```python
from fastapi import FastAPI, Request
from pramanix.integrations.fastapi import pramanix_route
from my_policies import TransferPolicy, TransferIntent

app = FastAPI()

@app.post("/transfer")
@pramanix_route(
    policy=TransferPolicy,
    intent_model=TransferIntent,
    state_loader=lambda req: fetch_account(req.headers["X-Account-Id"]),
)
async def transfer_handler(request: Request):
    # This handler only runs if Guard.verify() returned ALLOW
    body = await request.json()
    return {"status": "ok"}
```

**When to use middleware vs. route decorator:**
- Use `PramanixMiddleware` when the same policy applies to all routes in a prefix (e.g., all `/api/v1/transfers/*` routes)
- Use `pramanix_route` when different routes need different policies

---

## 2. LangChain

**Module:** `pramanix.integrations.langchain`
**Exports:** `PramanixGuardedTool`, `wrap_tools`
**Requires:** `langchain-core >= 0.1`

### 2.1 PramanixGuardedTool

A `BaseTool` subclass that gates every tool call through Z3 formal verification before executing.

```python
from decimal import Decimal
from langchain_core.tools import tool
from pramanix.integrations.langchain import PramanixGuardedTool
from my_policies import TransferPolicy

def execute_transfer(amount: str, recipient: str) -> str:
    # This function is the actual tool action
    return f"Transferred {amount} to {recipient}"

def get_account_state(tool_input: dict) -> dict:
    # Load current account state for policy evaluation
    return {
        "balance": Decimal("1000.00"),
        "daily_limit": Decimal("5000.00"),
        "minimum_reserve": Decimal("0.01"),
        "is_frozen": False,
        "state_version": "v1",
    }

guarded_transfer_tool = PramanixGuardedTool(
    name="transfer_funds",
    description="Transfer money between accounts",
    policy=TransferPolicy,
    state_loader=get_account_state,
    tool_fn=execute_transfer,
)

# Use in a LangChain agent
from langchain.agents import AgentExecutor
agent_executor = AgentExecutor(
    agent=your_agent,
    tools=[guarded_transfer_tool],
)
```

**What happens when an agent calls the tool:**
- Agent provides tool arguments (e.g., `{"amount": "500", "recipient": "alice"}`)
- `PramanixGuardedTool._run()` calls `Guard.verify()` with the intent and loaded state
- If ALLOW: proceeds to call `tool_fn` with the verified input
- If BLOCK: raises an exception with the violation reason -- LangChain routes this back to the agent as a tool error

### 2.2 wrap_tools

Wraps a list of existing LangChain tools with Pramanix guards.

```python
from pramanix.integrations.langchain import wrap_tools
from langchain_community.tools import some_tool, another_tool

guarded_tools = wrap_tools(
    [some_tool, another_tool],
    policy=MyPolicy,
    state_loader=get_state,
)
```

---

## 3. LlamaIndex

**Module:** `pramanix.integrations.llamaindex`
**Exports:** `PramanixGuardedQueryEngine`, `PramanixRAGGuard`

Guards RAG (Retrieval-Augmented Generation) pipelines before documents are returned to the LLM context.

```python
from pramanix.integrations.llamaindex import PramanixGuardedQueryEngine
from llama_index.core import VectorStoreIndex
from my_policies import PHIAccessPolicy

index = VectorStoreIndex.from_documents(documents)
base_engine = index.as_query_engine()

guarded_engine = PramanixGuardedQueryEngine(
    query_engine=base_engine,
    policy=PHIAccessPolicy,
    state_loader=lambda query: {
        "requestor_role": get_current_user_role(),
        "consent_active": check_consent(),
    },
)

# Use like a normal LlamaIndex query engine
response = guarded_engine.query("What is the patient's diagnosis?")
# Guard runs BEFORE the RAG retrieval happens.
# If BLOCK, query engine raises an exception -- no documents are retrieved.
```

**Why guard before retrieval, not after:**
- Guarding before retrieval means PHI documents are never fetched for unauthorized users
- Guarding after retrieval would mean PHI was already in the LLM's context window
- The policy should check the requestor's role and consent status, not the content

---

## 4. AutoGen

**Module:** `pramanix.integrations.autogen`
**Exports:** `PramanixGuardedAgent`, `PramanixToolGuard`

Wraps AutoGen agents with a formal verification layer on all tool calls.

```python
from pramanix.integrations.autogen import PramanixGuardedAgent
from autogen import AssistantAgent, UserProxyAgent
from my_policies import InfraPolicy

base_agent = AssistantAgent(
    name="infra_agent",
    llm_config={"model": "gpt-4o"},
)

guarded_agent = PramanixGuardedAgent(
    agent=base_agent,
    policy=InfraPolicy,
    state_loader=lambda: get_cluster_state(),
)

# All tool calls made by the agent go through Guard.verify() before execution
user = UserProxyAgent(name="user")
user.initiate_chat(guarded_agent, message="Scale up the web tier to 20 replicas")
```

**Multi-agent orchestration pattern:**
- Each agent has its own `Guard` instance with a policy matching its capabilities
- Agent A can call Agent B's tools -- but Agent B's Guard enforces its policy independently
- A compromised Agent A cannot make Agent B exceed its policy limits

---

## 5. Using the `@guard` Decorator

For simple function wrapping without a web framework:

```python
from decimal import Decimal
from pramanix.decorator import guard
from pramanix.guard import GuardConfig
from my_policies import TransferPolicy

@guard(
    policy=TransferPolicy,
    config=GuardConfig(execution_mode="sync"),
    state_loader=lambda intent: fetch_account_state(intent["account_id"]),
)
def execute_transfer(intent: dict) -> dict:
    # This function only runs if Guard.verify() returned ALLOW
    return transfer_service.execute(intent)

# Usage:
result = execute_transfer({"amount": Decimal("100"), "account_id": "acc-123"})
# If BLOCK, raises GuardViolationError with the violation reason
```

---

## 6. Async Usage Pattern

For async applications (FastAPI, async worker, etc.):

```python
from pramanix.guard import Guard, GuardConfig
from my_policies import TransferPolicy

guard = Guard(TransferPolicy, GuardConfig(execution_mode="async-thread"))

async def handle_transfer(intent: dict, state: dict):
    decision = await guard.verify_async(intent=intent, state=state)
    if decision.allowed:
        return await execute(intent)
    else:
        raise PolicyViolation(decision.explanation)
```

- `verify_async()` dispatches to the worker pool without blocking the event loop
- Use `execution_mode="async-thread"` for most web workloads
- Use `execution_mode="async-process"` for high-security environments requiring subprocess isolation

---

## 7. CrewAI

```python
from pramanix.integrations.crewai import PramanixCrewAITool

guard_tool = PramanixCrewAITool(guard=guard)
# Pass to a CrewAI Agent's tools list:
agent = Agent(role="Analyst", tools=[guard_tool])
```

`PramanixCrewAITool` wraps `Guard.verify()` as a CrewAI `BaseTool`. The tool's `_run(intent_json)` method deserializes the JSON intent, calls `verify()`, and returns the `Decision` result. Install with `pip install 'pramanix[crewai]'`.

## 8. DSPy

```python
from pramanix.integrations.dspy import PramanixDSPyModule

guard_module = PramanixDSPyModule(guard=guard)
# Use in a DSPy program:
result = guard_module(intent={"amount": Decimal("100")}, state=account_state)
```

`PramanixDSPyModule` subclasses `dspy.Module`. Install with `pip install 'pramanix[dspy]'`.

## 9. PydanticAI

```python
from pramanix.integrations.pydantic_ai import PramanixPydanticAIGuard

guard_wrapper = PramanixPydanticAIGuard(guard=guard)
decision = guard_wrapper.verify(intent={"amount": Decimal("100")}, state=account_state)
```

`PramanixPydanticAIGuard` adapts the guard for PydanticAI pipelines. Install with `pip install 'pramanix[pydantic-ai]'`.

## 10. Haystack

```python
from pramanix.integrations.haystack import PramanixHaystackComponent

component = PramanixHaystackComponent(guard=guard)
pipeline.add_component("guard", component)
```

`PramanixHaystackComponent` implements the Haystack `Component` protocol. The `run()` method accepts `intent` and `state` keyword arguments and outputs a `Decision`. Install with `pip install 'pramanix[haystack]'`.

## 11. Microsoft Semantic Kernel

```python
from pramanix.integrations.semantic_kernel import PramanixSemanticKernelPlugin

plugin = PramanixSemanticKernelPlugin(guard=guard)
kernel.add_plugin(plugin, plugin_name="PramanixGuard")
```

The plugin exposes `verify_intent` as a `@kernel_function`. Install with `pip install 'pramanix[semantic_kernel]'`.

## 12. gRPC Server Interceptor

```python
from pramanix.interceptors.grpc import PramanixGrpcInterceptor

interceptor = PramanixGrpcInterceptor(
    guard=guard,
    policy_fn=lambda context: {"amount": Decimal(context.invocation_metadata["amount"])},
)
server = grpc.server(
    futures.ThreadPoolExecutor(max_workers=10),
    interceptors=[interceptor],
)
```

Requests that fail `Guard.verify()` are aborted with `grpc.StatusCode.PERMISSION_DENIED` before the handler runs. Install with `pip install 'pramanix[grpc]'`.

## 13. Kafka Consumer Guard

```python
from pramanix.interceptors.kafka import PramanixKafkaGuard

kafka_guard = PramanixKafkaGuard(
    guard=guard,
    intent_extractor=lambda msg: json.loads(msg.value()),
)
# Wraps the confluent-kafka Consumer:
for message in kafka_guard.consume(consumer, topics=["transfers"]):
    process(message)  # only reaches here if Guard.verify() returns ALLOW
```

Messages that fail verification are not forwarded to `process()` — they are logged and the offset is committed. Install with `pip install 'pramanix[kafka]'`.

## 14. Kubernetes Admission Webhook

```python
# app.py — mount as a MutatingWebhookConfiguration endpoint
from pramanix.k8s import AdmissionWebhook

app = AdmissionWebhook(guard=guard, policy=ResourcePolicy).app
```

The webhook validates Pod and Deployment resource specs against the guard before they enter the cluster. See `deploy/k8s/webhook/` for the full `MutatingWebhookConfiguration` manifest and TLS bootstrapping guide. Install with `pip install 'pramanix[k8s]'`.

---

## 15. Integration Compatibility

| Framework | Version Tested | Extra | Status |
| --------- | -------------- | ----- | ------ |
| FastAPI | 0.100+ | `fastapi` | Stable |
| Starlette | 0.27+ | `fastapi` | Stable (FastAPI uses Starlette) |
| LangChain | langchain-core 0.1+ | `langchain` | Stable |
| LlamaIndex | llama-index-core 0.10+ | `llamaindex` | Stable |
| AutoGen | 0.2+ | `autogen` | Stable |
| CrewAI | 0.80+ | `crewai` | Stable |
| DSPy | 2.4+ | `dspy` | Stable |
| PydanticAI | 0.0.13+ | `pydantic-ai` | Stable |
| Haystack | haystack-ai 2.0+ | `haystack` | Stable |
| Semantic Kernel | 1.0+ | `semantic_kernel` | Stable |
| gRPC | grpcio 1.60+ | `grpc` | Stable |
| Kafka | confluent-kafka 2.3+ | `kafka` | Stable |
| Kubernetes (webhook) | FastAPI 0.100+ | `k8s` | Stable |

**Installation extras:**

```bash
pip install 'pramanix[fastapi]'          # includes starlette
pip install 'pramanix[langchain]'        # includes langchain-core
pip install 'pramanix[crewai]'           # CrewAI multi-agent
pip install 'pramanix[dspy]'             # DSPy pipeline
pip install 'pramanix[haystack]'         # Haystack pipeline
pip install 'pramanix[semantic_kernel]'  # Microsoft Semantic Kernel
pip install 'pramanix[grpc]'             # gRPC server interceptor
pip install 'pramanix[kafka]'            # Kafka consumer guard
pip install 'pramanix[k8s]'              # Kubernetes admission webhook
pip install 'pramanix[all]'              # all integrations
```
