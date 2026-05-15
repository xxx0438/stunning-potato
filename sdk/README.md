# echo-sdk

> Official Python SDK + CLI for [Echo Agent Governance](https://github.com/xxx0438/e-cho).

[![PyPI](https://img.shields.io/pypi/v/echo-sdk.svg)](https://pypi.org/project/echo-sdk/)
[![Python](https://img.shields.io/pypi/pyversions/echo-sdk.svg)](https://pypi.org/project/echo-sdk/)

## Install

```bash
pip install echo-sdk
```

## Quick start

```python
from echo_sdk import EchoClient

client = EchoClient(
    base_url="https://echo.example.com",
    token="eyJ...",            # JWT, or set ECHO_TOKEN
    tenant_id="tenant-a",       # or ECHO_TENANT_ID
)

# Check identity
print(client.whoami())

# CI gate
result = client.gate.check(commit_sha="abc123", is_ai_related=True)
if result.is_blocked:
    raise SystemExit(f"Gate blocked: {result.reasons}")

# Pre-flight guardrail before invoking an agent tool
decision = client.runtime.guardrail_check(
    asset_name="loan_agent",
    tool_name="transfer",
    tool_args={"amount": 1500, "currency": "EUR"},
    input_variables={"user_message": "Please transfer the money"},
)
if decision.is_blocked:
    raise PermissionError("Policy violation: " + decision.findings[0].reason)
```

## Configuration

| Env var | Purpose |
|---|---|
| `ECHO_BASE_URL` | API base URL (default `http://localhost:8000`) |
| `ECHO_TOKEN` | JWT Bearer token |
| `ECHO_TENANT_ID` | Tenant identifier |
| `ECHO_ACTOR` | Demo-mode actor (when no token set) |
| `ECHO_ROLES` | Demo-mode roles, comma-separated |

## CLI

After `pip install echo-sdk`, the `echo` command is available:

```bash
# Health
echo health

# Identity
echo whoami

# CI gate (returns exit 1 on block — perfect for CI pipelines)
echo gate check --commit "$CI_COMMIT_SHA" --ai-related

# Strict mode: also fail on 'warn'
echo gate check --commit "$CI_COMMIT_SHA" --ai-related --strict

# Runtime guardrail
echo guardrail check \
    --asset loan_agent \
    --tool transfer \
    --args '{"amount": 9999}' \
    --who "$USER"

# Asset registry
echo asset list --type workflows
echo asset get 42

# Register a change
echo change create --commit "$CI_COMMIT_SHA" \
    --asset-id 1 --risk high --review-required \
    --notes "Tightened amount limit"

# Run an evaluation suite (exit 1 if it fails)
echo eval run --suite 1 --version 42 \
    --mock-outputs '{"case_a": "Approved with eligibility"}'

# Webhook testing
echo webhook test --id 5 --event echo.test

# Audit hash chain integrity (exit 1 if broken)
echo audit verify
```

## GitLab CI example

```yaml
echo-gate:
  stage: governance
  image: python:3.12-slim
  variables:
    ECHO_BASE_URL: https://echo.example.com
    ECHO_TENANT_ID: tenant-a
  before_script:
    - pip install echo-sdk
  script:
    - echo gate check --commit "$CI_COMMIT_SHA" --ai-related --strict
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

## GitHub Actions example

```yaml
- uses: actions/setup-python@v5
  with: { python-version: "3.12" }
- run: pip install echo-sdk
- run: echo gate check --commit "${{ github.sha }}" --ai-related
  env:
    ECHO_BASE_URL: ${{ secrets.ECHO_BASE_URL }}
    ECHO_TOKEN: ${{ secrets.ECHO_TOKEN }}
    ECHO_TENANT_ID: ${{ vars.ECHO_TENANT_ID }}
```

## Async usage

```python
import asyncio
from echo_sdk import AsyncEchoClient

async def main():
    async with AsyncEchoClient(token="eyJ...") as client:
        result = await client.gate_check(commit_sha="abc", is_ai_related=True)
        print(result.status, result.reasons)

asyncio.run(main())
```

## Verifying webhooks

```python
from fastapi import FastAPI, Request, HTTPException
from echo_sdk import verify_webhook

app = FastAPI()
SECRET = "your-shared-secret"

@app.post("/echo-webhook")
async def receive(request: Request):
    body = await request.body()
    if not verify_webhook(SECRET, body, request.headers):
        raise HTTPException(401, "Invalid signature")
    event = await request.json()
    print(f"Echo event: {event['event']}")
    return {"ok": True}
```

## Error handling

```python
from echo_sdk.exceptions import (
    AuthenticationError,    # 401
    PermissionDeniedError,  # 403
    NotFoundError,          # 404
    ValidationError,        # 400/422
    RateLimitError,         # 429 (has .retry_after)
    EchoAPIError,           # other non-2xx
    EchoError,              # network / SDK errors
)
```

Built-in exponential backoff retries 429/5xx by default; customize via
`RetryPolicy(max_attempts=5, initial_delay=1.0, backoff=2.0, max_delay=60)`.

## Development

```bash
git clone https://github.com/xxx0438/e-cho.git
cd e-cho/sdk
pip install -e ".[dev]"
pytest -v
ruff check .
mypy echo_sdk/
```

## License

MIT
