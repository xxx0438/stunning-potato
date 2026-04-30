# Echo Prompt Manager — User Guide

> **The ultimate CMS for LLM Prompts. Decouple your prompts from your codebase.**

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Prerequisites](#3-prerequisites)
4. [Installation & Setup](#4-installation--setup)
   - [4.1 Backend Server](#41-backend-server)
   - [4.2 Dashboard (Web UI)](#42-dashboard-web-ui)
   - [4.3 Python SDK](#43-python-sdk)
5. [Core Concepts](#5-core-concepts)
   - [5.1 Assets](#51-assets)
   - [5.2 Asset Versions](#52-asset-versions)
   - [5.3 Execution Logs](#53-execution-logs)
   - [5.4 Change Requests](#54-change-requests)
6. [Dashboard Walkthrough](#6-dashboard-walkthrough)
   - [6.1 Connecting to the API](#61-connecting-to-the-api)
   - [6.2 Creating an Asset](#62-creating-an-asset)
   - [6.3 Publishing a Version](#63-publishing-a-version)
   - [6.4 Activating a Version](#64-activating-a-version)
   - [6.5 Viewing Execution Logs](#65-viewing-execution-logs)
   - [6.6 CI Gate Panel](#66-ci-gate-panel)
7. [Python SDK Reference](#7-python-sdk-reference)
   - [7.1 Initialization](#71-initialization)
   - [7.2 `get_active_prompt`](#72-get_active_prompt)
   - [7.3 `log_execution`](#73-log_execution)
   - [7.4 `create_asset`](#74-create_asset)
   - [7.5 `check_ci_gate`](#75-check_ci_gate)
8. [REST API Reference](#8-rest-api-reference)
   - [8.1 Asset APIs](#81-asset-apis)
   - [8.2 Version APIs](#82-version-apis)
   - [8.3 Runtime Service API](#83-runtime-service-api)
   - [8.4 Execution Log APIs](#84-execution-log-apis)
   - [8.5 Change Request APIs](#85-change-request-apis)
   - [8.6 CI Gate API](#86-ci-gate-api)
9. [End-to-End Integration Example](#9-end-to-end-integration-example)
10. [CI/CD Integration](#10-cicd-integration)
    - [10.1 GitHub Actions](#101-github-actions)
11. [Troubleshooting](#11-troubleshooting)
12. [FAQ](#12-faq)

---

## 1. Overview

Echo Prompt Manager is an enterprise-grade **Content Management System (CMS) for LLM Prompts**. It solves a core pain point in AI product development: prompts embedded in code are hard to iterate on, impossible for non-engineers to manage, and invisible to compliance teams.

Echo gives you:

| Capability | Description |
|---|---|
| **No-Code Dashboard** | Create, edit, and version-control prompts, context packs, skills, and workflows via a visual web UI |
| **Instant Deployment** | Swap the live prompt in production with zero code redeployment |
| **Python SDK** | Two-line integration to fetch the active prompt at runtime |
| **Data Flywheel** | Execution logs automatically trace every LLM call (inputs, outputs, latency, token usage) back to the exact prompt version that produced it |
| **CI Gate** | Block or warn on risky prompt changes in your GitHub Actions or GitLab CI pipeline |

---

## 2. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Your AI Application                     │
│                                                             │
│   from echo_sdk import EchoPromptClient                     │
│   client = EchoPromptClient(base_url="https://your-host")   │
│   config = client.get_active_prompt("my_asset")  ◄──────┐  │
│   client.log_execution(...)                       ──────►│  │
└───────────────────────────────────────────────────────────│─┘
                                                            │
              HTTP (REST JSON API)                          │
                                                            │
┌───────────────────────────────────────────────────────────▼─┐
│                   Echo Backend  (FastAPI)                    │
│                                                             │
│   /api/assets/          Asset CRUD                          │
│   /api/assets/.../versions/   Version management           │
│   /api/services/assets/{name}/active   ◄── Runtime fetch   │
│   /api/logs/            Execution log write/read            │
│   /api/changes/         Change request tracking             │
│   /api/ci/gate/check    CI compliance gate                  │
│                                                             │
│   SQLite (echo_prompt_manager.db)  — swappable to Postgres  │
└─────────────────────────────────────────────────────────────┘
              ▲
              │  opens
┌─────────────┴───────────────────┐
│   Dashboard (index.html)        │
│   Static single-page HTML/JS    │
│   No build step required        │
└─────────────────────────────────┘
```

---

## 3. Prerequisites

| Requirement | Minimum Version |
|---|---|
| Python | 3.7+ |
| pip | 21+ |

The FastAPI backend has the following Python dependencies:

```
fastapi
uvicorn[standard]
sqlalchemy
pydantic
```

The Python SDK depends on `requests`, but installing the SDK package will pull that in automatically.

No external database, message queue, or cloud service is required to get started — Echo uses SQLite by default.

---

## 4. Installation & Setup

### 4.1 Backend Server

**Step 1 — Clone the repository**

```bash
git clone https://github.com/PeterShanxin/stunning-potato.git
cd stunning-potato
```

**Step 2 — Install dependencies**

```bash
pip install fastapi "uvicorn[standard]" sqlalchemy pydantic
```

**Step 3 — Start the server**

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

The API will be live at `http://localhost:8000`.  
Interactive API docs are auto-generated at `http://localhost:8000/docs`.

> **Production tip:** Remove `--reload` in production and run behind a process manager such as `gunicorn` with `uvicorn` workers, or wrap in a systemd service.

### 4.2 Dashboard (Web UI)

The dashboard is a **static single HTML file** — no build step, no Node.js, no deployment needed.

Open `index.html` directly in any modern browser:

```bash
open index.html          # macOS
xdg-open index.html      # Linux
start index.html         # Windows
```

Or serve it through any static file server alongside the API.

### 4.3 Python SDK

Install the official SDK directly from GitHub:

```bash
pip install 'git+https://github.com/PeterShanxin/stunning-potato.git#subdirectory=echo_sdk_package'
```

Verify the installation:

```python
from echo_sdk import EchoPromptClient
print("Echo SDK installed successfully")
```

---

## 5. Core Concepts

### 5.1 Assets

An **Asset** is the top-level resource in Echo. It represents a named, reusable AI configuration that your application will fetch at runtime.

| Field | Description |
|---|---|
| `name` | Unique identifier used in SDK calls (e.g. `"customer_service_vqa"`) |
| `asset_type` | One of `prompt`, `context_pack`, `skill`, `workflow` |
| `owner` | Team or individual responsible for this asset |
| `description` | Human-readable summary |
| `tags` | Free-form list of labels for filtering (e.g. `["production", "v2"]`) |

### 5.2 Asset Versions

Every change to an asset creates a new **Version**. Versions are immutable once created, providing a complete audit trail.

| Field | Description |
|---|---|
| `version_tag` | Human-readable label (e.g. `"v1.0"`, `"2024-06-hotfix"`) |
| `status` | `draft` → `approved` → **`active`** → `deprecated` |
| `system_prompt` | The main system-level instruction sent to the LLM |
| `context_template` | Optional template for injecting dynamic context |
| `examples` | Few-shot examples (JSON array) |
| `guardrails` | Safety/compliance rules (JSON array) |
| `variables_schema` | Schema describing expected input variables |
| `change_summary` | Human-readable description of what changed |
| `created_by` | Author identifier |

Only **one version per asset** can be `active` at a time. Activating a new version automatically sets all other versions for that asset to `approved`, then marks the selected version as `active`.

### 5.3 Execution Logs

Every time your application calls the LLM using an Echo-managed prompt, you should log the result back to Echo. This creates a **Data Flywheel**:

- Trace every LLM response back to the exact prompt version that produced it
- Monitor latency and token usage over time
- Replay or audit any past interaction

### 5.4 Change Requests

A **Change Request** links a git commit SHA to a specific asset or asset version. This is the foundation for the CI Gate — it lets Echo answer the question: *"Does this commit have a reviewed and approved prompt change behind it?"*

---

## 6. Dashboard Walkthrough

### 6.1 Connecting to the API

When you open the dashboard, the top bar shows the **API Base URL** field (default: `http://127.0.0.1:8000`).

1. Enter the URL of your running Echo backend.
2. Click **Test** (or the connection button) to verify connectivity.
3. The status indicator turns **green** when the API is reachable.

### 6.2 Creating an Asset

1. Navigate to the **Assets** panel.
2. Fill in:
   - **Name** — must be unique; this is what your application uses in `get_active_prompt("name")`
   - **Type** — `prompt`, `context_pack`, `skill`, or `workflow`
   - **Owner** — your team or username
   - **Description** *(optional)*
   - **Tags** *(optional, comma-separated)*
3. Click **Create Asset**.

The new asset appears in the asset list immediately.

### 6.3 Publishing a Version

1. Select an asset from the asset list.
2. In the **Versions** panel, click **New Version**.
3. Fill in:
   - **Version Tag** — e.g. `v1.0`, `2024-07-experiment`
   - **System Prompt** — the core instruction for the LLM
   - **Context Template** *(optional)* — use `{{variable_name}}` placeholders
   - **Examples** *(optional)* — few-shot examples as JSON
   - **Guardrails** *(optional)* — compliance rules as JSON
   - **Change Summary** — what changed and why
   - **Set Active** — check this to immediately activate the version
4. Click **Save Version**.

### 6.4 Activating a Version

To promote an existing version to `active` (e.g. after a review):

1. Find the version in the version list.
2. Click **Activate**. The selected version becomes `active`, and all other versions for that asset are set to `approved`.

Your running applications will serve the new prompt on their **next** call to `get_active_prompt()` — no restart required.

### 6.5 Viewing Execution Logs

The **Execution Logs** panel shows all logged LLM calls. Each row includes:

- Version ID that was used
- Model name (e.g. `gpt-4o`)
- Input variables sent to the LLM
- LLM output
- Latency (ms)
- Token usage
- Timestamp

Use this panel to debug unexpected outputs, compare performance across versions, and spot regressions after a prompt change.

### 6.6 CI Gate Panel

The **CI Gate** panel lets you manually test whether a commit SHA would pass or fail the compliance gate. Enter a commit SHA, flag whether it is AI-related, and click **Check** to see the result: `pass`, `warn`, or `block`.

---

## 7. Python SDK Reference

### 7.1 Initialization

```python
from echo_sdk import EchoPromptClient

client = EchoPromptClient(base_url="http://localhost:8000")
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `base_url` | `str` | `"http://127.0.0.1:8000"` | Base URL of your Echo backend |

### 7.2 `get_active_prompt`

Fetch the currently active configuration for a named asset. Call this **before every LLM invocation** so your application always uses the latest approved prompt.

```python
config = client.get_active_prompt(asset_name="customer_service_vqa")

system_prompt    = config["system_prompt"]
context_template = config["context_template"]
examples         = config["examples"]        # list
guardrails       = config["guardrails"]      # list
version_id       = config["version_id"]      # int — needed for log_execution
version_tag      = config["version_tag"]
```

**Returns** a dict with keys: `asset_name`, `asset_type`, `version_id`, `version_tag`, `system_prompt`, `context_template`, `workflow_spec`, `examples`, `guardrails`, `variables_schema`, `change_summary`.

**Raises** `Exception` if the asset does not exist or has no active version.

### 7.3 `log_execution`

Record the result of an LLM call. Call this **after every LLM invocation** to feed the Data Flywheel.

```python
client.log_execution(
    asset_version_id=version_id,     # from get_active_prompt
    model_name="gpt-4o",
    input_variables={"user_input": user_message},
    llm_output=response_text,
    latency_ms=342,
    token_usage=87,
    request_id="req-abc-123",        # optional; must be globally unique
)
```

| Parameter | Type | Required | Description |
|---|---|---|---|
| `asset_version_id` | `int` | ✅ | Version that produced this response |
| `model_name` | `str` | ✅ | Model identifier (e.g. `"gpt-4o"`) |
| `llm_output` | `str` | ✅ | Raw LLM response text |
| `input_variables` | `dict` | | Variables injected into the prompt |
| `latency_ms` | `int` | | End-to-end latency in milliseconds |
| `token_usage` | `int` | | Total tokens consumed |
| `request_id` | `str` | | Idempotency key; duplicates are rejected |

### 7.4 `create_asset`

Programmatically create a new asset (useful for scripts or CI pipelines):

```python
asset = client.create_asset(
    name="onboarding_guide",
    asset_type="prompt",
    owner="ai-team",
    description="Guides new users through setup",
    tags=["onboarding", "production"],
)
print(asset["id"])  # the new asset ID
```

### 7.5 `check_ci_gate`

Check whether a commit passes the CI compliance gate:

```python
result = client.check_ci_gate(
    commit_sha="abc1234",
    is_ai_related=True,
)
# result["status"] is "pass", "warn", or "block"
# reviewed changes return result["reasons"]; fast-path responses may return result["reason"]
if result["status"] == "block":
    reasons = result.get("reasons") or [result.get("reason", "Unknown CI gate result")]
    reason_text = "; ".join(reasons)
    raise SystemExit(f"CI Gate blocked: {reason_text}")
```

---

## 8. REST API Reference

All endpoints return JSON. Error responses include a `"detail"` field with a human-readable message.

Base URL: `http://localhost:8000`  
Interactive docs: `http://localhost:8000/docs`

### 8.1 Asset APIs

#### `POST /api/assets/` — Create asset

```jsonc
// Request body
{
  "name": "my_asset",
  "asset_type": "prompt",
  "owner": "ai-team",
  "description": "Optional description",
  "tags": ["tag1", "tag2"]
}
```

Returns the created asset object.

#### `GET /api/assets/` — List assets

Query parameters:

| Param | Type | Description |
|---|---|---|
| `q` | string | Search by name, description, or owner |
| `asset_type` | string | Filter by type |
| `owner` | string | Filter by owner |
| `tag` | string | Filter by a single tag |

#### `GET /api/assets/{asset_id}` — Get asset with versions

Returns the asset object plus a `"versions"` array of all its versions.

#### `PATCH /api/assets/{asset_id}` — Update asset metadata

```json
{
  "description": "Updated description",
  "owner": "new-team",
  "tags": ["new-tag"]
}
```

All fields are optional. Only provided fields are updated.

### 8.2 Version APIs

#### `POST /api/assets/{asset_id}/versions/` — Create version

```json
{
  "version_tag": "v2.0",
  "system_prompt": "You are a helpful assistant...",
  "context_template": "User context: {{user_profile}}",
  "examples": [],
  "guardrails": [],
  "variables_schema": {},
  "change_summary": "Improved tone",
  "created_by": "alice",
  "set_active": true
}
```

If `set_active` is `true`, all other versions of this asset are moved to `approved` and the new version is set to `active`.

#### `GET /api/assets/{asset_id}/versions/` — List versions

Returns all versions for the asset, newest first.

#### `POST /api/assets/{asset_id}/versions/{version_id}/activate` — Activate version

Promotes the specified version to `active` and demotes all others to `approved`. No request body needed.

### 8.3 Runtime Service API

#### `GET /api/services/assets/{name}/active` — Get active prompt

The **primary runtime endpoint** called by the SDK. Returns the full active configuration for the named asset.

```
GET /api/services/assets/customer_service_vqa/active
```

```json
{
  "asset_name": "customer_service_vqa",
  "asset_type": "prompt",
  "version_id": 5,
  "version_tag": "v3.1",
  "system_prompt": "You are an expert customer service agent...",
  "context_template": "",
  "workflow_spec": {},
  "examples": [],
  "guardrails": [],
  "variables_schema": {},
  "change_summary": "Tone improvement"
}
```

Returns `404` if the asset does not exist or has no active version.

### 8.4 Execution Log APIs

#### `POST /api/logs/` — Record execution

```json
{
  "asset_version_id": 5,
  "model_name": "gpt-4o",
  "input_variables": { "user_input": "How do I reset my password?" },
  "llm_output": "To reset your password, visit...",
  "latency_ms": 342,
  "token_usage": 87,
  "request_id": "req-abc-123"
}
```

`request_id` is optional but recommended for idempotency. Returns `{"status": "success", "log_id": <int>}`.

#### `GET /api/logs/` — List logs

| Param | Type | Description |
|---|---|---|
| `asset_version_id` | int | Filter by version |
| `request_id` | string | Filter by request ID |
| `limit` | int | Max results (1–500, default 50) |

### 8.5 Change Request APIs

#### `POST /api/changes/` — Create change request

```json
{
  "commit_sha": "abc1234def5678",
  "pr_id": "PR-42",
  "asset_version_id": 5,
  "risk_level": "high",
  "impact_scope": ["customer_service", "billing"],
  "review_required": true,
  "review_status": "approved",
  "notes": "Updated tone per PM feedback",
  "created_by": "alice"
}
```

| `risk_level` | Values | CI Gate behavior |
|---|---|---|
| `low` | | Always passes |
| `medium` | | Warns if `review_required` and not approved |
| `high` | | Blocks if `review_required` is false, or if not approved |

#### `GET /api/changes/{commit_sha}` — Get change request

Returns the change request linked to the given commit SHA.

#### `GET /api/changes/` — List change requests

| Param | Type | Description |
|---|---|---|
| `risk_level` | string | Filter by risk level |
| `review_status` | string | Filter by review status |
| `limit` | int | Max results (1–500, default 100) |

### 8.6 CI Gate API

#### `POST /api/ci/gate/check` — Gate check

```json
{
  "commit_sha": "abc1234def5678",
  "is_ai_related": true
}
```

Response:

```jsonc
{
  "status": "pass",     // "pass" | "warn" | "block"
  "commit_sha": "abc1234def5678",
  "change_request": null,
  "reasons": ["All checks passed"]
}
```

When the commit is linked to a Change Request, the backend returns `change_request` and `reasons` as shown above. For the current fast-path cases with no linked Change Request, the backend returns a single `reason` string instead.

Gate logic:

- **AI-related commit with no linked change request** → `block`
- **High risk, `review_required: false`** → `block`
- **High risk, not yet approved** → `block`
- **Medium risk, pending review** → `warn`
- **Otherwise** → `pass`

---

## 9. End-to-End Integration Example

The following example shows the complete integration lifecycle:

```python
import time
from echo_sdk import EchoPromptClient

# 1. Initialize the client (typically once at app startup)
client = EchoPromptClient(base_url="http://localhost:8000")

def call_llm_with_echo(user_message: str) -> str:
    # 2. Fetch the latest active prompt — no hardcoded strings
    config = client.get_active_prompt(asset_name="customer_service_vqa")
    system_prompt = config["system_prompt"]
    version_id    = config["version_id"]

    # 3. Call your LLM of choice using the fetched prompt
    start = time.time()
    # --- replace with your actual LLM call ---
    llm_response = f"Echo: response to '{user_message}'"
    latency_ms = int((time.time() - start) * 1000)
    # -----------------------------------------

    # 4. Log the execution back to Echo
    client.log_execution(
        asset_version_id=version_id,
        model_name="gpt-4o",
        input_variables={"user_input": user_message},
        llm_output=llm_response,
        latency_ms=latency_ms,
        token_usage=60,
    )

    return llm_response

if __name__ == "__main__":
    print(call_llm_with_echo("How do I cancel my subscription?"))
```

When a product manager or prompt engineer updates the prompt in the Echo dashboard and activates a new version, the **next call** to `get_active_prompt` in your running application will return the updated configuration — with no code changes and no redeployment.

---

## 10. CI/CD Integration

### 10.1 GitHub Actions

Add a step to your workflow that calls the CI Gate before merging any AI-related changes:

```yaml
# .github/workflows/echo-ci-gate.yml
name: Echo CI Gate

on:
  pull_request:
    branches: [main]

jobs:
  echo-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Echo SDK
        run: pip install 'git+https://github.com/PeterShanxin/stunning-potato.git#subdirectory=echo_sdk_package'

      - name: Run CI Gate check
        env:
          ECHO_BASE_URL: ${{ secrets.ECHO_BASE_URL }}
          COMMIT_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          python - <<'EOF'
          import os, sys
          from echo_sdk import EchoPromptClient

          client = EchoPromptClient(base_url=os.environ["ECHO_BASE_URL"])
          result = client.check_ci_gate(
              commit_sha=os.environ["COMMIT_SHA"],
              is_ai_related=True,
          )
          reasons = result.get("reasons") or [result.get("reason", "Unknown CI gate result")]
          print(f"Gate status: {result['status']} — {'; '.join(reasons)}")
          if result["status"] == "block":
              sys.exit(1)
          EOF
```

**Setup steps:**

1. Add `ECHO_BASE_URL` as a GitHub Actions secret (e.g. `https://echo.yourcompany.com`).
2. Before merging a PR that changes a prompt, create a Change Request via the API (see [§8.5](#85-change-request-apis)), linking the PR commit SHA to the asset version and providing the review status.
3. The gate step will `pass` or `warn` for low/medium risk approved changes and `block` for unapproved high-risk changes, preventing the merge.

---

## 11. Troubleshooting

### `Connection refused` when opening the dashboard

- Confirm the backend is running: `uvicorn main:app --host 0.0.0.0 --port 8000`
- Check that the API Base URL in the dashboard matches the host and port of your backend.
- If running the backend on a remote server, ensure the port is accessible (firewall rules, security groups).

### `404 Asset not found` from `get_active_prompt`

- Verify the asset `name` is spelled exactly as entered in the dashboard (case-sensitive).
- Confirm the asset has at least one version with status `active`. Draft or approved versions are not served by the runtime endpoint.

### `404 No active version found`

- Open the dashboard, select the asset, and click **Activate** on the version you want to serve.

### SDK install fails

- Ensure `git` is available in your environment: `git --version`
- Try with `--upgrade` to force a fresh install: `pip install --upgrade 'git+...'`

### `request_id already exists` (409-equivalent `400`)

- Each `request_id` must be globally unique across all logs.
- Use a UUID: `import uuid; request_id = str(uuid.uuid4())`
- If you are retrying a failed log call, reuse the same `request_id` — Echo will reject the duplicate instead of double-logging.

### The database file keeps growing

- The SQLite database (`echo_prompt_manager.db`) is created in the working directory when you start the server.
- For production workloads with high log volume, swap the `SQLALCHEMY_DATABASE_URL` in `main.py` to PostgreSQL:
  ```python
  SQLALCHEMY_DATABASE_URL = "postgresql://user:password@localhost/echo"
  ```
- The current `create_engine(...)` call in `main.py` passes `connect_args={"check_same_thread": False}`, which is SQLite-specific. Remove that argument or make it conditional before switching to PostgreSQL.
- Then `pip install psycopg2-binary` and restart.

---

## 12. FAQ

**Q: Can non-engineers use Echo to change prompts without touching code?**  
A: Yes — that is the primary use case. A product manager opens the dashboard, edits the system prompt, clicks **Activate**, and the change is live immediately for all running application instances.

**Q: Is the dashboard secure?**  
A: The included `index.html` has no built-in authentication. For production deployments, place the dashboard and API behind an identity-aware proxy (e.g. Cloudflare Access, AWS Cognito) or add an authentication middleware to the FastAPI app.

**Q: Can I use Echo with any LLM provider?**  
A: Yes. Echo stores and serves prompt configurations — it is provider-agnostic. You pass the `system_prompt` to OpenAI, Anthropic, Google Gemini, or any other provider's SDK as you normally would.

**Q: How do I roll back a bad prompt change?**  
A: In the dashboard, navigate to the asset's version list, find a previous version, and click **Activate**. The rollback is instantaneous.

**Q: Does Echo cache prompts on the SDK side?**  
A: No. Each call to `get_active_prompt` makes a live HTTP request to ensure you always receive the latest version. If you require caching for latency or reliability reasons, add a short TTL cache in your application layer using a library with time-based expiry (for example, `cachetools.TTLCache`) or implement an explicit refresh-every-N-seconds pattern.

**Q: Can multiple assets be active simultaneously?**  
A: Yes. Each asset is independent. You can have hundreds of assets, each with its own active version.

**Q: What happens if the Echo backend is unreachable?**  
A: `get_active_prompt` raises an `Exception`. You should catch it and fall back to a locally defined default prompt to keep your application running.

```python
try:
    config = client.get_active_prompt("my_asset")
except Exception:
    config = {"system_prompt": DEFAULT_PROMPT, "version_id": None}
```
