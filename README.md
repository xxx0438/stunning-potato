# Echo Agent Governance

> **Single-file FastAPI + modular `app/` + single-file frontend** — a SaaS-ready agent governance platform.
> Closes the loop: **Asset → Version → Change → Evaluation → CI Gate → Runtime → Logs → Incidents → Collaboration → Audit**.

[![CI](https://github.com/xxx0438/e-cho/actions/workflows/ci.yml/badge.svg)](https://github.com/xxx0438/e-cho/actions/workflows/ci.yml)

## ✨ Features

| Capability | Status |
|---|---|
| Context Asset Registry (10 types) | ✅ |
| Version management + Diff | ✅ |
| CI Gate (risk-aware + eval-aware) | ✅ |
| Runtime Guardrails (5 rule types) | ✅ |
| Evaluations (stub/mock mode) | ✅ |
| GitLab webhook + import + status writeback | ✅ |
| Datadog outbox + incident loop | ✅ |
| RBAC + Review + Comments + Tasks | ✅ |
| Multi-tenant (row-level `tenant_id`) | ✅ |
| JWT authentication | ✅ |
| Alembic migrations | ✅ |
| OpenTelemetry traces | ✅ |
| Prometheus metrics | ✅ |
| API rate limiting | ✅ |
| Tamper-evident audit (hash chain) | ✅ |

## 🚀 Quick start

```bash
pip install -r requirements.txt
alembic upgrade head
uvicorn main:app --reload --port 8000
