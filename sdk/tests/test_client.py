"""Unit tests for the synchronous client."""

from __future__ import annotations

import json

import httpx
import pytest

from echo_sdk import EchoClient
from echo_sdk.exceptions import (
    AuthenticationError,
    EchoAPIError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ValidationError,
)
from echo_sdk.retry import RetryPolicy

def test_health(client, respx_mock):
    respx_mock.get("/health").respond(json={"status": "ok", "version": "2.5.0"})
    body = client.health()
    assert body["status"] == "ok"

def test_whoami_sends_auth_headers(client, respx_mock):
    route = respx_mock.get("/api/auth/me").respond(json={
        "actor": "alice", "tenant_id": "tenant-a", "roles": ["admin"],
    })
    body = client.whoami()
    assert body["actor"] == "alice"
    sent = route.calls.last.request
    assert sent.headers["Authorization"] == "Bearer test-token"
    assert sent.headers["X-Echo-Tenant"] == "tenant-a"

def test_demo_mode_headers(respx_mock):
    c = EchoClient(
        base_url="https://echo.test",
        actor="bob", roles=["viewer", "owner"],
        retry=RetryPolicy(max_attempts=1),
    )
    try:
        route = respx_mock.get("/api/assets/").respond(json={
            "items": [], "total": 0, "limit": 10, "offset": 0,
        })
        c.assets.list(limit=10)
        sent = route.calls.last.request
        assert sent.headers["X-Echo-Actor"] == "bob"
        assert sent.headers["X-Echo-Roles"] == "viewer,owner"
        assert "Authorization" not in sent.headers
    finally:
        c.close()

def test_list_assets_parsing(client, respx_mock):
    respx_mock.get("/api/assets/").respond(json={
        "items": [
            {"id": 1, "name": "agent_a", "asset_type": "workflows",
             "owner": "ai", "tenant_id": "tenant-a", "namespace": "default",
             "tags": [], "metadata": {}},
        ],
        "total": 1, "limit": 50, "offset": 0,
    })
    page = client.assets.list()
    assert page.total == 1
    assert len(page.items) == 1
    asset = page.items[0]
    assert asset.id == 1
    assert asset.name == "agent_a"
    assert asset.asset_type == "workflows"
    assert asset.raw["owner"] == "ai"

def test_gate_check_blocks(client, respx_mock):
    respx_mock.post("/api/ci/gate/check").respond(json={
        "status": "block",
        "commit_sha": "abc123",
        "reasons": ["High risk change is not approved"],
        "evaluations": [], "review_request": None,
    })
    result = client.gate.check(commit_sha="abc123", is_ai_related=True)
    assert result.is_blocked
    assert "High risk change is not approved" in result.reasons

def test_guardrail_check_decision(client, respx_mock):
    respx_mock.post("/api/runtime/guardrails/check").respond(json={
        "status": "block", "tool_name": "transfer", "actor": "alice",
        "findings": [{"rule": "max_amount", "decision": "block",
                       "reason": "tool_args.amount exceeds limit 5000"}],
    })
    result = client.runtime.guardrail_check(
        asset_name="loan_agent", tool_name="transfer",
        tool_args={"amount": 9999},
    )
    assert result.is_blocked
    assert result.findings[0].rule == "max_amount"

def test_404_raises_not_found(client, respx_mock):
    respx_mock.get("/api/assets/999").respond(404, json={"detail": "Asset not found"})
    with pytest.raises(NotFoundError):
        client.assets.get(999)

def test_401_raises_authentication_error(client, respx_mock):
    respx_mock.get("/api/auth/me").respond(401, json={"detail": "Invalid JWT signature"})
    with pytest.raises(AuthenticationError):
        client.whoami()

def test_403_raises_permission_denied(client, respx_mock):
    respx_mock.post("/api/integrations/connections/").respond(
        403, json={"detail": "Requires one of roles: admin, maintainer"},
    )
    with pytest.raises(PermissionDeniedError):
        client._request("POST", "/api/integrations/connections/", json={})

def test_422_raises_validation_error(client, respx_mock):
    respx_mock.post("/api/changes/").respond(
        422, json={"detail": "High-risk change must link an asset"},
    )
    with pytest.raises(ValidationError):
        client.changes.create(commit_sha="x", risk_level="high", created_by="me")

def test_429_includes_retry_after(client, respx_mock):
    respx_mock.get("/health").respond(
        429,
        headers={"Retry-After": "7"},
        json={"detail": "Rate limit exceeded"},
    )
    with pytest.raises(RateLimitError) as exc_info:
        client.health()
    assert exc_info.value.retry_after == 7

def test_retry_on_5xx_then_success(respx_mock):
    c = EchoClient(
        base_url="https://echo.test", token="t",
        retry=RetryPolicy(max_attempts=3, initial_delay=0.0, jitter=0),
    )
    try:
        respx_mock.get("/health").mock(side_effect=[
            httpx.Response(503, json={"detail": "down"}),
            httpx.Response(503, json={"detail": "down"}),
            httpx.Response(200, json={"status": "ok"}),
        ])
        body = c.health()
        assert body["status"] == "ok"
    finally:
        c.close()

def test_retry_exhausted(respx_mock):
    c = EchoClient(
        base_url="https://echo.test", token="t",
        retry=RetryPolicy(max_attempts=2, initial_delay=0.0, jitter=0),
    )
    try:
        respx_mock.get("/health").respond(503, json={"detail": "down"})
        with pytest.raises(EchoAPIError) as exc_info:
            c.health()
        assert exc_info.value.status_code == 503
    finally:
        c.close()

def test_context_manager_closes_client(respx_mock):
    respx_mock.get("/health").respond(json={"status": "ok"})
    with EchoClient(base_url="https://echo.test", token="t") as c:
        c.health()

def test_create_change_payload(client, respx_mock):
    route = respx_mock.post("/api/changes/").respond(json={
        "id": 1, "commit_sha": "xyz", "tenant_id": "tenant-a",
        "risk_level": "high", "review_required": True, "review_status": "pending",
        "impact_scope": ["agents/loan"], "notes": "AI change",
        "created_by": "alice",
    })
    change = client.changes.create(
        commit_sha="xyz", created_by="alice",
        risk_level="high", review_required=True,
        impact_scope=["agents/loan"], notes="AI change",
    )
    assert change.commit_sha == "xyz"
    assert change.review_required
    sent = json.loads(route.calls.last.request.content)
    assert sent["commit_sha"] == "xyz"
    assert sent["risk_level"] == "high"

def test_eval_run(client, respx_mock):
    respx_mock.post("/api/evaluations/run").respond(json={
        "id": 9, "tenant_id": "tenant-a", "suite_id": 1,
        "asset_version_id": 42, "status": "passed", "score": 90,
        "passed_count": 2, "failed_count": 0, "error_count": 0,
        "total_count": 2, "results": [], "mode": "mock",
    })
    run = client.evaluations.run(suite_id=1, asset_version_id=42,
                                  mock_outputs={"a": "good"})
    assert run.passed
    assert run.score == 90

def test_request_id_header_is_sent(client, respx_mock):
    route = respx_mock.get("/health").respond(json={"status": "ok"})
    client.health()
    assert route.calls.last.request.headers.get("X-Request-ID")

def test_user_agent(client, respx_mock):
    route = respx_mock.get("/health").respond(json={"status": "ok"})
    client.health()
    ua = route.calls.last.request.headers.get("User-Agent")
    assert "echo-sdk-python" in ua
