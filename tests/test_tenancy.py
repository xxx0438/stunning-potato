"""Multi-tenancy + JWT authentication tests."""

from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

# =====================================================
# Fixtures
# =====================================================
@pytest.fixture
def jwt_app_module(monkeypatch, tmp_path):
    """Re-import main with JWT mode enabled and an isolated in-memory DB."""
    monkeypatch.setenv("ECHO_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ECHO_DISABLE_WORKERS", "1")
    monkeypatch.setenv("ECHO_LOG_FORMAT", "console")
    monkeypatch.setenv("ECHO_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("ECHO_AUTH_MODE", "jwt")
    monkeypatch.setenv("ECHO_JWT_SECRET", "test-secret-please-change")
    monkeypatch.setenv("ECHO_JWT_ISSUER", "echo-test")
    monkeypatch.setenv("ECHO_DEMO_TOKEN_ENABLED", "1")
    monkeypatch.setenv("ECHO_RATELIMIT_ENABLED", "0")
    monkeypatch.setenv("ECHO_HASHCHAIN_ENABLED", "1")

    for mod in [m for m in list(sys.modules) if m == "main" or m.startswith("app.")]:
        del sys.modules[mod]

    main = importlib.import_module("main")

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=eng)
    main.engine = eng
    main.SessionLocal = TestSession
    main.Base.metadata.create_all(bind=eng)

    yield main

    main.Base.metadata.drop_all(bind=eng)
    eng.dispose()

@pytest.fixture
def jwt_client(jwt_app_module):
    with TestClient(jwt_app_module.app) as c:
        yield c

def _issue_token(client, username="alice", tenant_id="tenant-a", roles=None):
    """Helper: issue a demo JWT via the public endpoint."""
    resp = client.post(
        "/api/auth/demo-token",
        json={
            "username": username,
            "tenant_id": tenant_id,
            "roles": roles or ["admin", "owner", "approver"],
            "ttl_seconds": 3600,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]

def _auth_headers(token: str, tenant_id: str = "tenant-a"):
    return {"Authorization": f"Bearer {token}", "X-Echo-Tenant": tenant_id}

# =====================================================
# Tenant isolation (demo mode)
# =====================================================
def test_tenants_isolated_for_assets(client):
    """Assets created by tenant-a must not be visible to tenant-b."""
    client.headers.update({"X-Echo-Tenant": "tenant-a"})
    r1 = client.post("/api/assets/", json={
        "name": "agent_x", "asset_type": "workflows", "owner": "ai",
    })
    assert r1.status_code == 200, r1.text

    client.headers.update({"X-Echo-Tenant": "tenant-b"})
    r2 = client.get("/api/assets/")
    body = r2.json()
    items = body.get("items", body) if isinstance(body, dict) else body
    names = [a["name"] for a in items]
    assert "agent_x" not in names

def test_same_asset_name_across_tenants(client):
    """Same asset name can coexist across different tenants."""
    for tenant in ("tenant-a", "tenant-b"):
        client.headers.update({"X-Echo-Tenant": tenant})
        r = client.post("/api/assets/", json={
            "name": "shared_name", "asset_type": "workflows", "owner": "ai",
        })
        assert r.status_code == 200, r.text

def test_cross_tenant_asset_access_returns_404(client):
    """Tenant B cannot read tenant A's asset by id."""
    client.headers.update({"X-Echo-Tenant": "tenant-a"})
    r1 = client.post("/api/assets/", json={
        "name": "secret_agent", "asset_type": "workflows", "owner": "ai",
    })
    asset_id = r1.json()["id"]

    client.headers.update({"X-Echo-Tenant": "tenant-b"})
    r2 = client.get(f"/api/assets/{asset_id}")
    assert r2.status_code == 404

def test_tenant_id_is_persisted_on_create(client):
    """Auto-injected tenant_id should appear in the response."""
    client.headers.update({"X-Echo-Tenant": "tenant-x"})
    r = client.post("/api/assets/", json={
        "name": "asset_for_x", "asset_type": "skills", "owner": "ai",
    })
    assert r.status_code == 200
    assert r.json()["tenant_id"] == "tenant-x"

def test_change_request_isolated_by_tenant(client):
    """ChangeRequest must be tenant-scoped (high-risk wiring sanity check)."""
    # Setup an asset in tenant-a
    client.headers.update({"X-Echo-Tenant": "tenant-a"})
    asset = client.post("/api/assets/", json={
        "name": "agent_change_iso", "asset_type": "workflows", "owner": "ai",
    }).json()
    cr = client.post("/api/changes/", json={
        "commit_sha": "iso-001", "asset_id": asset["id"],
        "risk_level": "high", "review_required": True,
        "created_by": "alice",
    })
    assert cr.status_code == 200, cr.text

    # tenant-b should NOT see this change (404)
    client.headers.update({"X-Echo-Tenant": "tenant-b"})
    r = client.get("/api/changes/iso-001")
    assert r.status_code == 404

def test_audit_summary_scoped_per_tenant(client):
    """Each tenant gets its own audit summary."""
    client.headers.update({"X-Echo-Tenant": "tenant-a"})
    client.post("/api/assets/", json={
        "name": "tenant_a_asset", "asset_type": "skills", "owner": "ai",
    })
    a = client.get("/api/audit/reports/summary").json()
    assert a["asset_count"] >= 1
    assert a["tenant"] == "tenant-a"

    client.headers.update({"X-Echo-Tenant": "tenant-b"})
    b = client.get("/api/audit/reports/summary").json()
    assert b["asset_count"] == 0
    assert b["tenant"] == "tenant-b"

# =====================================================
# JWT authentication
# =====================================================
def test_jwt_missing_token_rejected(jwt_client):
    r = jwt_client.get("/api/auth/me")
    assert r.status_code == 401

def test_jwt_malformed_token_rejected(jwt_client):
    r = jwt_client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401

def test_jwt_invalid_signature_rejected(jwt_client, jwt_app_module):
    from app.auth import jwt_encode
    bad = jwt_encode(
        {"sub": "x", "tenant_id": "t", "roles": [], "exp": 9999999999, "iss": "echo-test"},
        "wrong-secret",
    )
    r = jwt_client.get("/api/auth/me", headers={"Authorization": f"Bearer {bad}"})
    assert r.status_code == 401

def test_jwt_expired_rejected(jwt_client):
    from app.auth import jwt_encode
    expired = jwt_encode(
        {"sub": "x", "tenant_id": "t", "roles": [], "exp": 1, "iss": "echo-test"},
        "test-secret-please-change",
    )
    r = jwt_client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()

def test_jwt_wrong_issuer_rejected(jwt_client, monkeypatch):
    monkeypatch.setenv("ECHO_JWT_ISSUER", "echo-test")
    from app.auth import jwt_encode
    import time as _t
    token = jwt_encode(
        {"sub": "x", "tenant_id": "t", "roles": [], "exp": int(_t.time()) + 3600,
         "iss": "evil-issuer"},
        "test-secret-please-change",
    )
    r = jwt_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401

def test_jwt_missing_tenant_rejected(jwt_client):
    from app.auth import jwt_encode
    import time as _t
    token = jwt_encode(
        {"sub": "x", "roles": ["admin"], "exp": int(_t.time()) + 3600, "iss": "echo-test"},
        "test-secret-please-change",
    )
    r = jwt_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert "tenant_id" in r.json()["detail"]

def test_jwt_demo_token_endpoint(jwt_client):
    token = _issue_token(jwt_client)
    me = jwt_client.get("/api/auth/me", headers=_auth_headers(token))
    assert me.status_code == 200
    body = me.json()
    assert body["actor"] == "alice"
    assert body["tenant_id"] == "tenant-a"
    assert "admin" in body["roles"]
    assert body["auth_mode"] == "jwt"

def test_jwt_tenant_isolation(jwt_client):
    """JWT tenant claim must override any X-Echo-Tenant header attempts."""
    token_a = _issue_token(jwt_client, username="alice", tenant_id="tenant-a")
    token_b = _issue_token(jwt_client, username="bob", tenant_id="tenant-b")

    # Alice creates an asset under tenant-a
    r1 = jwt_client.post(
        "/api/assets/",
        json={"name": "alice_asset", "asset_type": "workflows", "owner": "alice"},
        headers={"Authorization": f"Bearer {token_a}"},
    )
    assert r1.status_code == 200
    assert r1.json()["tenant_id"] == "tenant-a"

    # Bob (tenant-b) tries to read tenant-a's asset by id → must 404
    aid = r1.json()["id"]
    r2 = jwt_client.get(
        f"/api/assets/{aid}",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert r2.status_code == 404

def test_jwt_role_enforcement(jwt_client):
    """Endpoints behind require_role([...]) must reject under-privileged tokens."""
    low_token = _issue_token(jwt_client, username="charlie",
                              tenant_id="tenant-a", roles=["viewer"])
    r = jwt_client.post(
        "/api/integrations/connections/",
        json={"provider": "gitlab", "name": "x"},
        headers={"Authorization": f"Bearer {low_token}"},
    )
    assert r.status_code == 403

def test_jwt_admin_can_create_connection(jwt_client):
    admin_token = _issue_token(jwt_client, roles=["admin"])
    r = jwt_client.post(
        "/api/integrations/connections/",
        json={
            "provider": "gitlab", "name": "primary-gitlab",
            "base_url": "https://gitlab.com",
            "auth_ref": "env:GITLAB_TOKEN", "config": {}, "enabled": True,
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert r.status_code == 200, r.text

def test_jwt_demo_token_can_be_disabled(jwt_client, monkeypatch):
    monkeypatch.setenv("ECHO_DEMO_TOKEN_ENABLED", "0")
    r = jwt_client.post(
        "/api/auth/demo-token",
        json={"username": "x", "tenant_id": "t", "roles": ["viewer"]},
    )
    assert r.status_code == 404
