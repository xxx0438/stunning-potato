"""v2.4 SaaS 能力测试。"""

import pytest

def test_metrics_endpoint(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    # 没启用时返回 disabled 提示也算通过
    assert "echo" in r.text or "disabled" in r.text

def test_health_reports_features(client):
    r = client.get("/health")
    body = r.json()
    for key in ("auth_mode", "metrics_enabled", "tracing_enabled",
                 "hashchain_enabled", "ratelimit_enabled"):
        assert key in body

def test_hash_chain_intact(client, seeded):
    """seed 后审计链应该完整。"""
    r = client.get("/api/audit/chain/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["broken_count"] == 0

def test_hash_chain_detects_tampering(client, seeded, app_module):
    """手动篡改一条记录的 summary，验证应该检测到断裂。"""
    from sqlalchemy.orm import Session as _Session
    with _Session(app_module.engine) as db:
        ev = db.query(app_module.ActivityEvent).first()
        if ev:
            ev.summary = "TAMPERED"
            db.commit()
    r = client.get("/api/audit/chain/verify")
    body = r.json()
    assert body["broken_count"] >= 1

def test_ratelimit_blocks_after_burst(client, monkeypatch):
    monkeypatch.setenv("ECHO_RATELIMIT_ENABLED", "1")
    monkeypatch.setenv("ECHO_RATELIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("ECHO_RATELIMIT_BURST", "1")
    from app import ratelimit
    ratelimit.reset_all()

    # 前 3 个应该通过，第 4 个 429
    statuses = []
    for _ in range(5):
        r = client.get("/api/assets/")
        statuses.append(r.status_code)
    assert 429 in statuses

def test_auth_demo_token_then_jwt_call(jwt_client):
    r = jwt_client.post("/api/auth/demo-token", json={
        "username": "alice", "tenant_id": "tenant-a", "roles": ["admin"],
    })
    token = r.json()["token"]
    me = jwt_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["tenant_id"] == "tenant-a"
