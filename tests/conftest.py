"""Pytest fixtures for Echo Agent Governance.

每个测试函数用独立的 in-memory SQLite，互不影响。
通过 monkeypatch 把 main 模块的 engine/SessionLocal 替换为测试版本。
"""

from __future__ import annotations

import importlib
import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

@pytest.fixture
def app_module(monkeypatch, tmp_path):
    """重新导入 main，使用 in-memory SQLite，禁用后台 worker。"""
    monkeypatch.setenv("ECHO_DATABASE_URL", "sqlite:///:memory:")
    monkeypatch.setenv("ECHO_DISABLE_WORKERS", "1")
    monkeypatch.setenv("ECHO_LOG_FORMAT", "console")
    monkeypatch.setenv("ECHO_LOG_LEVEL", "WARNING")

    # 确保拿到全新模块（清缓存）
    if "main" in sys.modules:
        del sys.modules["main"]

    main = importlib.import_module("main")

    # 用 StaticPool 让 in-memory SQLite 在多次会话间共享
    test_engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    main.engine = test_engine
    main.SessionLocal = TestSession
    main.Base.metadata.create_all(bind=test_engine)

    yield main

    main.Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()

@pytest.fixture
def client(app_module):
    with TestClient(app_module.app) as c:
        c.headers.update({
            "X-Echo-Actor": "test-admin",
            "X-Echo-Roles": "admin,maintainer,owner,approver,reviewer,contributor",
        })
        yield c

@pytest.fixture
def seeded(client):
    """调用 demo seed，返回种子数据。"""
    resp = client.post("/api/demo/seed")
    assert resp.status_code == 200, resp.text
    return resp.json()
