"""CLI integration tests.

We don't use respx here because EchoClient inside the CLI builds its own
httpx.Client. Instead we monkey-patch httpx transports via a fake handler.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any, Dict, List

import httpx
import pytest

from echo_sdk.cli import build_parser, main

# =====================================================
# Tiny fake transport
# =====================================================
class _FakeTransport(httpx.BaseTransport):
    def __init__(self, routes: Dict[str, Any]) -> None:
        self.routes = routes
        self.calls: List[httpx.Request] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        key = f"{request.method} {request.url.path}"
        if key not in self.routes:
            return httpx.Response(404, json={"detail": f"no route: {key}"})
        route = self.routes[key]
        if callable(route):
            return route(request)
        status, body = route
        return httpx.Response(status, json=body)

@contextmanager
def _patched_client(monkeypatch, routes):
    transport = _FakeTransport(routes)
    original = httpx.Client.__init__

    def _init(self, *args, **kwargs):
        kwargs["transport"] = transport
        original(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", _init)
    try:
        yield transport
    finally:
        monkeypatch.setattr(httpx.Client, "__init__", original)

# =====================================================
# Tests
# =====================================================
def test_parser_builds():
    parser = build_parser()
    args = parser.parse_args([
        "gate", "check", "--commit", "abc", "--ai-related",
        "--base-url", "http://x",
    ])
    assert args.command == "gate"
    assert args.commit == "abc"
    assert args.ai_related is True

def test_health_cmd(monkeypatch, capsys):
    routes = {"GET /health": (200, {"status": "ok", "version": "2.5.0"})}
    with _patched_client(monkeypatch, routes):
        rc = main([
            "health", "--base-url", "https://echo.test", "--token", "t",
            "--format", "json",
        ])
    out = capsys.readouterr().out
    assert rc == 0
    assert json.loads(out)["status"] == "ok"

def test_gate_check_pass(monkeypatch, capsys):
    routes = {
        "POST /api/ci/gate/check": (200, {
            "status": "pass", "commit_sha": "abc",
            "reasons": ["All checks passed"],
            "evaluations": [], "review_request": None,
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "gate", "check", "--commit", "abc",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "pass" in out.lower()

def test_gate_check_block_returns_exit_1(monkeypatch, capsys):
    routes = {
        "POST /api/ci/gate/check": (200, {
            "status": "block", "commit_sha": "abc",
            "reasons": ["High risk change is not approved"],
            "evaluations": [], "review_request": None,
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "gate", "check", "--commit", "abc", "--ai-related",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 1

def test_gate_check_warn_strict_returns_1(monkeypatch):
    routes = {
        "POST /api/ci/gate/check": (200, {
            "status": "warn", "commit_sha": "abc",
            "reasons": ["Medium risk change is pending review"],
            "evaluations": [], "review_request": None,
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "gate", "check", "--commit", "abc", "--strict",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 1

def test_guardrail_check_block_returns_1(monkeypatch):
    routes = {
        "POST /api/runtime/guardrails/check": (200, {
            "status": "block", "tool_name": "transfer", "actor": "x",
            "findings": [{"rule": "max_amount", "decision": "block",
                           "reason": "limit exceeded"}],
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "guardrail", "check",
            "--asset", "loan_agent", "--tool", "transfer",
            "--args", '{"amount":9999}',
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 1

def test_eval_run_failure_returns_1(monkeypatch):
    routes = {
        "POST /api/evaluations/run": (200, {
            "id": 1, "suite_id": 1, "status": "failed",
            "score": 30, "passed_count": 1, "failed_count": 2,
            "error_count": 0, "total_count": 3, "results": [],
            "mode": "mock",
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "eval", "run", "--suite", "1", "--version", "42",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 1

def test_audit_verify_broken_returns_1(monkeypatch):
    routes = {
        "GET /api/audit/chain/verify": (200, {
            "total": 5, "broken_count": 1,
            "broken": [{"id": 3, "expected": "x", "actual": "y"}],
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "audit", "verify",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 1

def test_api_error_returns_exit_2(monkeypatch):
    routes = {
        "GET /health": (500, {"detail": "boom"}),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "health",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    assert rc == 2

def test_asset_list_text_output(monkeypatch, capsys):
    routes = {
        "GET /api/assets/": (200, {
            "items": [
                {"id": 1, "name": "a1", "asset_type": "workflows",
                 "namespace": "default", "tenant_id": "tenant-a",
                 "owner": "ai", "tags": [], "metadata": {}},
            ],
            "total": 1, "limit": 50, "offset": 0,
        }),
    }
    with _patched_client(monkeypatch, routes):
        rc = main([
            "asset", "list",
            "--base-url", "https://echo.test", "--token", "t",
        ])
    out = capsys.readouterr().out
    assert rc == 0
    assert "a1" in out and "workflows" in out

def test_invalid_json_args_aborts(monkeypatch):
    with pytest.raises(SystemExit):
        main([
            "guardrail", "check", "--tool", "x",
            "--args", "{not-json}",
            "--base-url", "https://echo.test", "--token", "t",
        ])
