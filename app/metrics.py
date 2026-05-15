"""Prometheus metrics。

通过 /metrics 端点暴露。未安装 prometheus_client 时降级为 no-op。
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import contextmanager

logger = logging.getLogger("echo.metrics")

_enabled = False
_registry = None

# Metric handles（启用时填充）
http_requests_total = None
http_request_duration_seconds = None
gate_decisions_total = None
guardrail_decisions_total = None
evaluation_runs_total = None
evaluation_score_histogram = None
ratelimit_rejections_total = None
tenant_active_assets = None

def is_enabled() -> bool:
    return _enabled

def setup_metrics() -> None:
    global _enabled, _registry
    global http_requests_total, http_request_duration_seconds
    global gate_decisions_total, guardrail_decisions_total
    global evaluation_runs_total, evaluation_score_histogram
    global ratelimit_rejections_total, tenant_active_assets
    global webhook_deliveries_total
webhook_deliveries_total = Counter(
    "echo_webhook_deliveries_total",
    "Outbound webhook delivery attempts",
    ["status", "event_type", "tenant"],
    registry=_registry,
)

    if os.getenv("ECHO_METRICS_ENABLED", "1").lower() not in ("1", "true", "yes"):
        return

    try:
        from prometheus_client import (
            CollectorRegistry,
            Counter,
            Gauge,
            Histogram,
        )
    except ImportError:
        logger.warning("prometheus_client not installed; metrics disabled.")
        return

    _registry = CollectorRegistry()

    http_requests_total = Counter(
        "echo_http_requests_total",
        "Total HTTP requests",
        ["method", "path", "status", "tenant"],
        registry=_registry,
    )
    http_request_duration_seconds = Histogram(
        "echo_http_request_duration_seconds",
        "HTTP request duration",
        ["method", "path"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
        registry=_registry,
    )
    gate_decisions_total = Counter(
        "echo_gate_decisions_total",
        "CI gate decisions",
        ["status", "tenant"],
        registry=_registry,
    )
    guardrail_decisions_total = Counter(
        "echo_guardrail_decisions_total",
        "Runtime guardrail decisions",
        ["decision", "tenant"],
        registry=_registry,
    )
    evaluation_runs_total = Counter(
        "echo_evaluation_runs_total",
        "Evaluation runs",
        ["status", "mode", "tenant"],
        registry=_registry,
    )
    evaluation_score_histogram = Histogram(
        "echo_evaluation_score",
        "Evaluation score distribution",
        ["tenant"],
        buckets=(0, 20, 40, 60, 70, 75, 80, 85, 90, 95, 100),
        registry=_registry,
    )
    ratelimit_rejections_total = Counter(
        "echo_ratelimit_rejections_total",
        "Rate limit rejections",
        ["bucket", "tenant"],
        registry=_registry,
    )
    tenant_active_assets = Gauge(
        "echo_tenant_active_assets",
        "Active assets per tenant",
        ["tenant"],
        registry=_registry,
    )

    _enabled = True
    logger.info("Prometheus metrics enabled")

def get_registry():
    return _registry

def render_metrics() -> tuple:
    """返回 (body_bytes, content_type)。"""
    if not _enabled:
        return b"# metrics disabled\n", "text/plain"
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
    return generate_latest(_registry), CONTENT_TYPE_LATEST

@contextmanager
def time_request(method: str, path: str):
    """请求时长计时上下文。"""
    start = time.perf_counter()
    try:
        yield
    finally:
        if _enabled and http_request_duration_seconds is not None:
            elapsed = time.perf_counter() - start
            try:
                http_request_duration_seconds.labels(method=method, path=path).observe(elapsed)
            except Exception:
                pass

def inc_request(method: str, path: str, status: int, tenant: str = "-"):
    if _enabled and http_requests_total is not None:
        try:
            http_requests_total.labels(method=method, path=path, status=str(status), tenant=tenant).inc()
        except Exception:
            pass

def inc_webhook(status: str, event_type: str, tenant: str = "-"):
    if _enabled and webhook_deliveries_total is not None:
        try:
            webhook_deliveries_total.labels(
                status=status, event_type=event_type, tenant=tenant
            ).inc()
        except Exception:
            pass

def inc_gate(status: str, tenant: str = "-"):
    if _enabled and gate_decisions_total is not None:
        gate_decisions_total.labels(status=status, tenant=tenant).inc()

def inc_guardrail(decision: str, tenant: str = "-"):
    if _enabled and guardrail_decisions_total is not None:
        guardrail_decisions_total.labels(decision=decision, tenant=tenant).inc()

def observe_eval(status: str, mode: str, score: int, tenant: str = "-"):
    if _enabled:
        if evaluation_runs_total is not None:
            evaluation_runs_total.labels(status=status, mode=mode, tenant=tenant).inc()
        if evaluation_score_histogram is not None:
            evaluation_score_histogram.labels(tenant=tenant).observe(score)

def inc_ratelimit_rejection(bucket: str, tenant: str = "-"):
    if _enabled and ratelimit_rejections_total is not None:
        ratelimit_rejections_total.labels(bucket=bucket, tenant=tenant).inc()
