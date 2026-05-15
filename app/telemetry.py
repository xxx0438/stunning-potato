"""OpenTelemetry 接入（可选）。

环境变量：
- ECHO_OTEL_ENABLED=1                  启用
- ECHO_OTEL_SERVICE_NAME=echo
- OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
- OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf  (or grpc)

未启用时所有调用为 no-op，main.py 无需感知。
"""

from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger("echo.telemetry")

_initialized = False
_tracer = None

def is_enabled() -> bool:
    return os.getenv("ECHO_OTEL_ENABLED", "0").lower() in ("1", "true", "yes")

def setup_tracing(app=None, engine=None) -> None:
    """初始化 OpenTelemetry。失败时降级为 no-op。"""
    global _initialized, _tracer

    if _initialized or not is_enabled():
        return

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.sdk.resources import SERVICE_NAME, Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        logger.warning("OTEL packages not installed; skipping tracing setup. (%s)", exc)
        return

    service_name = os.getenv("ECHO_OTEL_SERVICE_NAME", "echo-agent-governance")
    resource = Resource(attributes={SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter()  # 自动读 OTEL_EXPORTER_OTLP_*
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _tracer = trace.get_tracer("echo")

    if app is not None:
        FastAPIInstrumentor.instrument_app(app, excluded_urls="health,metrics")
    if engine is not None:
        SQLAlchemyInstrumentor().instrument(engine=engine)
    RequestsInstrumentor().instrument()

    _initialized = True
    logger.info("OpenTelemetry initialized: service=%s", service_name)

def get_tracer():
    return _tracer

def start_span(name: str, **attributes):
    """便捷上下文管理器；未启用时返回 nullcontext。"""
    if _tracer is None:
        from contextlib import nullcontext
        return nullcontext()
    span = _tracer.start_as_current_span(name)
    if attributes:
        # 进入上下文后再设置属性
        from contextlib import contextmanager

        @contextmanager
        def _wrap():
            with span as s:
                for k, v in attributes.items():
                    if v is not None:
                        s.set_attribute(k, v)
                yield s
        return _wrap()
    return span

def get_trace_id() -> Optional[str]:
    """返回当前活动 span 的 trace_id（hex 字符串），用于关联日志。"""
    if not _initialized:
        return None
    try:
        from opentelemetry import trace
        ctx = trace.get_current_span().get_span_context()
        if not ctx or not ctx.is_valid:
            return None
        return format(ctx.trace_id, "032x")
    except Exception:
        return None
