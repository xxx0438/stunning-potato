"""结构化日志配置。"""

from __future__ import annotations

import logging
import os
import sys
from contextvars import ContextVar

import structlog

# Request 级 ContextVar（与 app/auth.py 共用语义）
request_id_var: ContextVar[str] = ContextVar("request_id", default="-")

def _add_request_context(logger, method_name, event_dict):
    """注入服务标识、request_id、actor、tenant。"""
    from app.auth import current_actor, current_tenant  # 局部 import 避免循环

    event_dict["request_id"] = request_id_var.get()
    event_dict["actor"] = current_actor.get()
    event_dict["tenant_id"] = current_tenant.get() or "-"
    event_dict["service"] = "echo-agent-governance"
    return event_dict

def configure_logging() -> structlog.BoundLogger:
    log_level = os.getenv("ECHO_LOG_LEVEL", "INFO").upper()
    log_format = os.getenv("ECHO_LOG_FORMAT", "json").lower()

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level, logging.INFO),
    )

    renderer = (
        structlog.processors.JSONRenderer()
        if log_format == "json"
        else structlog.dev.ConsoleRenderer(colors=True)
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _add_request_context,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, log_level, logging.INFO)
        ),
        cache_logger_on_first_use=True,
    )
    return structlog.get_logger("echo")
