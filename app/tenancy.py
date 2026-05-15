"""多租户隔离层。"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Optional

from sqlalchemy import event
from sqlalchemy.orm import Session

from app.auth import current_tenant

logger = logging.getLogger("echo.tenancy")

TENANT_AWARE_TABLES: set = set()

def mark_tenant_aware(model_cls):
    """装饰器：把模型注册为租户感知。"""
    TENANT_AWARE_TABLES.add(model_cls.__tablename__)
    return model_cls

@contextmanager
def with_tenant_override(tenant_id: Optional[str]):
    token = current_tenant.set(tenant_id)
    try:
        yield
    finally:
        current_tenant.reset(token)

def get_current_tenant_or_raise() -> str:
    tid = current_tenant.get()
    if not tid:
        raise RuntimeError("No current tenant set; use with_tenant_override() in background tasks.")
    return tid

def install_tenancy_hooks(base) -> None:
    """安装 SQLAlchemy 事件：写入时自动注入 tenant_id。"""
    @event.listens_for(Session, "before_flush")
    def _inject_tenant_id(session, flush_context, instances):
        tid = current_tenant.get()
        if not tid:
            return
        for obj in session.new:
            tbl = getattr(obj, "__tablename__", None)
            if not tbl or tbl not in TENANT_AWARE_TABLES:
                continue
            if getattr(obj, "tenant_id", None) in (None, ""):
                setattr(obj, "tenant_id", tid)

    logger.info("Tenancy hooks installed for %d tables", len(TENANT_AWARE_TABLES))

def filter_by_tenant(query, model_cls, tenant_id: Optional[str] = None):
    tid = tenant_id or current_tenant.get()
    if not tid:
        raise RuntimeError("No tenant context for filter_by_tenant")
    if model_cls.__tablename__ not in TENANT_AWARE_TABLES:
        return query
    return query.filter(model_cls.tenant_id == tid)
