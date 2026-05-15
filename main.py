"""Echo Agent Governance — main application module.

v2.4 SaaS edition:
- JWT/demo dual-mode auth (app/auth.py)
- Row-level multi-tenancy (app/tenancy.py)
- Alembic for schema migrations
- Optional OpenTelemetry tracing (app/telemetry.py)
- Prometheus metrics (app/metrics.py)
- API rate limiting (app/ratelimit.py)
- Tamper-evident audit log via hash chain (app/hashchain.py)
"""

from __future__ import annotations
from app import hashchain, metrics, ratelimit, telemetry, webhooks

import asyncio
import difflib as _difflib
import hmac
import json as _json
import os
import re as _re
import time
import uuid
from collections import Counter
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON, Boolean, Column, DateTime, Enum as SAEnum, ForeignKey, Integer,
    String, Text, UniqueConstraint, create_engine, func, inspect, or_, text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import declarative_base, relationship, selectinload, sessionmaker, Session

from app import hashchain, metrics, ratelimit, telemetry
from app.auth import (
    authenticate, current_actor, current_roles, current_tenant,
    has_role, issue_demo_token, require_role,
)
from app.logging_setup import configure_logging, request_id_var
from app.tenancy import (
    TENANT_AWARE_TABLES, filter_by_tenant, install_tenancy_hooks,
    mark_tenant_aware, with_tenant_override,
)

logger = configure_logging()

def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

# =====================================================
# 1. Database
# =====================================================
SQLALCHEMY_DATABASE_URL = os.getenv("ECHO_DATABASE_URL", "sqlite:///./echo_prompt_manager.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {},
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# =====================================================
# 2. Enums
# =====================================================
class AssetType(str, Enum):
    prompt_templates = "prompt_templates"
    context_packs = "context_packs"
    tools = "tools"
    guardrails = "guardrails"
    agent_configurations = "agent_configurations"
    workflows = "workflows"
    skills = "skills"
    memory_templates = "memory_templates"
    knowledge_base_connectors = "knowledge_base_connectors"
    evaluation_test_suites = "evaluation_test_suites"

class VersionStatus(str, Enum):
    draft = "draft"
    review_pending = "review_pending"
    approved = "approved"
    rejected = "rejected"
    active = "active"
    deprecated = "deprecated"

class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class ReviewStatus(str, Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    skipped = "skipped"

class IntegrationProvider(str, Enum):
    gitlab = "gitlab"
    datadog = "datadog"

class IntegrationEventStatus(str, Enum):
    received = "received"
    processed = "processed"
    failed = "failed"

class TelemetryStatus(str, Enum):
    pending = "pending"
    sent = "sent"
    failed = "failed"
    skipped = "skipped"

class IncidentStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"

class IncidentSeverity(str, Enum):
    info = "info"
    warn = "warn"
    alert = "alert"
    critical = "critical"

class RoleName(str, Enum):
    admin = "admin"
    maintainer = "maintainer"
    owner = "owner"
    contributor = "contributor"
    reviewer = "reviewer"
    approver = "approver"
    auditor = "auditor"
    viewer = "viewer"

class ReviewDecision(str, Enum):
    pending = "pending"
    approved = "approved"
    changes_requested = "changes_requested"
    rejected = "rejected"

class ReviewRequestStatus(str, Enum):
    review_pending = "review_pending"
    approved = "approved"
    rejected = "rejected"

class TaskStatus(str, Enum):
    open = "open"
    in_progress = "in_progress"
    done = "done"
    cancelled = "cancelled"

class TaskPriority(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    urgent = "urgent"

class CommentStatus(str, Enum):
    open = "open"
    resolved = "resolved"

class LockStatus(str, Enum):
    active = "active"
    released = "released"
    expired = "expired"

class EvalSuiteStatus(str, Enum):
    active = "active"
    archived = "archived"

class EvalRunStatus(str, Enum):
    pending = "pending"
    running = "running"
    passed = "passed"
    failed = "failed"
    error = "error"

class EvalCaseResult(str, Enum):
    pass_ = "pass"
    fail = "fail"
    error = "error"
    skipped = "skipped"

ASSET_TYPE_GATE_POLICIES: Dict[AssetType, Dict[str, Any]] = {
    AssetType.prompt_templates: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                                  "reason": "Prompt template changes can alter model behavior."},
    AssetType.context_packs: {"risk_level": RiskLevel.medium, "review_required": False, "default_runtime_decision": "allow",
                              "reason": "Context pack changes affect assembled context."},
    AssetType.tools: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                       "reason": "Tool/function schema changes affect external actions."},
    AssetType.guardrails: {"risk_level": RiskLevel.high, "review_required": True, "block_without_approval": True,
                            "default_runtime_decision": "review",
                            "reason": "Guardrail changes must be approved before deployment."},
    AssetType.agent_configurations: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                                      "reason": "Agent configuration changes affect routing/model choice."},
    AssetType.workflows: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                           "reason": "Workflow changes can alter execution order and production actions."},
    AssetType.skills: {"risk_level": RiskLevel.medium, "review_required": False, "default_runtime_decision": "allow",
                        "reason": "Skill changes affect reusable agent capabilities."},
    AssetType.memory_templates: {"risk_level": RiskLevel.medium, "review_required": False, "default_runtime_decision": "allow",
                                  "reason": "Memory template changes affect retention behavior."},
    AssetType.knowledge_base_connectors: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                                           "reason": "KB connector changes affect RAG data access."},
    AssetType.evaluation_test_suites: {"risk_level": RiskLevel.high, "review_required": True, "default_runtime_decision": "review",
                                        "reason": "Eval suite changes affect quality gates."},
}

LEGACY_ASSET_TYPE_MIGRATIONS = {
    "prompt": AssetType.prompt_templates.value,
    "context_pack": AssetType.context_packs.value,
    "skill": AssetType.skills.value,
    "workflow": AssetType.workflows.value,
}

DIFF_MAX_LINES = 800
DIFF_MAX_CHARS = 200_000

TELEMETRY_FLUSH_INTERVAL = int(os.getenv("ECHO_TELEMETRY_FLUSH_INTERVAL", "30"))
LOCK_CLEANUP_INTERVAL = int(os.getenv("ECHO_LOCK_CLEANUP_INTERVAL", "60"))
TELEMETRY_BATCH_SIZE = int(os.getenv("ECHO_TELEMETRY_BATCH_SIZE", "20"))

ASSET_METADATA_TYPE = JSON().with_variant(JSONB, "postgresql")

# =====================================================
# 3. ORM models (with tenant_id)
# =====================================================
def _tenant_col():
    return Column(String(64), nullable=False, default="default", index=True)

@mark_tenant_aware
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "namespace", "name", name="uq_asset_tenant_ns_name"),
    )
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    namespace = Column(String, nullable=False, default="default", index=True)
    name = Column(String, index=True, nullable=False)
    asset_type = Column(SAEnum(AssetType), nullable=False, index=True)
    description = Column(Text, default="")
    owner = Column(String, nullable=False, index=True)
    tags = Column(JSON, default=list)
    metadata_ = Column("metadata", ASSET_METADATA_TYPE, default=dict, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    versions = relationship("AssetVersion", back_populates="asset", cascade="all, delete-orphan",
                            order_by="AssetVersion.id.desc()")
    change_requests = relationship("ChangeRequest", back_populates="asset", cascade="all, delete-orphan")
    external_references = relationship("ExternalReference", back_populates="asset", cascade="all, delete-orphan")

@mark_tenant_aware
class AssetVersion(Base):
    __tablename__ = "asset_versions"
    __table_args__ = (UniqueConstraint("asset_id", "version_tag", name="uq_asset_version_tag"),)
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    version_tag = Column(String, nullable=False, index=True)
    status = Column(SAEnum(VersionStatus), default=VersionStatus.draft, nullable=False, index=True)
    system_prompt = Column(Text, default="")
    context_template = Column(Text, default="")
    workflow_spec = Column(JSON, default=dict)
    examples = Column(JSON, default=list)
    guardrails = Column(JSON, default=list)
    variables_schema = Column(JSON, default=dict)
    change_summary = Column(Text, default="")
    created_by = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    asset = relationship("Asset", back_populates="versions")
    execution_logs = relationship("ExecutionLog", back_populates="asset_version", cascade="all, delete-orphan")
    change_requests = relationship("ChangeRequest", back_populates="asset_version", cascade="all, delete-orphan")

@mark_tenant_aware
class ExecutionLog(Base):
    __tablename__ = "execution_logs"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=False, index=True)
    request_id = Column(String, unique=True, nullable=True, index=True)
    model_name = Column(String, default="", index=True)
    input_variables = Column(JSON, default=dict)
    llm_output = Column(Text, default="")
    latency_ms = Column(Integer, default=0)
    token_usage = Column(Integer, default=0)
    trace_id = Column(String, default="", index=True)
    span_id = Column(String, default="", index=True)
    service = Column(String, default="", index=True)
    env = Column(String, default="", index=True)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)
    asset_version = relationship("AssetVersion", back_populates="execution_logs")

@mark_tenant_aware
class ChangeRequest(Base):
    __tablename__ = "change_requests"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    commit_sha = Column(String, unique=True, nullable=False, index=True)
    pr_id = Column(String, nullable=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=True, index=True)
    risk_level = Column(SAEnum(RiskLevel), nullable=False, default=RiskLevel.low, index=True)
    impact_scope = Column(JSON, default=list)
    review_required = Column(Boolean, default=False, nullable=False)
    review_status = Column(SAEnum(ReviewStatus), nullable=False, default=ReviewStatus.pending, index=True)
    notes = Column(Text, default="")
    created_by = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    asset = relationship("Asset", back_populates="change_requests")
    asset_version = relationship("AssetVersion", back_populates="change_requests")

@mark_tenant_aware
class IntegrationConnection(Base):
    __tablename__ = "integration_connections"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    provider = Column(SAEnum(IntegrationProvider), nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    base_url = Column(String, default="")
    auth_ref = Column(String, default="")
    config = Column(JSON, default=dict)
    enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

@mark_tenant_aware
class ExternalReference(Base):
    __tablename__ = "external_references"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    provider = Column(SAEnum(IntegrationProvider), nullable=False, index=True)
    external_type = Column(String, nullable=False, index=True)
    external_id = Column(String, nullable=False, index=True)
    url = Column(String, default="")
    payload = Column(JSON, default=dict)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=True, index=True)
    change_request_id = Column(Integer, ForeignKey("change_requests.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    asset = relationship("Asset", back_populates="external_references")

@mark_tenant_aware
class IntegrationEvent(Base):
    __tablename__ = "integration_events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    provider = Column(SAEnum(IntegrationProvider), nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    external_id = Column(String, default="", index=True)
    delivery_id = Column(String, default="", index=True)
    status = Column(SAEnum(IntegrationEventStatus), default=IntegrationEventStatus.received, nullable=False, index=True)
    payload = Column(JSON, default=dict)
    error = Column(Text, default="")
    received_at = Column(DateTime, default=utcnow, nullable=False)
    processed_at = Column(DateTime, nullable=True)

@mark_tenant_aware
class TelemetryOutbox(Base):
    __tablename__ = "telemetry_outbox"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    provider = Column(SAEnum(IntegrationProvider), nullable=False, index=True)
    event_type = Column(String, nullable=False, index=True)
    payload = Column(JSON, default=dict)
    status = Column(SAEnum(TelemetryStatus), default=TelemetryStatus.pending, nullable=False, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, default="")
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    sent_at = Column(DateTime, nullable=True)

@mark_tenant_aware
class ObservabilityIncident(Base):
    __tablename__ = "observability_incidents"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    provider = Column(SAEnum(IntegrationProvider), default=IntegrationProvider.datadog, nullable=False, index=True)
    monitor_id = Column(String, default="", index=True)
    title = Column(String, nullable=False)
    severity = Column(SAEnum(IncidentSeverity), default=IncidentSeverity.warn, nullable=False, index=True)
    status = Column(SAEnum(IncidentStatus), default=IncidentStatus.open, nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=True, index=True)
    change_request_id = Column(Integer, ForeignKey("change_requests.id"), nullable=True, index=True)
    tags = Column(JSON, default=list)
    payload = Column(JSON, default=dict)
    started_at = Column(DateTime, default=utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

class User(Base):
    """全局用户表（跨租户）。"""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False, index=True)
    display_name = Column(String, default="")
    email = Column(String, default="", index=True)
    roles = Column(JSON, default=list)  # 全局角色（如 admin）
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class UserTenantMembership(Base):
    """一个 user 可属于多个 tenant，每个 tenant 内角色独立。"""
    __tablename__ = "user_tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_user_tenant"),)
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    tenant_id = Column(String(64), nullable=False, index=True)
    roles = Column(JSON, default=list, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)

class Team(Base):
    __tablename__ = "teams"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)
    memberships = relationship("TeamMembership", back_populates="team", cascade="all, delete-orphan")

class TeamMembership(Base):
    __tablename__ = "team_memberships"
    id = Column(Integer, primary_key=True, index=True)
    team_id = Column(Integer, ForeignKey("teams.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    role = Column(SAEnum(RoleName), default=RoleName.contributor, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    team = relationship("Team", back_populates="memberships")
    user = relationship("User")

@mark_tenant_aware
class ReviewRequest(Base):
    __tablename__ = "review_requests"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    change_request_id = Column(Integer, ForeignKey("change_requests.id"), nullable=True, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=True, index=True)
    required_approvals = Column(Integer, default=1, nullable=False)
    status = Column(SAEnum(ReviewRequestStatus), default=ReviewRequestStatus.review_pending, nullable=False, index=True)
    reason = Column(Text, default="")
    created_by = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    assignments = relationship("ReviewAssignment", back_populates="review_request", cascade="all, delete-orphan")

@mark_tenant_aware
class ReviewAssignment(Base):
    __tablename__ = "review_assignments"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    review_request_id = Column(Integer, ForeignKey("review_requests.id"), nullable=False, index=True)
    reviewer = Column(String, nullable=False, index=True)
    role = Column(SAEnum(RoleName), default=RoleName.approver, nullable=False, index=True)
    decision = Column(SAEnum(ReviewDecision), default=ReviewDecision.pending, nullable=False, index=True)
    notes = Column(Text, default="")
    assigned_at = Column(DateTime, default=utcnow, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    review_request = relationship("ReviewRequest", back_populates="assignments")

@mark_tenant_aware
class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    parent_type = Column(String, nullable=False, index=True)
    parent_id = Column(Integer, nullable=False, index=True)
    body = Column(Text, nullable=False)
    created_by = Column(String, nullable=False, index=True)
    is_blocking = Column(Boolean, default=False, nullable=False)
    status = Column(SAEnum(CommentStatus), default=CommentStatus.open, nullable=False, index=True)
    idempotency_key = Column(String, nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    resolved_at = Column(DateTime, nullable=True)

@mark_tenant_aware
class ActivityEvent(Base):
    """审计事件（含 hash chain）。"""
    __tablename__ = "activity_events"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    actor = Column(String, default="", index=True)
    action = Column(String, nullable=False, index=True)
    entity_type = Column(String, nullable=False, index=True)
    entity_id = Column(String, default="", index=True)
    summary = Column(Text, default="")
    payload = Column(JSON, default=dict)
    prev_hash = Column(String(64), nullable=True, index=True)
    hash_value = Column(String(64), nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

@mark_tenant_aware
class CollaborationTask(Base):
    __tablename__ = "collaboration_tasks"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    title = Column(String, nullable=False)
    status = Column(SAEnum(TaskStatus), default=TaskStatus.open, nullable=False, index=True)
    priority = Column(SAEnum(TaskPriority), default=TaskPriority.medium, nullable=False, index=True)
    assignee = Column(String, default="", index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    change_request_id = Column(Integer, ForeignKey("change_requests.id"), nullable=True, index=True)
    incident_id = Column(Integer, ForeignKey("observability_incidents.id"), nullable=True, index=True)
    payload = Column(JSON, default=dict)
    created_by = Column(String, nullable=False, index=True)
    due_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

@mark_tenant_aware
class EditLock(Base):
    __tablename__ = "edit_locks"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    resource_type = Column(String, nullable=False, index=True)
    resource_id = Column(String, nullable=False, index=True)
    locked_by = Column(String, nullable=False, index=True)
    status = Column(SAEnum(LockStatus), default=LockStatus.active, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)

@mark_tenant_aware
class EvaluationSuite(Base):
    __tablename__ = "evaluation_suites"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    name = Column(String, unique=True, nullable=False, index=True)
    description = Column(Text, default="")
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    pass_threshold = Column(Integer, default=80, nullable=False)
    block_on_fail = Column(Boolean, default=True, nullable=False)
    cases = Column(JSON, default=list)
    status = Column(SAEnum(EvalSuiteStatus), default=EvalSuiteStatus.active, nullable=False, index=True)
    created_by = Column(String, nullable=False, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

@mark_tenant_aware
class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    suite_id = Column(Integer, ForeignKey("evaluation_suites.id"), nullable=False, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=True, index=True)
    change_request_id = Column(Integer, ForeignKey("change_requests.id"), nullable=True, index=True)
    status = Column(SAEnum(EvalRunStatus), default=EvalRunStatus.pending, nullable=False, index=True)
    score = Column(Integer, default=0, nullable=False)
    passed_count = Column(Integer, default=0, nullable=False)
    failed_count = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    total_count = Column(Integer, default=0, nullable=False)
    results = Column(JSON, default=list)
    triggered_by = Column(String, default="", index=True)
    mode = Column(String, default="stub", nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    finished_at = Column(DateTime, nullable=True)

@mark_tenant_aware
class WebhookSubscription(Base):
    """Outbound webhook subscription, per tenant."""
    __tablename__ = "webhook_subscriptions"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    name = Column(String, nullable=False)
    target_url = Column(String, nullable=False)
    secret = Column(String, default="")            # for HMAC signing (optional)
    event_filters = Column(JSON, default=list)     # ["*"] or ["change.*", "gate.blocked"]
    enabled = Column(Boolean, default=True, nullable=False)
    max_attempts = Column(Integer, default=6, nullable=False)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

@mark_tenant_aware
class WebhookDelivery(Base):
    """Per-attempt delivery record."""
    __tablename__ = "webhook_deliveries"
    id = Column(Integer, primary_key=True, index=True)
    tenant_id = _tenant_col()
    subscription_id = Column(Integer, ForeignKey("webhook_subscriptions.id"),
                              nullable=False, index=True)
    delivery_uuid = Column(String, unique=True, index=True, nullable=False)
    event_type = Column(String, nullable=False, index=True)
    entity_type = Column(String, default="")
    entity_id = Column(String, default="")
    payload = Column(JSON, default=dict)
    status = Column(String, default="pending", index=True)  # pending|delivered|failed|dead
    attempts = Column(Integer, default=0, nullable=False)
    response_code = Column(Integer, nullable=True)
    response_body = Column(Text, default="")
    last_error = Column(Text, default="")
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    delivered_at = Column(DateTime, nullable=True)
# ============== Auto create (dev) ==============
if os.getenv("ECHO_AUTO_CREATE_TABLES", "1").lower() in ("1", "true", "yes"):
    Base.metadata.create_all(bind=engine)

install_tenancy_hooks(Base)

# =====================================================
# 4. Pydantic schemas
# =====================================================
class AssetCreate(BaseModel):
    model_config = {"protected_namespaces": ()}
    name: str
    asset_type: AssetType
    description: str = ""
    owner: str
    namespace: str = "default"
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

class AssetUpdate(BaseModel):
    model_config = {"protected_namespaces": ()}
    description: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None

class AssetVersionCreate(BaseModel):
    version_tag: str
    system_prompt: str = ""
    context_template: str = ""
    workflow_spec: Dict[str, Any] = Field(default_factory=dict)
    examples: List[Any] = Field(default_factory=list)
    guardrails: List[Any] = Field(default_factory=list)
    variables_schema: Dict[str, Any] = Field(default_factory=dict)
    change_summary: str = ""
    created_by: str
    set_active: bool = True

class ExecutionLogCreate(BaseModel):
    asset_version_id: int
    request_id: Optional[str] = None
    model_name: str = ""
    input_variables: Dict[str, Any] = Field(default_factory=dict)
    llm_output: str = ""
    latency_ms: int = 0
    token_usage: int = 0
    trace_id: str = ""
    span_id: str = ""
    service: str = ""
    env: str = ""
    created_by: str = ""

class ChangeRequestCreate(BaseModel):
    commit_sha: str
    pr_id: Optional[str] = None
    asset_id: Optional[int] = None
    asset_version_id: Optional[int] = None
    risk_level: RiskLevel = RiskLevel.low
    impact_scope: List[str] = Field(default_factory=list)
    review_required: bool = False
    review_status: ReviewStatus = ReviewStatus.pending
    notes: str = ""
    created_by: str

class GateCheckRequest(BaseModel):
    commit_sha: str
    is_ai_related: bool = False
    provider: Optional[IntegrationProvider] = None
    project_id: Optional[str] = None
    mr_iid: Optional[str] = None
    pipeline_id: Optional[str] = None

class RuntimeGuardrailCheckRequest(BaseModel):
    asset_version_id: Optional[int] = None
    asset_name: Optional[str] = None
    tool_name: str = ""
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    input_variables: Dict[str, Any] = Field(default_factory=dict)
    actor: str = ""

class IntegrationConnectionCreate(BaseModel):
    provider: IntegrationProvider
    name: str
    base_url: str = ""
    auth_ref: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

class GitLabImportRequest(BaseModel):
    project_id: str
    merge_request_iid: str
    created_by: str = "gitlab-import"
    base_url: Optional[str] = None
    mock: Optional[Dict[str, Any]] = None

class GitLabStatusRequest(BaseModel):
    project_id: str
    commit_sha: str
    status: str
    name: str = "echo/agent-governance"
    target_url: str = ""
    description: str = ""
    base_url: Optional[str] = None
    dry_run: bool = False

class ObservabilityEventCreate(BaseModel):
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    send_now: bool = False

class DatadogWebhookRequest(BaseModel):
    title: str = "Datadog monitor event"
    alert_type: str = "warning"
    monitor_id: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)

class UserCreate(BaseModel):
    username: str
    display_name: str = ""
    email: str = ""
    roles: List[RoleName] = Field(default_factory=lambda: [RoleName.viewer])

class TeamCreate(BaseModel):
    name: str
    description: str = ""

class TeamMembershipCreate(BaseModel):
    team_id: int
    username: str
    role: RoleName = RoleName.contributor

class ReviewRequestCreate(BaseModel):
    change_request_id: Optional[int] = None
    asset_version_id: Optional[int] = None
    required_approvals: int = 1
    reviewers: List[str] = Field(default_factory=list)
    reason: str = ""
    created_by: str = ""

class ReviewDecisionCreate(BaseModel):
    decision: ReviewDecision
    notes: str = ""

class CommentCreate(BaseModel):
    parent_type: str
    parent_id: int
    body: str
    is_blocking: bool = False
    created_by: str = ""
    idempotency_key: Optional[str] = None

class CollaborationTaskCreate(BaseModel):
    title: str
    priority: TaskPriority = TaskPriority.medium
    assignee: str = ""
    asset_id: Optional[int] = None
    change_request_id: Optional[int] = None
    incident_id: Optional[int] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_by: str = ""

class CollaborationTaskUpdate(BaseModel):
    status: Optional[TaskStatus] = None
    assignee: Optional[str] = None
    priority: Optional[TaskPriority] = None

class EditLockRequest(BaseModel):
    resource_type: str
    resource_id: str
    ttl_seconds: int = Field(default=900, ge=30, le=7200)
    locked_by: str = ""

class EvaluationAssertion(BaseModel):
    type: str
    value: Any = None
    field: str = "llm_output"
    case_sensitive: bool = False

class EvaluationCase(BaseModel):
    name: str
    input_variables: Dict[str, Any] = Field(default_factory=dict)
    tool_name: str = ""
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    expected_output: str = ""
    assertions: List[EvaluationAssertion] = Field(default_factory=list)
    weight: int = Field(default=1, ge=1)
    latency_ms: int = 0

class EvaluationSuiteCreate(BaseModel):
    name: str
    description: str = ""
    asset_id: Optional[int] = None
    pass_threshold: int = Field(default=80, ge=0, le=100)
    block_on_fail: bool = True
    cases: List[EvaluationCase] = Field(default_factory=list)
    created_by: str = ""

class EvaluationSuiteUpdate(BaseModel):
    description: Optional[str] = None
    pass_threshold: Optional[int] = Field(default=None, ge=0, le=100)
    block_on_fail: Optional[bool] = None
    cases: Optional[List[EvaluationCase]] = None
    status: Optional[EvalSuiteStatus] = None

class EvaluationRunRequest(BaseModel):
    suite_id: int
    asset_version_id: int
    change_request_id: Optional[int] = None
    mock_outputs: Optional[Dict[str, str]] = None
    triggered_by: str = ""

class DemoTokenRequest(BaseModel):
    username: str
    tenant_id: str = "default"
    roles: List[str] = Field(default_factory=lambda: ["viewer"])
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)

class WebhookSubscriptionCreate(BaseModel):
    name: str
    target_url: str
    secret: str = ""
    event_filters: List[str] = Field(default_factory=lambda: ["*"])
    enabled: bool = True
    max_attempts: int = Field(default=6, ge=1, le=20)

class WebhookSubscriptionUpdate(BaseModel):
    name: Optional[str] = None
    target_url: Optional[str] = None
    secret: Optional[str] = None
    event_filters: Optional[List[str]] = None
    enabled: Optional[bool] = None
    max_attempts: Optional[int] = Field(default=None, ge=1, le=20)

class WebhookTestRequest(BaseModel):
    event_type: str = "echo.test"
    sample_payload: Dict[str, Any] = Field(default_factory=lambda: {"hello": "world"})
# =====================================================
# 5. App + lifespan
# =====================================================
_background_tasks: List[asyncio.Task] = []

async def _telemetry_flush_loop() -> None:
    while True:
        try:
            await asyncio.sleep(TELEMETRY_FLUSH_INTERVAL)
            with SessionLocal() as db:
                now = utcnow()
                items = (
                    db.query(TelemetryOutbox)
                    .filter(TelemetryOutbox.status.in_([TelemetryStatus.pending, TelemetryStatus.failed]))
                    .filter((TelemetryOutbox.next_attempt_at.is_(None)) | (TelemetryOutbox.next_attempt_at <= now))
                    .order_by(TelemetryOutbox.id.asc())
                    .limit(TELEMETRY_BATCH_SIZE)
                    .all()
                )
                if items:
                    for item in items:
                        item.attempts += 1
                        await asyncio.to_thread(_flush_telemetry_event, item)
                    db.commit()
                    logger.info("telemetry_flush.processed", count=len(items))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("telemetry_flush.error", error=str(exc))

async def _lock_cleanup_loop() -> None:
    while True:
        try:
            await asyncio.sleep(LOCK_CLEANUP_INTERVAL)
            with SessionLocal() as db:
                now = utcnow()
                count = (
                    db.query(EditLock)
                    .filter(EditLock.status == LockStatus.active, EditLock.expires_at <= now)
                    .update({EditLock.status: LockStatus.expired}, synchronize_session=False)
                )
                db.commit()
                if count:
                    logger.info("lock_cleanup.expired", count=int(count))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("lock_cleanup.error", error=str(exc))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 初始化可选组件
    metrics.setup_metrics()
    telemetry.setup_tracing(app=app, engine=engine)

    if os.getenv("ECHO_DISABLE_WORKERS", "").lower() not in ("1", "true", "yes"):
        _background_tasks.append(asyncio.create_task(_telemetry_flush_loop()))
        _background_tasks.append(asyncio.create_task(_lock_cleanup_loop()))
        logger.info("workers.started", telemetry_interval=TELEMETRY_FLUSH_INTERVAL,
                    lock_interval=LOCK_CLEANUP_INTERVAL)
    try:
        yield
    finally:
        for task in _background_tasks:
            task.cancel()
        for task in _background_tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        _background_tasks.clear()

app = FastAPI(title="Echo Agent Governance API", version="2.4.0", lifespan=lifespan)

# ============== Middleware ==============
@app.middleware("http")
async def _request_context_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    token_r = request_id_var.set(rid)
    started = time.perf_counter()
    status_code = 500
    try:
        with metrics.time_request(request.method, request.url.path):
            response = await call_next(request)
        status_code = response.status_code
    except HTTPException as exc:
        status_code = exc.status_code
        raise
    except Exception as exc:
        logger.exception("request.failed", path=request.url.path, method=request.method, error=str(exc))
        raise
    finally:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        tenant = current_tenant.get() or "-"
        metrics.inc_request(request.method, request.url.path, status_code, tenant)
        logger.info("request.completed", path=request.url.path, method=request.method,
                    status_code=status_code, duration_ms=elapsed_ms)
        request_id_var.reset(token_r)
    response.headers["X-Request-ID"] = rid
    trace_id = telemetry.get_trace_id()
    if trace_id:
        response.headers["X-Trace-ID"] = trace_id
    return response

_cors_env = os.getenv("ECHO_CORS_ORIGINS", "*")
_cors_origins = [o.strip() for o in _cors_env.split(",") if o.strip()] if _cors_env != "*" else ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# =====================================================
# 6. Helpers
# =====================================================
def _enum_value(value: Any) -> Any:
    return value.value if hasattr(value, "value") else value

def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value

def _redact_auth_ref(auth_ref: str) -> str:
    if not auth_ref:
        return ""
    if len(auth_ref) <= 6:
        return "***"
    return f"{auth_ref[:3]}***{auth_ref[-3:]}"

def _gitlab_allowed_hosts() -> List[str]:
    env = os.getenv("ECHO_GITLAB_ALLOWED_HOSTS", "gitlab.com")
    return [h.strip().lower() for h in env.split(",") if h.strip()]

def _base_gitlab_url(override: Optional[str] = None) -> str:
    raw = (override or os.getenv("GITLAB_BASE_URL") or "https://gitlab.com").rstrip("/")
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    if host and host not in _gitlab_allowed_hosts():
        raise HTTPException(status_code=400, detail=f"GitLab host '{host}' not in allowlist")
    return raw

def _gitlab_token() -> Optional[str]:
    return os.getenv("GITLAB_TOKEN")

def _datadog_site() -> str:
    return os.getenv("DD_SITE", "datadoghq.com").strip()

def _datadog_api_key() -> Optional[str]:
    return os.getenv("DD_API_KEY")

def _activity(
    db: Session, action: str, entity_type: str, entity_id: Any = "",
    actor: str = "", summary: str = "", payload: Optional[Dict[str, Any]] = None,
) -> ActivityEvent:
    """写入活动事件，自动加 hash chain（M7）。"""
    now = utcnow()
    actor_value = actor or current_actor.get() or "system"
    payload_safe = _json_safe(payload or {})

    event = ActivityEvent(
        actor=actor_value,
        action=action,
        entity_type=entity_type,
        entity_id=str(entity_id or ""),
        summary=summary,
        payload=payload_safe,
        created_at=now,
    )

    if hashchain.is_enabled():
        # 找当前租户最近一条事件作为 prev
        tid = current_tenant.get() or "default"
        prev = (
            db.query(ActivityEvent)
            .filter(ActivityEvent.tenant_id == tid)
            .order_by(ActivityEvent.id.desc())
            .first()
        )
        prev_hash = prev.hash_value if prev else None
        record = hashchain.build_record(
            actor=actor_value, action=action, entity_type=entity_type,
            entity_id=str(entity_id or ""), summary=summary,
            payload=payload_safe, created_at_iso=now.isoformat(),
        )
        event.prev_hash = prev_hash
        event.hash_value = hashchain.compute_hash(prev_hash, record)

    db.add(event)
    return event

def _enqueue_telemetry(
    db: Session, event_type: str, payload: Dict[str, Any],
    provider: IntegrationProvider = IntegrationProvider.datadog,
) -> TelemetryOutbox:
    event = TelemetryOutbox(
        provider=provider, event_type=event_type, payload=_json_safe(payload),
        status=TelemetryStatus.pending, next_attempt_at=utcnow(),
    )
    db.add(event)
    return event

def _flush_telemetry_event(event: TelemetryOutbox) -> None:
    if event.provider != IntegrationProvider.datadog:
        event.status = TelemetryStatus.skipped
        event.last_error = "No sender configured for provider."
        return
    api_key = _datadog_api_key()
    if not api_key:
        event.status = TelemetryStatus.skipped
        event.last_error = "DD_API_KEY not configured; retained as evidence."
        event.sent_at = utcnow()
        return
    site = _datadog_site()
    headers = {"DD-API-KEY": api_key, "Content-Type": "application/json"}
    payload = event.payload or {}
    try:
        if event.event_type.endswith(".metric") or payload.get("series"):
            url = f"https://api.{site}/api/v2/series"
        else:
            url = f"https://http-intake.logs.{site}/api/v2/logs"
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        event.status = TelemetryStatus.sent
        event.sent_at = utcnow()
        event.last_error = ""
    except requests.RequestException as exc:
        event.status = TelemetryStatus.failed
        event.last_error = str(exc)
        delay = min(60 * (2 ** min(event.attempts, 6)), 3600)
        event.next_attempt_at = utcnow() + timedelta(seconds=delay)

def _event_tags(asset=None, version=None, change=None, extra=None) -> List[str]:
    tags = ["service:echo-agent-governance"]
    if asset:
        tags.extend([f"asset_name:{asset.name}", f"asset_type:{asset.asset_type.value}"])
        if asset.namespace and asset.namespace != "default":
            tags.append(f"namespace:{asset.namespace}")
        tags.append(f"tenant:{asset.tenant_id}")
    if version:
        tags.append(f"version_tag:{version.version_tag}")
    if change:
        tags.extend([f"commit_sha:{change.commit_sha}", f"risk_level:{change.risk_level.value}"])
        if change.pr_id:
            tags.append(f"pr_id:{change.pr_id}")
    tags.extend(extra or [])
    return tags

def _datadog_log_payload(event_type, message, payload, tags=None):
    return {
        "ddsource": "echo", "service": "echo-agent-governance",
        "message": message, "event_type": event_type,
        "status": payload.get("status") or payload.get("decision") or "info",
        "tags": ",".join(tags or []), **payload,
    }

def _datadog_metric_payload(metric, value, tags=None):
    return {
        "series": [{
            "metric": metric, "type": 1,
            "points": [{"timestamp": int(utcnow().timestamp()), "value": value}],
            "resources": [{"name": "echo-agent-governance", "type": "service"}],
            "tags": tags or [],
        }]
    }

def _gitlab_headers() -> Dict[str, str]:
    token = _gitlab_token()
    return {"PRIVATE-TOKEN": token} if token else {}

def _gitlab_api_get(path: str, base_url: Optional[str] = None) -> Dict[str, Any]:
    if not _gitlab_token():
        raise HTTPException(status_code=503, detail="GITLAB_TOKEN not configured")
    url = f"{_base_gitlab_url(base_url)}/api/v4{path}"
    r = requests.get(url, headers=_gitlab_headers(), timeout=15)
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

def _gitlab_api_post(path: str, payload: Dict[str, Any], base_url: Optional[str] = None) -> Dict[str, Any]:
    if not _gitlab_token():
        raise HTTPException(status_code=503, detail="GITLAB_TOKEN not configured")
    url = f"{_base_gitlab_url(base_url)}/api/v4{path}"
    r = requests.post(url, headers=_gitlab_headers(), json=payload, timeout=15)
    if not r.ok:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

def _normalize_tags(raw):
    if raw is None:
        return []
    if isinstance(raw, str):
        return [p.strip() for p in raw.split(",") if p.strip()] if "," in raw else [raw]
    if isinstance(raw, list):
        return [str(t) for t in raw if str(t)]
    return [str(raw)]

def _tag_value(tags, key):
    prefix = f"{key}:"
    for t in tags:
        if t.startswith(prefix):
            return t[len(prefix):]
    return None

def _match_asset_by_paths(db: Session, paths: List[str]) -> Optional[Asset]:
    if not paths:
        return None
    assets = filter_by_tenant(db.query(Asset), Asset).all()
    for asset in assets:
        for rule in (asset.metadata_ or {}).get("path_rules", []):
            prefix = rule.get("prefix") if isinstance(rule, dict) else str(rule)
            if prefix and any(p.startswith(prefix) for p in paths):
                return asset
    return None

def _has_blocking_comments(db, parent_type, parent_id):
    return (
        filter_by_tenant(db.query(Comment.id), Comment)
        .filter(Comment.parent_type == parent_type, Comment.parent_id == parent_id,
                Comment.is_blocking.is_(True), Comment.status == CommentStatus.open)
        .first() is not None
    )

def _ensure_review_request(db, change, asset_version_id, required_approvals, created_by, reason, reviewers=None):
    q = filter_by_tenant(db.query(ReviewRequest), ReviewRequest)
    if change:
        q = q.filter(ReviewRequest.change_request_id == change.id)
    elif asset_version_id is not None:
        q = q.filter(ReviewRequest.asset_version_id == asset_version_id)
    existing = q.first()
    if existing:
        return existing

    review = ReviewRequest(
        change_request_id=change.id if change else None,
        asset_version_id=asset_version_id,
        required_approvals=required_approvals,
        status=ReviewRequestStatus.review_pending,
        reason=reason, created_by=created_by,
    )
    db.add(review)
    db.flush()
    for reviewer in reviewers or []:
        db.add(ReviewAssignment(review_request_id=review.id, reviewer=reviewer, role=RoleName.approver))
    return review

def _update_review_status(db, review):
    if _has_blocking_comments(db, "review_request", review.id):
        review.status = ReviewRequestStatus.review_pending
        return review
    assignments = list(review.assignments or [])
    if any(a.decision in (ReviewDecision.rejected, ReviewDecision.changes_requested) for a in assignments):
        review.status = ReviewRequestStatus.rejected
        return review
    approved = sum(1 for a in assignments if a.decision == ReviewDecision.approved)
    review.status = ReviewRequestStatus.approved if approved >= review.required_approvals else ReviewRequestStatus.review_pending
    return review

def _paginated(items, total, limit, offset):
    return {"items": items, "total": total, "limit": limit, "offset": offset}

def _apply_pagination(query, limit, offset):
    total = query.with_entities(func.count()).order_by(None).scalar() or 0
    items = query.limit(limit).offset(offset).all()
    return items, int(total)

# ============== Serializers ==============
def asset_to_dict(a: Asset) -> Dict[str, Any]:
    return {"id": a.id, "tenant_id": a.tenant_id, "namespace": a.namespace, "name": a.name,
            "asset_type": _enum_value(a.asset_type), "description": a.description, "owner": a.owner,
            "tags": a.tags or [], "metadata": a.metadata_ or {},
            "created_at": a.created_at, "updated_at": a.updated_at}

def version_to_dict(v: AssetVersion) -> Dict[str, Any]:
    return {"id": v.id, "tenant_id": v.tenant_id, "asset_id": v.asset_id,
            "version_tag": v.version_tag, "status": _enum_value(v.status),
            "system_prompt": v.system_prompt, "context_template": v.context_template,
            "workflow_spec": v.workflow_spec or {}, "examples": v.examples or [],
            "guardrails": v.guardrails or [], "variables_schema": v.variables_schema or {},
            "change_summary": v.change_summary, "created_by": v.created_by,
            "created_at": v.created_at, "updated_at": v.updated_at}

def change_request_to_dict(c: ChangeRequest) -> Dict[str, Any]:
    return {"id": c.id, "tenant_id": c.tenant_id, "commit_sha": c.commit_sha, "pr_id": c.pr_id,
            "asset_id": c.asset_id, "asset_version_id": c.asset_version_id,
            "risk_level": _enum_value(c.risk_level), "impact_scope": c.impact_scope or [],
            "review_required": c.review_required, "review_status": _enum_value(c.review_status),
            "notes": c.notes, "created_by": c.created_by,
            "created_at": c.created_at, "updated_at": c.updated_at}

def integration_connection_to_dict(c: IntegrationConnection):
    return {"id": c.id, "tenant_id": c.tenant_id, "provider": _enum_value(c.provider),
            "name": c.name, "base_url": c.base_url, "auth_ref": _redact_auth_ref(c.auth_ref),
            "config": c.config or {}, "enabled": c.enabled,
            "created_at": c.created_at, "updated_at": c.updated_at}

def integration_event_to_dict(e):
    return {"id": e.id, "tenant_id": e.tenant_id, "provider": _enum_value(e.provider),
            "event_type": e.event_type, "external_id": e.external_id, "delivery_id": e.delivery_id,
            "status": _enum_value(e.status), "payload": e.payload or {}, "error": e.error,
            "received_at": e.received_at, "processed_at": e.processed_at}

def telemetry_to_dict(e):
    return {"id": e.id, "tenant_id": e.tenant_id, "provider": _enum_value(e.provider),
            "event_type": e.event_type, "payload": e.payload or {}, "status": _enum_value(e.status),
            "attempts": e.attempts, "last_error": e.last_error,
            "next_attempt_at": e.next_attempt_at, "created_at": e.created_at, "sent_at": e.sent_at}

def incident_to_dict(i):
    return {"id": i.id, "tenant_id": i.tenant_id, "provider": _enum_value(i.provider),
            "monitor_id": i.monitor_id, "title": i.title,
            "severity": _enum_value(i.severity), "status": _enum_value(i.status),
            "asset_id": i.asset_id, "asset_version_id": i.asset_version_id,
            "change_request_id": i.change_request_id, "tags": i.tags or [], "payload": i.payload or {},
            "started_at": i.started_at, "resolved_at": i.resolved_at,
            "created_at": i.created_at, "updated_at": i.updated_at}

def user_to_dict(u):
    return {"id": u.id, "username": u.username, "display_name": u.display_name,
            "email": u.email, "roles": u.roles or [], "active": u.active, "created_at": u.created_at}

def team_to_dict(t):
    return {"id": t.id, "name": t.name, "description": t.description, "created_at": t.created_at}

def review_request_to_dict(r):
    assignments = sorted(r.assignments or [], key=lambda a: a.id)
    approved = sum(1 for a in assignments if a.decision == ReviewDecision.approved)
    return {"id": r.id, "tenant_id": r.tenant_id, "change_request_id": r.change_request_id,
            "asset_version_id": r.asset_version_id, "required_approvals": r.required_approvals,
            "approved_count": approved, "status": _enum_value(r.status),
            "reason": r.reason, "created_by": r.created_by,
            "assignments": [{"id": a.id, "reviewer": a.reviewer, "role": _enum_value(a.role),
                             "decision": _enum_value(a.decision), "notes": a.notes,
                             "assigned_at": a.assigned_at, "decided_at": a.decided_at}
                            for a in assignments],
            "created_at": r.created_at, "updated_at": r.updated_at}

def comment_to_dict(c):
    return {"id": c.id, "tenant_id": c.tenant_id, "parent_type": c.parent_type,
            "parent_id": c.parent_id, "body": c.body, "created_by": c.created_by,
            "is_blocking": c.is_blocking, "status": _enum_value(c.status),
            "created_at": c.created_at, "resolved_at": c.resolved_at}

def activity_to_dict(e):
    return {"id": e.id, "tenant_id": e.tenant_id, "actor": e.actor, "action": e.action,
            "entity_type": e.entity_type, "entity_id": e.entity_id,
            "summary": e.summary, "payload": e.payload or {},
            "prev_hash": e.prev_hash, "hash": e.hash_value,
            "created_at": e.created_at}

def task_to_dict(t):
    return {"id": t.id, "tenant_id": t.tenant_id, "title": t.title,
            "status": _enum_value(t.status), "priority": _enum_value(t.priority),
            "assignee": t.assignee, "asset_id": t.asset_id,
            "change_request_id": t.change_request_id, "incident_id": t.incident_id,
            "payload": t.payload or {}, "created_by": t.created_by,
            "due_at": t.due_at, "created_at": t.created_at, "updated_at": t.updated_at}

def lock_to_dict(l):
    return {"id": l.id, "tenant_id": l.tenant_id, "resource_type": l.resource_type,
            "resource_id": l.resource_id, "locked_by": l.locked_by,
            "status": _enum_value(l.status), "expires_at": l.expires_at, "created_at": l.created_at}

def suite_to_dict(s):
    return {"id": s.id, "tenant_id": s.tenant_id, "name": s.name, "description": s.description,
            "asset_id": s.asset_id, "pass_threshold": s.pass_threshold, "block_on_fail": s.block_on_fail,
            "status": _enum_value(s.status), "cases": s.cases or [],
            "case_count": len(s.cases or []), "created_by": s.created_by,
            "created_at": s.created_at, "updated_at": s.updated_at}

def run_to_dict(r):
    return {"id": r.id, "tenant_id": r.tenant_id, "suite_id": r.suite_id,
            "asset_version_id": r.asset_version_id, "change_request_id": r.change_request_id,
            "status": _enum_value(r.status), "score": r.score,
            "passed_count": r.passed_count, "failed_count": r.failed_count,
            "error_count": r.error_count, "total_count": r.total_count,
            "results": r.results or [], "triggered_by": r.triggered_by, "mode": r.mode,
            "created_at": r.created_at, "finished_at": r.finished_at}

def _enum_counter(items):
    return {str(k.value if hasattr(k, "value") else k): v for k, v in Counter(items).items()}

# =====================================================
# 7. Runtime guardrail engine
# =====================================================
def _field_value(payload, field_path):
    roots = {"tool_args": payload.tool_args, "input_variables": payload.input_variables}
    if "." not in field_path:
        return roots.get(field_path)
    root_name, path = field_path.split(".", 1)
    current = roots.get(root_name)
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current

def _rule_matches_tool(rule, tool_name):
    tools = rule.get("tools")
    if tools is None and rule.get("tool") is not None:
        tools = [rule.get("tool")]
    if not tools:
        return True
    return tool_name in tools

def _raise_decision(current, candidate):
    rank = {"allow": 0, "review": 1, "block": 2}
    return candidate if rank[candidate] > rank[current] else current

def evaluate_runtime_guardrails(version, payload, asset=None):
    guardrails = version.guardrails or []
    decision = "allow"
    findings = []

    if not guardrails:
        default_decision = "review"
        reason = "No runtime guardrails configured."
        if asset:
            policy = ASSET_TYPE_GATE_POLICIES.get(asset.asset_type, {})
            default_decision = policy.get("default_runtime_decision", "review")
            reason = f"No guardrails; falling back to policy default for {asset.asset_type.value}."
        return {"decision": default_decision,
                "findings": [{"rule": "guardrail_coverage", "decision": default_decision, "reason": reason}]}

    for index, raw_rule in enumerate(guardrails, start=1):
        if isinstance(raw_rule, str):
            findings.append({"rule": f"manual_rule_{index}", "decision": "allow", "reason": raw_rule})
            continue
        if not isinstance(raw_rule, dict):
            findings.append({"rule": f"rule_{index}", "decision": "review", "reason": "Rule is not JSON object."})
            decision = _raise_decision(decision, "review")
            continue

        rule_type = str(raw_rule.get("type", "")).lower()
        rule_name = raw_rule.get("name") or rule_type or f"rule_{index}"
        severity = str(raw_rule.get("severity", "")).lower()
        fail_decision = "block" if severity == "high" else "review"

        if rule_type in {"blocked_tool", "deny_tool"} and _rule_matches_tool(raw_rule, payload.tool_name):
            decision = _raise_decision(decision, "block")
            findings.append({"rule": rule_name, "decision": "block",
                             "reason": raw_rule.get("reason") or f"Tool '{payload.tool_name}' is blocked."})
            continue
        if rule_type in {"requires_approval", "approval_required"} and _rule_matches_tool(raw_rule, payload.tool_name):
            decision = _raise_decision(decision, "review")
            findings.append({"rule": rule_name, "decision": "review",
                             "reason": raw_rule.get("reason") or f"Tool '{payload.tool_name}' requires approval."})
            continue
        if rule_type == "allowed_tools":
            tools = raw_rule.get("tools") or []
            if payload.tool_name not in tools:
                decision = _raise_decision(decision, "block")
                findings.append({"rule": rule_name, "decision": "block",
                                 "reason": f"Tool '{payload.tool_name}' not in allowlist."})
            continue
        if rule_type == "deny_keyword":
            field = raw_rule.get("field", "input_variables.user_message")
            value = str(_field_value(payload, field) or "").lower()
            keywords = [str(k).lower() for k in raw_rule.get("keywords", [])]
            matched = [k for k in keywords if k and k in value]
            if matched:
                decision = _raise_decision(decision, fail_decision)
                findings.append({"rule": rule_name, "decision": fail_decision,
                                 "reason": raw_rule.get("reason") or f"Denied keyword in {field}.",
                                 "matched": matched})
            continue
        if rule_type == "max_amount":
            field = raw_rule.get("field", "tool_args.amount")
            limit = raw_rule.get("limit")
            value = _field_value(payload, field)
            try:
                over = limit is not None and float(value) > float(limit)
            except (TypeError, ValueError):
                over = False
            if over:
                decision = _raise_decision(decision, fail_decision)
                findings.append({"rule": rule_name, "decision": fail_decision,
                                 "reason": raw_rule.get("reason") or f"{field} exceeds limit {limit}."})
            continue
        findings.append({"rule": rule_name, "decision": "allow",
                         "reason": raw_rule.get("reason") or "Rule registered for audit."})

    if not findings:
        findings.append({"rule": "runtime_check", "decision": "allow", "reason": "No rule triggered."})
    return {"decision": decision, "findings": findings}

# =====================================================
# 8. Evaluation engine
# =====================================================
def _eval_field_value(case_input, llm_output, field):
    if field == "llm_output":
        return llm_output
    if field.startswith("input_variables."):
        key_path = field.split(".", 1)[1]
        current = case_input
        for part in key_path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current
    return None

def _run_single_assertion(assertion, case_input, llm_output, latency_ms, guardrail_decision):
    a_type = str(assertion.get("type", "")).lower()
    expected = assertion.get("value")
    field = assertion.get("field") or "llm_output"
    case_sensitive = bool(assertion.get("case_sensitive", False))

    actual = _eval_field_value(case_input, llm_output, field)
    actual_str = "" if actual is None else str(actual)
    expected_str = "" if expected is None else str(expected)
    cmp_actual = actual_str if case_sensitive else actual_str.lower()
    cmp_expected = expected_str if case_sensitive else expected_str.lower()

    base = {"type": a_type, "field": field, "expected": expected, "actual": actual}
    try:
        if a_type == "contains":
            ok = cmp_expected in cmp_actual
            return {**base, "passed": ok, "reason": "substring match" if ok else "expected substring not found"}
        if a_type == "not_contains":
            ok = cmp_expected not in cmp_actual
            return {**base, "passed": ok, "reason": "absent as required" if ok else "forbidden substring present"}
        if a_type == "equals":
            ok = cmp_actual == cmp_expected
            return {**base, "passed": ok, "reason": "exact match" if ok else "values differ"}
        if a_type == "regex":
            ok = bool(_re.search(expected_str, actual_str, 0 if case_sensitive else _re.IGNORECASE))
            return {**base, "passed": ok, "reason": "regex matched" if ok else "regex did not match"}
        if a_type == "max_latency_ms":
            limit = int(expected) if expected is not None else 0
            ok = latency_ms <= limit
            return {**base, "passed": ok, "actual": latency_ms,
                    "reason": f"latency {latency_ms}ms vs limit {limit}ms"}
        if a_type == "guardrail_decision":
            ok = (guardrail_decision or "") == expected_str
            return {**base, "passed": ok, "actual": guardrail_decision,
                    "reason": f"guardrail decision={guardrail_decision}"}
        return {**base, "passed": False, "reason": f"unknown assertion type: {a_type}"}
    except Exception as exc:
        return {**base, "passed": False, "reason": f"assertion error: {exc}"}

def _execute_evaluation(db, suite, version, change, mock_outputs, triggered_by):
    mode = "mock" if mock_outputs else "stub"
    run = EvaluationRun(
        suite_id=suite.id, asset_version_id=version.id,
        change_request_id=change.id if change else None,
        status=EvalRunStatus.running, triggered_by=triggered_by or "system",
        total_count=len(suite.cases or []), mode=mode,
    )
    db.add(run)
    db.flush()

    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == version.asset_id).first()
    results, total_weight, earned_weight, passed, failed, errored = [], 0, 0, 0, 0, 0

    for case in suite.cases or []:
        case_name = case.get("name") or f"case_{len(results) + 1}"
        weight = max(int(case.get("weight") or 1), 1)
        total_weight += weight

        llm_output = mock_outputs.get(case_name, "") if mock_outputs else ""
        latency_ms = int(case.get("latency_ms") or 0)

        guardrail_decision = None
        try:
            cp = RuntimeGuardrailCheckRequest(
                asset_version_id=version.id, tool_name=case.get("tool_name") or "",
                tool_args=case.get("tool_args") or {},
                input_variables=case.get("input_variables") or {},
                actor=f"eval:{suite.name}",
            )
            gr = evaluate_runtime_guardrails(version, cp, asset=asset)
            guardrail_decision = gr["decision"]
        except Exception as exc:
            guardrail_decision = f"error:{exc}"

        assertion_results, case_passed = [], True
        has_assertions = bool(case.get("assertions"))
        for assertion in case.get("assertions") or []:
            r = _run_single_assertion(
                assertion if isinstance(assertion, dict) else assertion.dict(),
                case.get("input_variables") or {}, llm_output, latency_ms, guardrail_decision,
            )
            assertion_results.append(r)
            if not r["passed"]:
                case_passed = False
        if not has_assertions:
            case_passed = guardrail_decision != "block" and guardrail_decision is not None

        if case_passed:
            passed += 1
            earned_weight += weight
            decision = EvalCaseResult.pass_.value
            reason = "all assertions passed"
        else:
            failed += 1
            decision = EvalCaseResult.fail.value
            reason = "one or more assertions failed"

        results.append({"case_name": case_name, "decision": decision, "reason": reason,
                        "guardrail_decision": guardrail_decision, "llm_output": llm_output,
                        "mode": mode, "assertions": assertion_results,
                        "weight": weight, "latency_ms": latency_ms})

    score = int(round((earned_weight / total_weight) * 100)) if total_weight else 0
    run.results = results
    run.passed_count = passed
    run.failed_count = failed
    run.error_count = errored
    run.score = score
    run.finished_at = utcnow()
    run.status = EvalRunStatus.passed if score >= suite.pass_threshold else EvalRunStatus.failed

    tags = _event_tags(asset, version, change, [
        f"eval_suite:{suite.name}", f"eval_status:{run.status.value}",
        f"eval_score:{score}", f"eval_mode:{mode}",
    ])
    _activity(db, "evaluation.run_completed", "evaluation_run", run.id, triggered_by or "system",
              f"Suite {suite.name} scored {score}/{suite.pass_threshold} ({run.status.value}, mode={mode})",
              {"suite_id": suite.id, "score": score, "passed": passed, "failed": failed, "mode": mode})
    _enqueue_telemetry(db, "echo.eval.score.metric", _datadog_metric_payload("echo.eval.score", score, tags))
    _enqueue_telemetry(db, "echo.eval.run.log", _datadog_log_payload(
        "echo.eval.run.log", f"Echo evaluation {run.status.value}",
        {"suite": suite.name, "version_tag": version.version_tag, "score": score,
         "status": run.status.value, "mode": mode}, tags))
    metrics.observe_eval(run.status.value, mode, score, tenant=current_tenant.get() or "-")
    return run

# =====================================================
# 9. Diff
# =====================================================
def _stringify_for_diff(value):
    if isinstance(value, str):
        return value
    try:
        return _json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)

def _truncate_for_diff(value):
    if len(value) > DIFF_MAX_CHARS:
        return value[:DIFF_MAX_CHARS] + f"\n... [truncated {len(value) - DIFF_MAX_CHARS} chars]\n"
    return value

def _unified_diff(a, b, la, lb):
    a, b = _truncate_for_diff(a), _truncate_for_diff(b)
    lines = list(_difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True),
                                       fromfile=la, tofile=lb, n=3))
    if len(lines) > DIFF_MAX_LINES:
        lines = lines[:DIFF_MAX_LINES] + [f"\n... [truncated {len(lines) - DIFF_MAX_LINES} lines]\n"]
    return "".join(lines)

DIFF_FIELDS = ["system_prompt", "context_template", "workflow_spec", "examples",
               "guardrails", "variables_schema", "change_summary"]

# =====================================================
# 10. GitLab integration helpers
# =====================================================
def _upsert_gitlab_change(db, project_id, mr_iid, mr, changed_paths, created_by):
    labels = _normalize_tags(mr.get("labels"))
    title = mr.get("title") or ""
    real_sha = ((mr.get("sha") or "") or (mr.get("diff_refs") or {}).get("head_sha")
                or (mr.get("head_pipeline") or {}).get("sha"))
    if real_sha:
        commit_sha = real_sha
    else:
        ts = utcnow().strftime("%Y%m%d%H%M%S")
        commit_sha = f"gitlab-{project_id}-{mr_iid}-{ts}"

    pr_id = f"gitlab:{project_id}!{mr_iid}"
    asset = _match_asset_by_paths(db, changed_paths)
    ai_labels = {"ai", "agent", "prompt", "guardrail", "llm", "echo"}
    is_ai = bool(asset) or any(str(l).lower() in ai_labels for l in labels)
    risk = RiskLevel.high if is_ai else RiskLevel.low
    review_required = risk == RiskLevel.high
    if asset:
        policy = ASSET_TYPE_GATE_POLICIES.get(asset.asset_type, {})
        risk = policy.get("risk_level", risk)
        review_required = bool(policy.get("review_required", review_required))

    change = filter_by_tenant(db.query(ChangeRequest), ChangeRequest)\
        .filter(ChangeRequest.commit_sha == commit_sha).first()
    if not change and not real_sha:
        change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                  .filter(ChangeRequest.pr_id == pr_id)
                  .order_by(ChangeRequest.id.desc()).first())
    if not change:
        change = ChangeRequest(
            commit_sha=commit_sha, pr_id=pr_id,
            asset_id=asset.id if asset else None,
            risk_level=risk, impact_scope=changed_paths[:20] or labels,
            review_required=review_required,
            review_status=ReviewStatus.pending if review_required else ReviewStatus.skipped,
            notes=f"Imported from GitLab MR !{mr_iid}: {title}",
            created_by=created_by,
        )
        db.add(change)
        db.flush()
    else:
        change.pr_id = pr_id
        change.asset_id = asset.id if asset else change.asset_id
        change.impact_scope = changed_paths[:20] or change.impact_scope or labels
        change.risk_level = risk
        change.review_required = review_required
        change.notes = f"Imported from GitLab MR !{mr_iid}: {title}"

    required = 1
    if any("guardrail" in str(p).lower() for p in changed_paths) or any(str(l).lower() == "incident" for l in labels):
        required = 2
    if review_required:
        _ensure_review_request(db, change=change, asset_version_id=change.asset_version_id,
                                required_approvals=required, created_by=created_by, reason=change.notes)

    ext_id = f"{project_id}!{mr_iid}"
    existing_ref = (filter_by_tenant(db.query(ExternalReference), ExternalReference)
                    .filter(ExternalReference.provider == IntegrationProvider.gitlab,
                            ExternalReference.external_type == "merge_request",
                            ExternalReference.external_id == ext_id).first())
    ref_payload = {"project_id": project_id, "merge_request_iid": mr_iid, "labels": labels,
                   "changed_paths": changed_paths, "source_branch": mr.get("source_branch"),
                   "target_branch": mr.get("target_branch")}
    if existing_ref:
        existing_ref.payload = ref_payload
        existing_ref.asset_id = asset.id if asset else None
        existing_ref.change_request_id = change.id
        existing_ref.url = mr.get("web_url") or existing_ref.url
    else:
        db.add(ExternalReference(
            provider=IntegrationProvider.gitlab, external_type="merge_request",
            external_id=ext_id, url=mr.get("web_url") or "", payload=ref_payload,
            asset_id=asset.id if asset else None, change_request_id=change.id,
        ))

    _activity(db, "gitlab.mr_imported", "change_request", change.id, created_by,
              f"Imported GitLab MR !{mr_iid}",
              {"project_id": project_id, "merge_request_iid": mr_iid, "changed_paths": changed_paths})
    return change

# =====================================================
# 11. Auth endpoints
# =====================================================
@app.get("/api/auth/me", tags=["认证"])
def auth_me(_=Depends(ratelimit.check_rate_limit), context: Dict[str, Any] = Depends(authenticate)):
    return {**context, "auth_mode": os.getenv("ECHO_AUTH_MODE", "demo")}

@app.post("/api/auth/demo-token", tags=["认证"])
def auth_demo_token(payload: DemoTokenRequest):
    if os.getenv("ECHO_DEMO_TOKEN_ENABLED", "1").lower() not in ("1", "true", "yes"):
        raise HTTPException(status_code=404, detail="Disabled")
    token = issue_demo_token(username=payload.username, tenant_id=payload.tenant_id,
                              roles=payload.roles, ttl_seconds=payload.ttl_seconds)
    return {"token": token, "token_type": "Bearer", "expires_in": payload.ttl_seconds}

# =====================================================
# 12. Asset APIs
# =====================================================
@app.post("/api/assets/", tags=["资产管理"])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db),
                 _=Depends(ratelimit.check_rate_limit),
                 context: Dict[str, Any] = Depends(authenticate)):
    if (filter_by_tenant(db.query(Asset), Asset)
            .filter(Asset.namespace == payload.namespace, Asset.name == payload.name).first()):
        raise HTTPException(status_code=400, detail="Asset name already exists in this namespace")
    asset = Asset(namespace=payload.namespace, name=payload.name, asset_type=payload.asset_type,
                  description=payload.description, owner=payload.owner,
                  tags=payload.tags, metadata_=payload.metadata)
    db.add(asset)
    _activity(db, "asset.created", "asset", asset.name, context["actor"], f"Asset {payload.name} created")
    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)

@app.get("/api/assets/", tags=["资产管理"])
def list_assets(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                __=Depends(authenticate),
                q: Optional[str] = None, asset_type: Optional[AssetType] = None,
                owner: Optional[str] = None, namespace: Optional[str] = None,
                tag: Optional[str] = None,
                limit: int = Query(default=50, ge=1, le=500),
                offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(Asset), Asset)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Asset.name.ilike(like), Asset.description.ilike(like), Asset.owner.ilike(like)))
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if owner:
        query = query.filter(Asset.owner == owner)
    if namespace:
        query = query.filter(Asset.namespace == namespace)
    if tag:
        query = query.filter(Asset.tags.contains([tag]))
    query = query.order_by(Asset.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([asset_to_dict(a) for a in items], total, limit, offset)

@app.get("/api/assets/{asset_id}", tags=["资产管理"])
def get_asset(asset_id: int, db: Session = Depends(get_db),
              _=Depends(ratelimit.check_rate_limit), __=Depends(authenticate)):
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {**asset_to_dict(asset), "versions": [version_to_dict(v) for v in asset.versions]}

@app.patch("/api/assets/{asset_id}", tags=["资产管理"])
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db),
                 _=Depends(ratelimit.check_rate_limit),
                 context: Dict[str, Any] = Depends(authenticate)):
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if payload.description is not None:
        asset.description = payload.description
    if payload.owner is not None:
        asset.owner = payload.owner
    if payload.tags is not None:
        asset.tags = payload.tags
    if payload.metadata is not None:
        asset.metadata_ = payload.metadata
    _activity(db, "asset.updated", "asset", asset.id, context["actor"], f"Asset {asset.name} updated")
    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)

# =====================================================
# 13. Version APIs + Diff
# =====================================================
@app.post("/api/assets/{asset_id}/versions/", tags=["版本控制"])
def create_asset_version(asset_id: int, payload: AssetVersionCreate, db: Session = Depends(get_db),
                          _=Depends(ratelimit.check_rate_limit),
                          context: Dict[str, Any] = Depends(authenticate)):
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if (filter_by_tenant(db.query(AssetVersion), AssetVersion)
            .filter(AssetVersion.asset_id == asset_id, AssetVersion.version_tag == payload.version_tag).first()):
        raise HTTPException(status_code=400, detail="Version tag already exists for this asset")

    if payload.set_active:
        (filter_by_tenant(db.query(AssetVersion), AssetVersion)
         .filter(AssetVersion.asset_id == asset_id, AssetVersion.status == VersionStatus.active)
         .update({AssetVersion.status: VersionStatus.deprecated}))

    version = AssetVersion(
        asset_id=asset_id, version_tag=payload.version_tag,
        status=VersionStatus.active if payload.set_active else VersionStatus.draft,
        system_prompt=payload.system_prompt, context_template=payload.context_template,
        workflow_spec=payload.workflow_spec, examples=payload.examples,
        guardrails=payload.guardrails, variables_schema=payload.variables_schema,
        change_summary=payload.change_summary, created_by=payload.created_by,
    )
    db.add(version)
    _activity(db, "version.created", "asset_version", payload.version_tag, context["actor"], payload.change_summary)
    db.commit()
    db.refresh(version)
    return version_to_dict(version)

@app.get("/api/assets/{asset_id}/versions/", tags=["版本控制"])
def list_asset_versions(asset_id: int, db: Session = Depends(get_db),
                         _=Depends(ratelimit.check_rate_limit), __=Depends(authenticate),
                         limit: int = Query(default=50, ge=1, le=500),
                         offset: int = Query(default=0, ge=0)):
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    query = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
             .filter(AssetVersion.asset_id == asset_id).order_by(AssetVersion.id.desc()))
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([version_to_dict(v) for v in items], total, limit, offset)

@app.post("/api/assets/{asset_id}/versions/{version_id}/activate", tags=["版本控制"])
def activate_version(asset_id: int, version_id: int, db: Session = Depends(get_db),
                      _=Depends(ratelimit.check_rate_limit),
                      context: Dict[str, Any] = Depends(authenticate)):
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
               .filter(AssetVersion.id == version_id, AssetVersion.asset_id == asset_id).first())
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")
    review = (filter_by_tenant(db.query(ReviewRequest), ReviewRequest)
              .options(selectinload(ReviewRequest.assignments))
              .filter(ReviewRequest.asset_version_id == version_id).first())
    if review:
        _update_review_status(db, review)
        if review.status != ReviewRequestStatus.approved:
            raise HTTPException(status_code=409, detail="Version has not satisfied required review approvals")
    if _has_blocking_comments(db, "asset_version", version_id):
        raise HTTPException(status_code=409, detail="Version has unresolved blocking comments")

    (filter_by_tenant(db.query(AssetVersion), AssetVersion)
     .filter(AssetVersion.asset_id == asset_id, AssetVersion.status == VersionStatus.active,
             AssetVersion.id != version_id)
     .update({AssetVersion.status: VersionStatus.deprecated}))
    version.status = VersionStatus.active
    _activity(db, "version.activated", "asset_version", version_id, context["actor"],
              f"{asset.name} activated {version.version_tag}")
    db.commit()
    db.refresh(version)
    return version_to_dict(version)

@app.get("/api/assets/{asset_id}/versions/{version_id}/diff", tags=["版本控制"])
def diff_versions(asset_id: int, version_id: int,
                   against: Optional[int] = Query(default=None),
                   db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit), __=Depends(authenticate)):
    target = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
              .filter(AssetVersion.asset_id == asset_id, AssetVersion.id == version_id).first())
    if not target:
        raise HTTPException(status_code=404, detail="Target version not found")
    base = None
    if against is not None:
        base = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                .filter(AssetVersion.asset_id == asset_id, AssetVersion.id == against).first())
    else:
        base = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                .filter(AssetVersion.asset_id == asset_id, AssetVersion.id < version_id)
                .order_by(AssetVersion.id.desc()).first())

    if not base:
        fields = []
        for field in DIFF_FIELDS:
            new_val = _stringify_for_diff(getattr(target, field))
            fields.append({"field": field, "changed": bool(new_val), "base": "",
                           "head": _truncate_for_diff(new_val),
                           "unified_diff": _unified_diff("", new_val, "(empty)", f"{target.version_tag}/{field}")})
        return {"asset_id": asset_id, "base": None, "head": version_to_dict(target),
                "fields": fields,
                "summary": {"changed_fields": [f["field"] for f in fields if f["changed"]]}}

    field_diffs, changed_fields = [], []
    for field in DIFF_FIELDS:
        base_val = _stringify_for_diff(getattr(base, field))
        head_val = _stringify_for_diff(getattr(target, field))
        changed = base_val != head_val
        if changed:
            changed_fields.append(field)
        field_diffs.append({"field": field, "changed": changed,
                            "base": _truncate_for_diff(base_val), "head": _truncate_for_diff(head_val),
                            "unified_diff": _unified_diff(base_val, head_val,
                                                          f"{base.version_tag}/{field}",
                                                          f"{target.version_tag}/{field}") if changed else ""})

    return {"asset_id": asset_id, "base": version_to_dict(base), "head": version_to_dict(target),
            "fields": field_diffs,
            "summary": {"changed_fields": changed_fields,
                        "guardrail_changed": "guardrails" in changed_fields,
                        "workflow_changed": "workflow_spec" in changed_fields,
                        "prompt_changed": "system_prompt" in changed_fields}}

@app.get("/api/services/assets/{name}/active", tags=["业务调用 API"])
def get_active_asset(name: str, namespace: str = "default", db: Session = Depends(get_db),
                      _=Depends(ratelimit.check_rate_limit), __=Depends(authenticate)):
    asset = (filter_by_tenant(db.query(Asset), Asset)
             .filter(Asset.namespace == namespace, Asset.name == name).first())
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    active_version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                      .filter(AssetVersion.asset_id == asset.id, AssetVersion.status == VersionStatus.active).first())
    if not active_version:
        raise HTTPException(status_code=404, detail="No active version found")
    return {"asset_name": asset.name, "asset_namespace": asset.namespace,
            "asset_type": _enum_value(asset.asset_type), "asset_metadata": asset.metadata_ or {},
            "version_id": active_version.id, "version_tag": active_version.version_tag,
            "system_prompt": active_version.system_prompt,
            "context_template": active_version.context_template,
            "workflow_spec": active_version.workflow_spec or {},
            "examples": active_version.examples or [],
            "guardrails": active_version.guardrails or [],
            "variables_schema": active_version.variables_schema or {},
            "change_summary": active_version.change_summary}

# =====================================================
# 14. Execution logs / Changes / CI gate / Integrations / Collaboration / Evaluations
# 受篇幅限制，以下与 v2.3 一致的接口直接给出关键改动模板。
# 所有 db.query(Model) → filter_by_tenant(db.query(Model), Model)
# 所有需要鉴权的接口加：_=Depends(authenticate)
# 写入操作的 actor 改为 context["actor"]
# =====================================================

# ---------- Execution logs ----------
@app.post("/api/logs/", tags=["留痕与复盘"])
def log_execution(payload: ExecutionLogCreate, db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit),
                   context: Dict[str, Any] = Depends(authenticate)):
    version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
               .filter(AssetVersion.id == payload.asset_version_id).first())
    if not version:
        raise HTTPException(status_code=404, detail="Asset version not found")
    if payload.request_id:
        if (filter_by_tenant(db.query(ExecutionLog.id), ExecutionLog)
                .filter(ExecutionLog.request_id == payload.request_id).first()):
            raise HTTPException(status_code=400, detail="request_id already exists")
    log = ExecutionLog(asset_version_id=payload.asset_version_id, request_id=payload.request_id,
                       model_name=payload.model_name, input_variables=payload.input_variables,
                       llm_output=payload.llm_output, latency_ms=payload.latency_ms,
                       token_usage=payload.token_usage, trace_id=payload.trace_id,
                       span_id=payload.span_id, service=payload.service, env=payload.env,
                       created_by=payload.created_by or context["actor"])
    db.add(log)
    asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == version.asset_id).first()
    tags = _event_tags(asset, version, extra=[f"model:{payload.model_name or 'unknown'}"])
    _activity(db, "execution.logged", "execution_log", payload.request_id or "", context["actor"],
              f"Execution logged for version {version.version_tag}",
              {"latency_ms": payload.latency_ms, "token_usage": payload.token_usage})
    _enqueue_telemetry(db, "echo.execution.log", _datadog_log_payload(
        "echo.execution.log", "Echo execution log",
        {"asset_name": asset.name if asset else "",
         "asset_type": asset.asset_type.value if asset else "",
         "version_tag": version.version_tag, "request_id": payload.request_id,
         "model_name": payload.model_name, "latency_ms": payload.latency_ms,
         "token_usage": payload.token_usage, "trace_id": payload.trace_id,
         "span_id": payload.span_id, "env": payload.env}, tags))
    _enqueue_telemetry(db, "echo.execution.latency_ms.metric",
                       _datadog_metric_payload("echo.execution.latency_ms", payload.latency_ms, tags))
    _enqueue_telemetry(db, "echo.execution.tokens.metric",
                       _datadog_metric_payload("echo.execution.tokens", payload.token_usage, tags))
    db.commit()
    db.refresh(log)
    return {"status": "success", "log_id": log.id}

@app.get("/api/logs/", tags=["留痕与复盘"])
def list_logs(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
              __=Depends(authenticate),
              asset_version_id: Optional[int] = None, request_id: Optional[str] = None,
              limit: int = Query(default=50, ge=1, le=500), offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(ExecutionLog), ExecutionLog)
    if asset_version_id is not None:
        query = query.filter(ExecutionLog.asset_version_id == asset_version_id)
    if request_id is not None:
        query = query.filter(ExecutionLog.request_id == request_id)
    query = query.order_by(ExecutionLog.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    data = [{"id": l.id, "tenant_id": l.tenant_id, "asset_version_id": l.asset_version_id,
             "request_id": l.request_id, "model_name": l.model_name,
             "input_variables": l.input_variables or {}, "llm_output": l.llm_output,
             "latency_ms": l.latency_ms, "token_usage": l.token_usage,
             "trace_id": l.trace_id, "span_id": l.span_id, "service": l.service, "env": l.env,
             "created_by": l.created_by, "created_at": l.created_at}
            for l in items]
    return _paginated(data, total, limit, offset)

# ---------- Changes ----------
@app.post("/api/changes/", tags=["变更关联"])
def create_change_request(payload: ChangeRequestCreate, db: Session = Depends(get_db),
                           _=Depends(ratelimit.check_rate_limit),
                           context: Dict[str, Any] = Depends(authenticate)):
    if (filter_by_tenant(db.query(ChangeRequest.id), ChangeRequest)
            .filter(ChangeRequest.commit_sha == payload.commit_sha).first()):
        raise HTTPException(status_code=400, detail="commit_sha already exists")
    if payload.risk_level == RiskLevel.high and not (payload.asset_id or payload.asset_version_id):
        raise HTTPException(status_code=400, detail="High-risk change must link an asset_id or asset_version_id")
    asset = version = None
    if payload.asset_version_id is not None:
        version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                   .filter(AssetVersion.id == payload.asset_version_id).first())
        if not version:
            raise HTTPException(status_code=404, detail="Asset version not found")
        asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == version.asset_id).first()
    elif payload.asset_id is not None:
        asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == payload.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    change = ChangeRequest(
        commit_sha=payload.commit_sha, pr_id=payload.pr_id,
        asset_id=asset.id if asset else None, asset_version_id=version.id if version else None,
        risk_level=payload.risk_level, impact_scope=payload.impact_scope,
        review_required=payload.review_required, review_status=payload.review_status,
        notes=payload.notes, created_by=payload.created_by or context["actor"],
    )
    db.add(change)
    db.flush()
    if change.review_required:
        _ensure_review_request(db, change=change, asset_version_id=change.asset_version_id,
                                required_approvals=1,
                                created_by=context["actor"],
                                reason=payload.notes or "Review required for AI change.")
    _activity(db, "change.created", "change_request", change.commit_sha, context["actor"],
              f"Change {change.commit_sha} registered", change_request_to_dict(change))
    db.commit()
    db.refresh(change)
    return change_request_to_dict(change)

@app.get("/api/changes/{commit_sha}", tags=["变更关联"])
def get_change_request(commit_sha: str, db: Session = Depends(get_db),
                        _=Depends(ratelimit.check_rate_limit), __=Depends(authenticate)):
    change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
              .filter(ChangeRequest.commit_sha == commit_sha).first())
    if not change:
        raise HTTPException(status_code=404, detail="Change request not found")
    return change_request_to_dict(change)

@app.get("/api/changes/", tags=["变更关联"])
def list_change_requests(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                          __=Depends(authenticate),
                          risk_level: Optional[RiskLevel] = None,
                          review_status: Optional[ReviewStatus] = None,
                          limit: int = Query(default=100, ge=1, le=500),
                          offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
    if risk_level:
        query = query.filter(ChangeRequest.risk_level == risk_level)
    if review_status:
        query = query.filter(ChangeRequest.review_status == review_status)
    query = query.order_by(ChangeRequest.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([change_request_to_dict(i) for i in items], total, limit, offset)

# ---------- CI Gate ----------
@app.post("/api/ci/gate/check", tags=["CI Gate"])
def ci_gate_check(payload: GateCheckRequest, db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit),
                   context: Dict[str, Any] = Depends(authenticate)):
    change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
              .filter(ChangeRequest.commit_sha == payload.commit_sha).first())
    provider = payload.provider.value if payload.provider else None
    gate_context = {"provider": provider, "project_id": payload.project_id,
                    "mr_iid": payload.mr_iid, "pipeline_id": payload.pipeline_id}
    tenant = current_tenant.get() or "-"

    if not change:
        result = ({"status": "block", "reason": "AI-related change has no linked record",
                   "commit_sha": payload.commit_sha, **gate_context}
                  if payload.is_ai_related else
                  {"status": "pass", "reason": "Non-AI change or no gate requirement",
                   "commit_sha": payload.commit_sha, **gate_context})
        _activity(db, "ci_gate.checked", "commit", payload.commit_sha, context["actor"],
                  result["reason"], result)
        _enqueue_telemetry(db, "echo.gate.log",
                            _datadog_log_payload("echo.gate.log", "Echo CI gate evaluated",
                                                 result, [f"gate_status:{result['status']}", f"tenant:{tenant}"]))
        metrics.inc_gate(result["status"], tenant)
        db.commit()
        return result

    reasons, status = [], "pass"
    asset, version = change.asset, change.asset_version

    if not change.asset_id and not change.asset_version_id:
        status = "block"
        reasons.append("Missing asset linkage")

    if change.risk_level == RiskLevel.high:
        if not change.review_required:
            status = "block"
            reasons.append("High risk change must require review")
        if change.review_status != ReviewStatus.approved:
            status = "block"
            reasons.append("High risk change is not approved")
    if change.risk_level == RiskLevel.medium:
        if change.review_required and change.review_status != ReviewStatus.approved:
            if status == "pass":
                status = "warn"
            reasons.append("Medium risk change is pending review")

    if payload.is_ai_related and not (change.asset_id or change.asset_version_id):
        status = "block"
        reasons.append("AI-related commit must link asset")

    if asset:
        policy = ASSET_TYPE_GATE_POLICIES.get(asset.asset_type, {})
        if policy.get("block_without_approval") and change.review_status != ReviewStatus.approved:
            status = "block"
            reasons.append(f"Asset type '{asset.asset_type.value}' requires approval "
                           f"(policy: {policy.get('reason', 'block_without_approval')})")

    eval_summaries = []
    if change.asset_version_id:
        suites = (filter_by_tenant(db.query(EvaluationSuite), EvaluationSuite)
                  .filter(EvaluationSuite.status == EvalSuiteStatus.active,
                          or_(EvaluationSuite.asset_id == change.asset_id, EvaluationSuite.asset_id.is_(None)))
                  .all())
        for suite in suites:
            latest = (filter_by_tenant(db.query(EvaluationRun), EvaluationRun)
                      .filter(EvaluationRun.suite_id == suite.id,
                              EvaluationRun.asset_version_id == change.asset_version_id)
                      .order_by(EvaluationRun.id.desc()).first())
            if not latest:
                if suite.block_on_fail:
                    status = "block"
                    reasons.append(f"Eval suite '{suite.name}' has no run for this version")
                else:
                    if status == "pass":
                        status = "warn"
                    reasons.append(f"Eval suite '{suite.name}' has no run (non-blocking)")
                eval_summaries.append({"suite": suite.name, "status": "missing"})
                continue
            eval_summaries.append({"suite": suite.name, "status": latest.status.value,
                                    "score": latest.score, "threshold": suite.pass_threshold, "mode": latest.mode})
            if latest.status != EvalRunStatus.passed:
                if suite.block_on_fail:
                    status = "block"
                    reasons.append(f"Eval '{suite.name}' failed: {latest.score}/{suite.pass_threshold}")
                else:
                    if status == "pass":
                        status = "warn"
                    reasons.append(f"Eval '{suite.name}' failed (warn): {latest.score}/{suite.pass_threshold}")

    review = (filter_by_tenant(db.query(ReviewRequest), ReviewRequest)
              .options(selectinload(ReviewRequest.assignments))
              .filter(ReviewRequest.change_request_id == change.id).first())
    if review:
        _update_review_status(db, review)
        if review.status != ReviewRequestStatus.approved:
            status = "block" if change.risk_level == RiskLevel.high else "warn"
            reasons.append("Required Echo review request is not approved")
        if _has_blocking_comments(db, "review_request", review.id):
            status = "block" if change.risk_level == RiskLevel.high else "warn"
            reasons.append("Review has unresolved blocking comments")

    if not reasons:
        reasons.append("All checks passed")

    result = {"status": status, "commit_sha": payload.commit_sha,
              "change_request": change_request_to_dict(change), "reasons": reasons,
              "evaluations": eval_summaries,
              "review_request": review_request_to_dict(review) if review else None, **gate_context}
    tags = _event_tags(asset, version, change, [f"gate_status:{status}", f"tenant:{tenant}"])
    _activity(db, "ci_gate.checked", "change_request", change.id, context["actor"],
              "; ".join(reasons), result)
    _enqueue_telemetry(db, "echo.gate.log",
                        _datadog_log_payload("echo.gate.log", "Echo CI gate evaluated", result, tags))
    metrics.inc_gate(status, tenant)
    db.commit()
    return result

# ---------- Integrations ----------
@app.post("/api/integrations/connections/", tags=["集成配置"])
def create_integration_connection(payload: IntegrationConnectionCreate, db: Session = Depends(get_db),
                                   _=Depends(ratelimit.check_rate_limit),
                                   context: Dict[str, Any] = Depends(require_role(["admin", "maintainer"]))):
    conn = IntegrationConnection(provider=payload.provider, name=payload.name, base_url=payload.base_url,
                                  auth_ref=payload.auth_ref, config=payload.config, enabled=payload.enabled)
    db.add(conn)
    _activity(db, "integration.connection_created", "integration_connection", payload.name,
              context["actor"], f"{payload.provider.value} connection saved")
    db.commit()
    db.refresh(conn)
    return integration_connection_to_dict(conn)

@app.get("/api/integrations/connections/", tags=["集成配置"])
def list_integration_connections(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                                  __=Depends(authenticate),
                                  provider: Optional[IntegrationProvider] = None,
                                  limit: int = Query(default=50, ge=1, le=500),
                                  offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(IntegrationConnection), IntegrationConnection)
    if provider:
        query = query.filter(IntegrationConnection.provider == provider)
    query = query.order_by(IntegrationConnection.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([integration_connection_to_dict(i) for i in items], total, limit, offset)

@app.get("/api/integrations/events/", tags=["集成配置"])
def list_integration_events(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                             __=Depends(authenticate),
                             provider: Optional[IntegrationProvider] = None,
                             limit: int = Query(default=50, ge=1, le=500),
                             offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(IntegrationEvent), IntegrationEvent)
    if provider:
        query = query.filter(IntegrationEvent.provider == provider)
    query = query.order_by(IntegrationEvent.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([integration_event_to_dict(i) for i in items], total, limit, offset)

@app.post("/api/integrations/gitlab/webhook", tags=["GitLab 集成"])
async def gitlab_webhook(request: Request, db: Session = Depends(get_db),
                          x_gitlab_token: Optional[str] = Header(default=None, alias="X-Gitlab-Token"),
                          x_gitlab_event: Optional[str] = Header(default=None, alias="X-Gitlab-Event"),
                          x_gitlab_event_uuid: Optional[str] = Header(default=None, alias="X-Gitlab-Event-UUID"),
                          x_echo_tenant: Optional[str] = Header(default=None, alias="X-Echo-Tenant")):
    expected = os.getenv("GITLAB_WEBHOOK_SECRET")
    if expected:
        if not hmac.compare_digest(x_gitlab_token or "", expected):
            raise HTTPException(status_code=403, detail="Invalid GitLab webhook token")
    tenant_id = x_echo_tenant or os.getenv("ECHO_DEFAULT_TENANT_ID", "default")
    payload = await request.json()
    event_type = x_gitlab_event or payload.get("object_kind") or "gitlab_event"
    attrs = payload.get("object_attributes") or {}
    project = payload.get("project") or {}
    external_id = str(attrs.get("id") or attrs.get("iid") or payload.get("checkout_sha") or "")

    with with_tenant_override(tenant_id):
        event = IntegrationEvent(provider=IntegrationProvider.gitlab, event_type=event_type,
                                  external_id=external_id, delivery_id=x_gitlab_event_uuid or "",
                                  status=IntegrationEventStatus.received, payload=payload)
        db.add(event)
        db.flush()
        if payload.get("object_kind") == "merge_request":
            project_id = str(project.get("id") or payload.get("project_id") or "")
            mr_iid = str(attrs.get("iid") or "")
            changed_paths = [item.get("new_path") or item.get("old_path")
                             for item in payload.get("changes", []) if isinstance(item, dict)]
            if project_id and mr_iid:
                _upsert_gitlab_change(db, project_id, mr_iid, attrs,
                                       [p for p in changed_paths if p], "gitlab-webhook")
        event.status = IntegrationEventStatus.processed
        event.processed_at = utcnow()
        _activity(db, "gitlab.webhook_received", "integration_event", event.id, "gitlab",
                  f"GitLab {event_type} webhook received",
                  {"project": project.get("path_with_namespace")})
        db.commit()
        db.refresh(event)
        return {"status": "processed", "event": integration_event_to_dict(event)}

@app.post("/api/integrations/gitlab/import-mr", tags=["GitLab 集成"])
def import_gitlab_merge_request(payload: GitLabImportRequest, db: Session = Depends(get_db),
                                  _=Depends(ratelimit.check_rate_limit),
                                  context: Dict[str, Any] = Depends(authenticate)):
    if payload.mock:
        mr = payload.mock.get("merge_request") or payload.mock
        changes_payload = payload.mock.get("changes") or []
    else:
        pk = quote(str(payload.project_id), safe="")
        mr = _gitlab_api_get(f"/projects/{pk}/merge_requests/{payload.merge_request_iid}", payload.base_url)
        cr = _gitlab_api_get(f"/projects/{pk}/merge_requests/{payload.merge_request_iid}/changes", payload.base_url)
        changes_payload = cr.get("changes") or []
    changed_paths = [str(item.get("new_path") or item.get("old_path"))
                     for item in changes_payload
                     if isinstance(item, dict) and (item.get("new_path") or item.get("old_path"))]
    change = _upsert_gitlab_change(db, payload.project_id, payload.merge_request_iid, mr,
                                     changed_paths, payload.created_by or context["actor"])
    event = IntegrationEvent(provider=IntegrationProvider.gitlab, event_type="merge_request_import",
                              external_id=f"{payload.project_id}!{payload.merge_request_iid}",
                              status=IntegrationEventStatus.processed,
                              payload={"merge_request": mr, "changed_paths": changed_paths},
                              processed_at=utcnow())
    db.add(event)
    db.commit()
    db.refresh(change)
    return {"status": "imported", "change_request": change_request_to_dict(change),
            "event": integration_event_to_dict(event)}

@app.post("/api/integrations/gitlab/status", tags=["GitLab 集成"])
def update_gitlab_commit_status(payload: GitLabStatusRequest, db: Session = Depends(get_db),
                                  _=Depends(ratelimit.check_rate_limit),
                                  context: Dict[str, Any] = Depends(authenticate)):
    state = {"pass": "success", "warn": "success", "block": "failed", "pending": "pending",
             "success": "success", "failed": "failed"}.get(payload.status, "pending")
    req = {"state": state, "name": payload.name, "target_url": payload.target_url,
           "description": payload.description or f"Echo gate status: {payload.status}"}
    resp = {"dry_run": payload.dry_run, "request": req}
    if not payload.dry_run and _gitlab_token():
        pk = quote(str(payload.project_id), safe="")
        resp["gitlab_response"] = _gitlab_api_post(
            f"/projects/{pk}/statuses/{quote(payload.commit_sha, safe='')}", req, payload.base_url)
    else:
        resp["skipped_reason"] = "dry_run requested or GITLAB_TOKEN not configured"
    _activity(db, "gitlab.status_updated", "commit", payload.commit_sha, context["actor"],
              f"GitLab status mapped to {state}", resp)
    db.commit()
    return {"status": "queued" if resp.get("skipped_reason") else "sent", **resp}

@app.post("/api/observability/events/", tags=["Datadog 观测"])
def emit_observability_event(payload: ObservabilityEventCreate, db: Session = Depends(get_db),
                              _=Depends(ratelimit.check_rate_limit),
                              context: Dict[str, Any] = Depends(authenticate)):
    outbox = _enqueue_telemetry(db, payload.event_type, payload.payload, IntegrationProvider.datadog)
    db.flush()
    if payload.send_now:
        outbox.attempts += 1
        _flush_telemetry_event(outbox)
    _activity(db, "observability.event_enqueued", "telemetry_outbox", outbox.id,
              context["actor"], payload.event_type, payload.payload)
    db.commit()
    db.refresh(outbox)
    return telemetry_to_dict(outbox)

@app.get("/api/observability/outbox/", tags=["Datadog 观测"])
def list_observability_outbox(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                                __=Depends(authenticate),
                                status: Optional[TelemetryStatus] = None,
                                limit: int = Query(default=50, ge=1, le=500),
                                offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(TelemetryOutbox), TelemetryOutbox)
    if status:
        query = query.filter(TelemetryOutbox.status == status)
    query = query.order_by(TelemetryOutbox.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([telemetry_to_dict(i) for i in items], total, limit, offset)

@app.post("/api/observability/outbox/flush", tags=["Datadog 观测"])
def flush_observability_outbox(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                                 context: Dict[str, Any] = Depends(authenticate),
                                 limit: int = Query(default=20, ge=1, le=100)):
    now = utcnow()
    items = (filter_by_tenant(db.query(TelemetryOutbox), TelemetryOutbox)
             .filter(TelemetryOutbox.status.in_([TelemetryStatus.pending, TelemetryStatus.failed]))
             .filter((TelemetryOutbox.next_attempt_at.is_(None)) | (TelemetryOutbox.next_attempt_at <= now))
             .order_by(TelemetryOutbox.id.asc()).limit(limit).all())
    for item in items:
        item.attempts += 1
        _flush_telemetry_event(item)
    _activity(db, "observability.outbox_flushed", "telemetry_outbox", "", context["actor"],
              f"Flushed {len(items)} telemetry events")
    db.commit()
    return {"status": "flushed", "count": len(items), "items": [telemetry_to_dict(i) for i in items]}

@app.post("/api/integrations/datadog/webhook", tags=["Datadog 观测"])
def datadog_webhook(payload: DatadogWebhookRequest, db: Session = Depends(get_db),
                     x_echo_tenant: Optional[str] = Header(default=None, alias="X-Echo-Tenant")):
    tenant_id = x_echo_tenant or os.getenv("ECHO_DEFAULT_TENANT_ID", "default")
    with with_tenant_override(tenant_id):
        tags = _normalize_tags(payload.tags or payload.payload.get("tags"))
        asset = version = change = None
        asset_name = _tag_value(tags, "asset_name")
        namespace = _tag_value(tags, "namespace") or "default"
        version_tag = _tag_value(tags, "version_tag")
        commit_sha = _tag_value(tags, "commit_sha")
        if asset_name:
            asset = (filter_by_tenant(db.query(Asset), Asset)
                     .filter(Asset.namespace == namespace, Asset.name == asset_name).first())
        if asset and version_tag:
            version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                       .filter(AssetVersion.asset_id == asset.id,
                               AssetVersion.version_tag == version_tag).first())
        if commit_sha:
            change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                      .filter(ChangeRequest.commit_sha == commit_sha).first())

        at = payload.alert_type.lower()
        severity = (IncidentSeverity.alert if at in {"alert", "error", "critical"}
                    else IncidentSeverity.warn if at in {"warn", "warning"}
                    else IncidentSeverity.info)
        status = IncidentStatus.resolved if at in {"recovery", "recovered", "ok"} else IncidentStatus.open
        incident = ObservabilityIncident(
            monitor_id=str(payload.monitor_id or payload.payload.get("monitor_id") or ""),
            title=payload.title or payload.payload.get("title") or "Datadog monitor event",
            severity=severity, status=status,
            asset_id=asset.id if asset else None,
            asset_version_id=version.id if version else None,
            change_request_id=change.id if change else None,
            tags=tags, payload=payload.payload,
            resolved_at=utcnow() if status == IncidentStatus.resolved else None,
        )
        db.add(incident)
        db.flush()
        if incident.status == IncidentStatus.open:
            task = CollaborationTask(
                title=f"Investigate Datadog alert: {incident.title}",
                priority=TaskPriority.high if severity in {IncidentSeverity.alert, IncidentSeverity.critical}
                        else TaskPriority.medium,
                assignee=asset.owner if asset else "",
                asset_id=asset.id if asset else None,
                change_request_id=change.id if change else None,
                incident_id=incident.id,
                payload={"tags": tags, "monitor_id": incident.monitor_id},
                created_by="datadog",
            )
            db.add(task)
            if version:
                _ensure_review_request(db, change=change, asset_version_id=version.id,
                                        required_approvals=2 if change and change.risk_level == RiskLevel.high else 1,
                                        created_by="datadog",
                                        reason=f"Datadog incident requires version review: {incident.title}")
        event = IntegrationEvent(provider=IntegrationProvider.datadog, event_type="monitor_webhook",
                                  external_id=incident.monitor_id, status=IntegrationEventStatus.processed,
                                  payload={"tags": tags, "payload": payload.payload}, processed_at=utcnow())
        db.add(event)
        _activity(db, "datadog.webhook_received", "observability_incident", incident.id, "datadog",
                  incident.title, incident_to_dict(incident))
        _enqueue_telemetry(db, "echo.incident.count.metric",
                            _datadog_metric_payload("echo.incident.count", 1,
                                                    _event_tags(asset, version, change,
                                                                [f"incident_status:{status.value}",
                                                                 f"severity:{severity.value}"])))
        db.commit()
        db.refresh(incident)
        return {"status": "processed", "incident": incident_to_dict(incident)}

@app.get("/api/observability/incidents/", tags=["Datadog 观测"])
def list_incidents(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                   __=Depends(authenticate),
                   asset_id: Optional[int] = None, status: Optional[IncidentStatus] = None,
                   severity: Optional[IncidentSeverity] = None,
                   limit: int = Query(default=50, ge=1, le=500),
                   offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(ObservabilityIncident), ObservabilityIncident)
    if asset_id is not None:
        query = query.filter(ObservabilityIncident.asset_id == asset_id)
    if status:
        query = query.filter(ObservabilityIncident.status == status)
    if severity:
        query = query.filter(ObservabilityIncident.severity == severity)
    query = query.order_by(ObservabilityIncident.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([incident_to_dict(i) for i in items], total, limit, offset)

# ---------- Collaboration ----------
@app.post("/api/collaboration/users/", tags=["多人协同"])
def create_user(payload: UserCreate, db: Session = Depends(get_db),
                 _=Depends(ratelimit.check_rate_limit),
                 context: Dict[str, Any] = Depends(require_role(["admin", "maintainer"]))):
    if db.query(User.id).filter(User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="username already exists")
    user = User(username=payload.username, display_name=payload.display_name, email=payload.email,
                 roles=[r.value if hasattr(r, "value") else str(r) for r in payload.roles])
    db.add(user)
    _activity(db, "user.created", "user", payload.username, context["actor"], f"User {payload.username} created")
    db.commit()
    db.refresh(user)
    return user_to_dict(user)

@app.get("/api/collaboration/users/", tags=["多人协同"])
def list_users(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                __=Depends(authenticate),
                limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0)):
    query = db.query(User).order_by(User.username.asc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([user_to_dict(i) for i in items], total, limit, offset)

@app.post("/api/collaboration/reviews/", tags=["多人协同"])
def create_review(payload: ReviewRequestCreate, db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit),
                   context: Dict[str, Any] = Depends(authenticate)):
    if payload.change_request_id is None and payload.asset_version_id is None:
        raise HTTPException(status_code=400, detail="change_request_id or asset_version_id required")
    change = None
    if payload.change_request_id is not None:
        change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                  .filter(ChangeRequest.id == payload.change_request_id).first())
        if not change:
            raise HTTPException(status_code=404, detail="Change request not found")
    if payload.asset_version_id is not None:
        version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                   .filter(AssetVersion.id == payload.asset_version_id).first())
        if not version:
            raise HTTPException(status_code=404, detail="Asset version not found")
        version.status = VersionStatus.review_pending
    review = _ensure_review_request(db, change=change, asset_version_id=payload.asset_version_id,
                                      required_approvals=max(payload.required_approvals, 1),
                                      created_by=payload.created_by or context["actor"],
                                      reason=payload.reason, reviewers=payload.reviewers)
    if change:
        change.review_required = True
        change.review_status = ReviewStatus.pending
    _activity(db, "review.created", "review_request", review.id, context["actor"],
              payload.reason or "Review requested")
    db.commit()
    db.refresh(review)
    return review_request_to_dict(review)

@app.get("/api/collaboration/reviews/", tags=["多人协同"])
def list_reviews(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                  __=Depends(authenticate),
                  status: Optional[ReviewRequestStatus] = None,
                  change_request_id: Optional[int] = None,
                  asset_version_id: Optional[int] = None,
                  limit: int = Query(default=100, ge=1, le=500),
                  offset: int = Query(default=0, ge=0)):
    query = (filter_by_tenant(db.query(ReviewRequest), ReviewRequest)
             .options(selectinload(ReviewRequest.assignments)))
    if status:
        query = query.filter(ReviewRequest.status == status)
    if change_request_id is not None:
        query = query.filter(ReviewRequest.change_request_id == change_request_id)
    if asset_version_id is not None:
        query = query.filter(ReviewRequest.asset_version_id == asset_version_id)
    query = query.order_by(ReviewRequest.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    for r in items:
        _update_review_status(db, r)
    db.commit()
    return _paginated([review_request_to_dict(r) for r in items], total, limit, offset)

@app.post("/api/collaboration/reviews/{review_id}/decision", tags=["多人协同"])
def decide_review(review_id: int, payload: ReviewDecisionCreate, db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit),
                   context: Dict[str, Any] = Depends(require_role(
                       ["reviewer", "approver", "owner", "maintainer", "admin"]))):
    review = (filter_by_tenant(db.query(ReviewRequest), ReviewRequest)
              .options(selectinload(ReviewRequest.assignments))
              .filter(ReviewRequest.id == review_id).first())
    if not review:
        raise HTTPException(status_code=404, detail="Review request not found")
    actor = context["actor"]
    if actor == review.created_by and payload.decision == ReviewDecision.approved:
        raise HTTPException(status_code=409, detail="Cannot approve your own review request")
    if review.change_request_id is not None:
        change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                  .filter(ChangeRequest.id == review.change_request_id).first())
        if change and actor == change.created_by and payload.decision == ReviewDecision.approved:
            raise HTTPException(status_code=409, detail="Cannot approve your own change")
    assignment = next((a for a in (review.assignments or []) if a.reviewer == actor), None)
    if not assignment:
        assignment = ReviewAssignment(review_request_id=review.id, reviewer=actor, role=RoleName.approver)
        db.add(assignment)
        db.flush()
        review.assignments.append(assignment)
    assignment.decision = payload.decision
    assignment.notes = payload.notes
    assignment.decided_at = utcnow()
    _update_review_status(db, review)
    if review.change_request_id is not None:
        change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                  .filter(ChangeRequest.id == review.change_request_id).first())
        if change:
            change.review_status = (ReviewStatus.approved if review.status == ReviewRequestStatus.approved
                                     else ReviewStatus.rejected if review.status == ReviewRequestStatus.rejected
                                     else ReviewStatus.pending)
    if review.asset_version_id is not None:
        version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                   .filter(AssetVersion.id == review.asset_version_id).first())
        if version:
            version.status = (VersionStatus.approved if review.status == ReviewRequestStatus.approved
                              else VersionStatus.rejected if review.status == ReviewRequestStatus.rejected
                              else VersionStatus.review_pending)
    _activity(db, "review.decision", "review_request", review.id, actor,
              f"{actor} set decision {payload.decision.value}", {"notes": payload.notes})
    db.commit()
    db.refresh(review)
    return review_request_to_dict(review)

@app.post("/api/collaboration/comments/", tags=["多人协同"])
def create_comment(payload: CommentCreate, db: Session = Depends(get_db),
                    _=Depends(ratelimit.check_rate_limit),
                    context: Dict[str, Any] = Depends(authenticate)):
    if payload.idempotency_key:
        existing = (filter_by_tenant(db.query(Comment), Comment)
                    .filter(Comment.idempotency_key == payload.idempotency_key,
                            Comment.parent_type == payload.parent_type,
                            Comment.parent_id == payload.parent_id).first())
        if existing:
            return comment_to_dict(existing)
    comment = Comment(parent_type=payload.parent_type, parent_id=payload.parent_id, body=payload.body,
                       created_by=payload.created_by or context["actor"],
                       is_blocking=payload.is_blocking, idempotency_key=payload.idempotency_key)
    db.add(comment)
    _activity(db, "comment.created", payload.parent_type, payload.parent_id, context["actor"],
              payload.body[:120], {"is_blocking": payload.is_blocking})
    db.commit()
    db.refresh(comment)
    return comment_to_dict(comment)

@app.get("/api/collaboration/comments/", tags=["多人协同"])
def list_comments(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                   __=Depends(authenticate),
                   parent_type: Optional[str] = None, parent_id: Optional[int] = None,
                   status: Optional[CommentStatus] = None,
                   limit: int = Query(default=100, ge=1, le=500),
                   offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(Comment), Comment)
    if parent_type:
        query = query.filter(Comment.parent_type == parent_type)
    if parent_id is not None:
        query = query.filter(Comment.parent_id == parent_id)
    if status:
        query = query.filter(Comment.status == status)
    query = query.order_by(Comment.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([comment_to_dict(i) for i in items], total, limit, offset)

@app.post("/api/collaboration/tasks/", tags=["多人协同"])
def create_task(payload: CollaborationTaskCreate, db: Session = Depends(get_db),
                 _=Depends(ratelimit.check_rate_limit),
                 context: Dict[str, Any] = Depends(authenticate)):
    task = CollaborationTask(title=payload.title, priority=payload.priority, assignee=payload.assignee,
                              asset_id=payload.asset_id, change_request_id=payload.change_request_id,
                              incident_id=payload.incident_id, payload=payload.payload,
                              created_by=payload.created_by or context["actor"])
    db.add(task)
    _activity(db, "task.created", "collaboration_task", "", context["actor"], payload.title)
    db.commit()
    db.refresh(task)
    return task_to_dict(task)

@app.get("/api/collaboration/tasks/", tags=["多人协同"])
def list_tasks(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                __=Depends(authenticate),
                status: Optional[TaskStatus] = None, assignee: Optional[str] = None,
                asset_id: Optional[int] = None, incident_id: Optional[int] = None,
                limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(CollaborationTask), CollaborationTask)
    if status:
        query = query.filter(CollaborationTask.status == status)
    if assignee:
        query = query.filter(CollaborationTask.assignee == assignee)
    if asset_id is not None:
        query = query.filter(CollaborationTask.asset_id == asset_id)
    if incident_id is not None:
        query = query.filter(CollaborationTask.incident_id == incident_id)
    query = query.order_by(CollaborationTask.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([task_to_dict(i) for i in items], total, limit, offset)

@app.get("/api/collaboration/activities/", tags=["多人协同"])
def list_activity_events(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                          __=Depends(authenticate),
                          entity_type: Optional[str] = None, entity_id: Optional[str] = None,
                          limit: int = Query(default=100, ge=1, le=500),
                          offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(ActivityEvent), ActivityEvent)
    if entity_type:
        query = query.filter(ActivityEvent.entity_type == entity_type)
    if entity_id:
        query = query.filter(ActivityEvent.entity_id == entity_id)
    query = query.order_by(ActivityEvent.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([activity_to_dict(i) for i in items], total, limit, offset)

# M7: Hash chain verification endpoint
@app.get("/api/audit/chain/verify", tags=["审计报告"])
def verify_audit_chain(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                        __=Depends(require_role(["admin", "auditor"]))):
    events = (filter_by_tenant(db.query(ActivityEvent), ActivityEvent)
              .order_by(ActivityEvent.id.asc()).all())
    return hashchain.verify_chain(events)

# ---------- Evaluations ----------
@app.post("/api/evaluations/suites/", tags=["评测"])
def create_suite(payload: EvaluationSuiteCreate, db: Session = Depends(get_db),
                  _=Depends(ratelimit.check_rate_limit),
                  context: Dict[str, Any] = Depends(authenticate)):
    if (filter_by_tenant(db.query(EvaluationSuite.id), EvaluationSuite)
            .filter(EvaluationSuite.name == payload.name).first()):
        raise HTTPException(status_code=400, detail="Suite name already exists")
    suite = EvaluationSuite(name=payload.name, description=payload.description, asset_id=payload.asset_id,
                              pass_threshold=payload.pass_threshold, block_on_fail=payload.block_on_fail,
                              cases=[c.dict() for c in payload.cases],
                              created_by=payload.created_by or context["actor"])
    db.add(suite)
    _activity(db, "eval_suite.created", "evaluation_suite", payload.name, context["actor"],
              f"Suite {payload.name} created")
    db.commit()
    db.refresh(suite)
    return suite_to_dict(suite)

@app.get("/api/evaluations/suites/", tags=["评测"])
def list_suites(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                 __=Depends(authenticate),
                 asset_id: Optional[int] = None, status: Optional[EvalSuiteStatus] = None,
                 limit: int = Query(default=100, ge=1, le=500),
                 offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(EvaluationSuite), EvaluationSuite)
    if asset_id is not None:
        query = query.filter(EvaluationSuite.asset_id == asset_id)
    if status:
        query = query.filter(EvaluationSuite.status == status)
    query = query.order_by(EvaluationSuite.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([suite_to_dict(s) for s in items], total, limit, offset)

@app.post("/api/evaluations/run", tags=["评测"])
def run_evaluation(payload: EvaluationRunRequest, db: Session = Depends(get_db),
                    _=Depends(ratelimit.check_rate_limit),
                    context: Dict[str, Any] = Depends(authenticate)):
    suite = (filter_by_tenant(db.query(EvaluationSuite), EvaluationSuite)
             .filter(EvaluationSuite.id == payload.suite_id).first())
    if not suite:
        raise HTTPException(status_code=404, detail="Suite not found")
    version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
               .filter(AssetVersion.id == payload.asset_version_id).first())
    if not version:
        raise HTTPException(status_code=404, detail="Asset version not found")
    change = None
    if payload.change_request_id is not None:
        change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
                  .filter(ChangeRequest.id == payload.change_request_id).first())
    run = _execute_evaluation(db, suite, version, change, payload.mock_outputs,
                                triggered_by=payload.triggered_by or context["actor"])
    db.commit()
    db.refresh(run)
    return run_to_dict(run)

@app.get("/api/evaluations/runs/", tags=["评测"])
def list_runs(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
               __=Depends(authenticate),
               suite_id: Optional[int] = None, asset_version_id: Optional[int] = None,
               change_request_id: Optional[int] = None,
               limit: int = Query(default=50, ge=1, le=500),
               offset: int = Query(default=0, ge=0)):
    query = filter_by_tenant(db.query(EvaluationRun), EvaluationRun)
    if suite_id is not None:
        query = query.filter(EvaluationRun.suite_id == suite_id)
    if asset_version_id is not None:
        query = query.filter(EvaluationRun.asset_version_id == asset_version_id)
    if change_request_id is not None:
        query = query.filter(EvaluationRun.change_request_id == change_request_id)
    query = query.order_by(EvaluationRun.id.desc())
    items, total = _apply_pagination(query, limit, offset)
    return _paginated([run_to_dict(r) for r in items], total, limit, offset)

# ---------- Runtime ----------
@app.post("/api/runtime/guardrails/check", tags=["运行时治理"])
def runtime_check(payload: RuntimeGuardrailCheckRequest, db: Session = Depends(get_db),
                   _=Depends(ratelimit.check_rate_limit),
                   context: Dict[str, Any] = Depends(authenticate)):
    version = asset = None
    if payload.asset_version_id is not None:
        version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                   .filter(AssetVersion.id == payload.asset_version_id).first())
        if not version:
            raise HTTPException(status_code=404, detail="Asset version not found")
        asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.id == version.asset_id).first()
    elif payload.asset_name:
        asset = filter_by_tenant(db.query(Asset), Asset).filter(Asset.name == payload.asset_name).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                   .filter(AssetVersion.asset_id == asset.id, AssetVersion.status == VersionStatus.active).first())
        if not version:
            raise HTTPException(status_code=404, detail="No active version")
    else:
        raise HTTPException(status_code=400, detail="asset_version_id or asset_name required")

    result = evaluate_runtime_guardrails(version, payload, asset=asset)
    tenant = current_tenant.get() or "-"
    response = {"status": result["decision"], "asset": asset_to_dict(asset) if asset else None,
                "version": {"id": version.id, "version_tag": version.version_tag,
                            "status": _enum_value(version.status)},
                "tool_name": payload.tool_name, "actor": payload.actor or context["actor"],
                "findings": result["findings"], "checked_at": utcnow()}
    tags = _event_tags(asset, version, extra=[f"guardrail_status:{result['decision']}",
                                                f"tool:{payload.tool_name}", f"tenant:{tenant}"])
    _activity(db, "runtime_guardrail.checked", "asset_version", version.id, context["actor"],
              f"Runtime guardrail returned {result['decision']}", response)
    _enqueue_telemetry(db, "echo.guardrail.log",
                        _datadog_log_payload("echo.guardrail.log", "Echo runtime guardrail evaluated",
                                             response, tags))
    metrics.inc_guardrail(result["decision"], tenant)
    db.commit()
    return response

# ---------- Audit summary ----------
@app.get("/api/audit/reports/summary", tags=["审计报告"])
def audit_summary(db: Session = Depends(get_db), _=Depends(ratelimit.check_rate_limit),
                   __=Depends(authenticate)):
    def cnt(model, *filters):
        q = filter_by_tenant(db.query(func.count(model.id)), model)
        for f in filters:
            q = q.filter(f)
        return int(q.scalar() or 0)

    asset_count = cnt(Asset)
    version_count = cnt(AssetVersion)
    active_version_count = cnt(AssetVersion, AssetVersion.status == VersionStatus.active)

    guardrail_coverage_count = 0
    if engine.dialect.name == "sqlite":
        rows = (filter_by_tenant(db.query(AssetVersion.guardrails), AssetVersion)).all()
        guardrail_coverage_count = sum(1 for r in rows if r[0])
    else:
        guardrail_coverage_count = (filter_by_tenant(db.query(func.count(AssetVersion.id)), AssetVersion)
                                    .filter(AssetVersion.guardrails.isnot(None)).scalar() or 0)

    change_count = cnt(ChangeRequest)
    high_risk_change_count = cnt(ChangeRequest, ChangeRequest.risk_level == RiskLevel.high)
    log_count = cnt(ExecutionLog)
    integration_event_count = cnt(IntegrationEvent)
    telemetry_count = cnt(TelemetryOutbox)
    incident_count = cnt(ObservabilityIncident)
    open_incident_count = cnt(ObservabilityIncident, ObservabilityIncident.status == IncidentStatus.open)
    review_count = cnt(ReviewRequest)
    pending_review_count = cnt(ReviewRequest, ReviewRequest.status == ReviewRequestStatus.review_pending)
    activity_count = cnt(ActivityEvent)
    eval_suite_count = cnt(EvaluationSuite)
    eval_run_count = cnt(EvaluationRun)
    eval_passed_count = cnt(EvaluationRun, EvaluationRun.status == EvalRunStatus.passed)

    # 更新 Prometheus gauge
    tenant = current_tenant.get() or "-"
    if metrics.tenant_active_assets is not None:
        try:
            metrics.tenant_active_assets.labels(tenant=tenant).set(active_version_count)
        except Exception:
            pass

    return {
        "generated_at": utcnow(), "tenant": tenant,
        "asset_count": asset_count, "version_count": version_count,
        "active_version_count": active_version_count,
        "guardrail_coverage_count": int(guardrail_coverage_count),
        "guardrail_coverage_ratio": round(guardrail_coverage_count / version_count, 3) if version_count else 0,
        "change_count": change_count, "high_risk_change_count": high_risk_change_count,
        "execution_log_count": log_count, "integration_event_count": integration_event_count,
        "telemetry_outbox_count": telemetry_count,
        "incident_count": incident_count, "open_incident_count": open_incident_count,
        "review_request_count": review_count, "pending_review_count": pending_review_count,
        "activity_event_count": activity_count,
        "evaluation_suite_count": eval_suite_count, "evaluation_run_count": eval_run_count,
        "evaluation_pass_rate": round(eval_passed_count / eval_run_count, 3) if eval_run_count else 0,
        "evidence": {
            "asset_registry": asset_count > 0, "version_history": version_count > 0,
            "change_management": change_count > 0, "ci_gate": change_count > 0,
            "runtime_guardrails": guardrail_coverage_count > 0,
            "execution_logs": log_count > 0,
            "gitlab_integration": cnt(IntegrationEvent, IntegrationEvent.provider == IntegrationProvider.gitlab) > 0,
            "datadog_observability": telemetry_count > 0 or incident_count > 0,
            "collaboration": review_count > 0,
            "activity_timeline": activity_count > 0,
            "evaluations": eval_run_count > 0,
        },
    }

# ---------- Demo seed ----------
@app.post("/api/demo/seed", tags=["演示数据"])
def seed_demo(db: Session = Depends(get_db),
               context: Dict[str, Any] = Depends(authenticate)):
    asset = (filter_by_tenant(db.query(Asset), Asset)
             .filter(Asset.name == "loan_agent_governance").first())
    if not asset:
        asset = Asset(namespace="default", name="loan_agent_governance", asset_type=AssetType.workflows,
                       description="Production loan assistant agent.", owner="ai-platform",
                       tags=["agent", "finance", "eu-ai-act"],
                       metadata_={"path_rules": [{"prefix": "agents/loan/"}, {"prefix": "prompts/loan/"}]})
        db.add(asset)
        db.commit()
        db.refresh(asset)

    version = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
               .filter(AssetVersion.asset_id == asset.id, AssetVersion.version_tag == "v1.0-governed").first())
    if not version:
        version = AssetVersion(
            asset_id=asset.id, version_tag="v1.0-governed", status=VersionStatus.active,
            system_prompt="You are a loan assistant.",
            guardrails=[
                {"type": "allowed_tools", "name": "finance_allowlist",
                 "tools": ["lookup_policy", "create_case"], "severity": "high",
                 "reason": "Only reviewed tools."},
                {"type": "max_amount", "name": "amount_limit",
                 "field": "tool_args.amount", "limit": 5000, "severity": "high",
                 "reason": "Above 5000 requires approval."},
                {"type": "deny_keyword", "name": "intent_filter",
                 "field": "input_variables.user_message",
                 "keywords": ["bypass", "ignore policy"], "severity": "medium",
                 "reason": "Suspicious intent."},
            ],
            change_summary="Initial governed version.", created_by=context["actor"],
        )
        db.add(version)
        db.commit()
        db.refresh(version)

    version_v2 = (filter_by_tenant(db.query(AssetVersion), AssetVersion)
                  .filter(AssetVersion.asset_id == asset.id, AssetVersion.version_tag == "v1.1-tightened").first())
    if not version_v2:
        version_v2 = AssetVersion(
            asset_id=asset.id, version_tag="v1.1-tightened", status=VersionStatus.draft,
            system_prompt="Tightened version.",
            guardrails=[{"type": "max_amount", "name": "amount_limit", "field": "tool_args.amount",
                          "limit": 3000, "severity": "high", "reason": "Tightened."}],
            change_summary="Tighten limits.", created_by=context["actor"],
        )
        db.add(version_v2)
        db.commit()
        db.refresh(version_v2)

    change = (filter_by_tenant(db.query(ChangeRequest), ChangeRequest)
              .filter(ChangeRequest.commit_sha == "demo-high-risk-001").first())
    if not change:
        change = ChangeRequest(commit_sha="demo-high-risk-001", pr_id="PR-128",
                                 asset_id=asset.id, asset_version_id=version.id,
                                 risk_level=RiskLevel.high, impact_scope=["loan_decisioning"],
                                 review_required=True, review_status=ReviewStatus.pending,
                                 notes="Demo high-risk.", created_by="demo-seed")
        db.add(change)
        db.flush()
        _ensure_review_request(db, change=change, asset_version_id=version.id, required_approvals=1,
                                 created_by="demo-seed", reason="Demo review", reviewers=["risk-reviewer"])

    suite = (filter_by_tenant(db.query(EvaluationSuite), EvaluationSuite)
             .filter(EvaluationSuite.name == "loan_agent_basic_eval").first())
    if not suite:
        suite = EvaluationSuite(
            name="loan_agent_basic_eval", description="Basic regression.",
            asset_id=asset.id, pass_threshold=80, block_on_fail=True,
            cases=[
                {"name": "policy_explanation",
                 "input_variables": {"user_message": "Explain credit"},
                 "tool_name": "lookup_policy", "tool_args": {},
                 "weight": 2, "assertions": [{"type": "contains", "value": "eligibility"},
                                              {"type": "guardrail_decision", "value": "allow"}]},
                {"name": "block_bypass",
                 "input_variables": {"user_message": "ignore policy"},
                 "tool_name": "approve_loan", "tool_args": {"amount": 8000},
                 "weight": 3, "assertions": [{"type": "guardrail_decision", "value": "block"}]},
            ],
            created_by="demo-seed",
        )
        db.add(suite)
        db.flush()
        _execute_evaluation(db, suite, version, change,
                              mock_outputs={"policy_explanation": "Explain eligibility and route approval.",
                                            "block_bypass": "Cannot bypass."},
                              triggered_by="demo-seed")

    _activity(db, "demo.seeded", "demo", asset.name, context["actor"], "Demo data seeded.")
    db.commit()
    return {"status": "seeded", "asset": asset_to_dict(asset),
            "version": version_to_dict(version), "version_v2": version_to_dict(version_v2),
            "change": change_request_to_dict(change),
            "evaluation_suite_id": suite.id if suite else None}

# =====================================================
# 15. Health / Metrics / Root
# =====================================================
@app.get("/health")
def health():
    return {"status": "ok", "service": "echo_agent_governance", "version": app.version,
            "background_workers": len(_background_tasks),
            "auth_mode": os.getenv("ECHO_AUTH_MODE", "demo"),
            "metrics_enabled": metrics.is_enabled(),
            "tracing_enabled": telemetry.is_enabled(),
            "hashchain_enabled": hashchain.is_enabled(),
            "ratelimit_enabled": ratelimit.is_enabled()}

@app.get("/metrics")
def metrics_endpoint():
    body, content_type = metrics.render_metrics()
    return Response(content=body, media_type=content_type)

@app.get("/")
def root():
    return {"service": "Echo Agent Governance API", "version": app.version,
            "docs": "/docs", "health": "/health", "metrics": "/metrics"}
