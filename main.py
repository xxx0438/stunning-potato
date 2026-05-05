from collections import Counter
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session


# ==========================================
# 1. Database configuration
# ==========================================
SQLALCHEMY_DATABASE_URL = "sqlite:///./echo_prompt_manager.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ==========================================
# 2. Enums
# ==========================================
class AssetType(str, Enum):
    prompt = "prompt"
    context_pack = "context_pack"
    skill = "skill"
    workflow = "workflow"


class VersionStatus(str, Enum):
    draft = "draft"
    approved = "approved"
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


# ==========================================
# 3. ORM models
# ==========================================
class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    asset_type = Column(SAEnum(AssetType), nullable=False, index=True)
    description = Column(Text, default="")
    owner = Column(String, nullable=False, index=True)
    tags = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    versions = relationship(
        "AssetVersion",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetVersion.id.desc()",
    )
    change_requests = relationship(
        "ChangeRequest",
        back_populates="asset",
        cascade="all, delete-orphan",
    )


class AssetVersion(Base):
    __tablename__ = "asset_versions"
    __table_args__ = (
        UniqueConstraint("asset_id", "version_tag", name="uq_asset_version_tag"),
    )

    id = Column(Integer, primary_key=True, index=True)
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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    asset = relationship("Asset", back_populates="versions")
    execution_logs = relationship(
        "ExecutionLog",
        back_populates="asset_version",
        cascade="all, delete-orphan",
    )
    change_requests = relationship(
        "ChangeRequest",
        back_populates="asset_version",
        cascade="all, delete-orphan",
    )


class ExecutionLog(Base):
    __tablename__ = "execution_logs"

    id = Column(Integer, primary_key=True, index=True)
    asset_version_id = Column(Integer, ForeignKey("asset_versions.id"), nullable=False, index=True)
    request_id = Column(String, unique=True, nullable=True, index=True)
    model_name = Column(String, default="", index=True)
    input_variables = Column(JSON, default=dict)
    llm_output = Column(Text, default="")
    latency_ms = Column(Integer, default=0)
    token_usage = Column(Integer, default=0)
    created_by = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    asset_version = relationship("AssetVersion", back_populates="execution_logs")


class ChangeRequest(Base):
    __tablename__ = "change_requests"

    id = Column(Integer, primary_key=True, index=True)
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
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    asset = relationship("Asset", back_populates="change_requests")
    asset_version = relationship("AssetVersion", back_populates="change_requests")


Base.metadata.create_all(bind=engine)


# ==========================================
# 4. Pydantic models
# ==========================================
class AssetCreate(BaseModel):
    name: str
    asset_type: AssetType
    description: str = ""
    owner: str
    tags: List[str] = Field(default_factory=list)


class AssetUpdate(BaseModel):
    description: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None


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


class RuntimeGuardrailCheckRequest(BaseModel):
    asset_version_id: Optional[int] = None
    asset_name: Optional[str] = None
    tool_name: str = ""
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    input_variables: Dict[str, Any] = Field(default_factory=dict)
    actor: str = ""


# ==========================================
# 5. App
# ==========================================
app = FastAPI(title="Echo Prompt CMS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


def asset_to_dict(asset: Asset) -> Dict[str, Any]:
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_type": asset.asset_type,
        "description": asset.description,
        "owner": asset.owner,
        "tags": asset.tags or [],
        "created_at": asset.created_at,
        "updated_at": asset.updated_at,
    }


def version_to_dict(version: AssetVersion) -> Dict[str, Any]:
    return {
        "id": version.id,
        "asset_id": version.asset_id,
        "version_tag": version.version_tag,
        "status": version.status,
        "system_prompt": version.system_prompt,
        "context_template": version.context_template,
        "workflow_spec": version.workflow_spec or {},
        "examples": version.examples or [],
        "guardrails": version.guardrails or [],
        "variables_schema": version.variables_schema or {},
        "change_summary": version.change_summary,
        "created_by": version.created_by,
        "created_at": version.created_at,
        "updated_at": version.updated_at,
    }


def change_request_to_dict(cr: ChangeRequest) -> Dict[str, Any]:
    return {
        "id": cr.id,
        "commit_sha": cr.commit_sha,
        "pr_id": cr.pr_id,
        "asset_id": cr.asset_id,
        "asset_version_id": cr.asset_version_id,
        "risk_level": cr.risk_level,
        "impact_scope": cr.impact_scope or [],
        "review_required": cr.review_required,
        "review_status": cr.review_status,
        "notes": cr.notes,
        "created_by": cr.created_by,
        "created_at": cr.created_at,
        "updated_at": cr.updated_at,
    }


def _enum_counter(items: List[Any]) -> Dict[str, int]:
    return {str(k.value if hasattr(k, "value") else k): v for k, v in Counter(items).items()}


def _field_value(payload: RuntimeGuardrailCheckRequest, field_path: str) -> Any:
    roots = {
        "tool_args": payload.tool_args,
        "input_variables": payload.input_variables,
    }
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


def _rule_matches_tool(rule: Dict[str, Any], tool_name: str) -> bool:
    tools = rule.get("tools")
    if tools is None and rule.get("tool") is not None:
        tools = [rule.get("tool")]
    if not tools:
        return True
    return tool_name in tools


def _raise_decision(current: str, candidate: str) -> str:
    rank = {"allow": 0, "review": 1, "block": 2}
    return candidate if rank[candidate] > rank[current] else current


def evaluate_runtime_guardrails(
    version: AssetVersion,
    payload: RuntimeGuardrailCheckRequest,
) -> Dict[str, Any]:
    guardrails = version.guardrails or []
    decision = "allow"
    findings = []

    if not guardrails:
        return {
            "decision": "review",
            "findings": [
                {
                    "rule": "guardrail_coverage",
                    "decision": "review",
                    "reason": "No runtime guardrails are configured for this active asset version.",
                }
            ],
        }

    for index, raw_rule in enumerate(guardrails, start=1):
        if isinstance(raw_rule, str):
            findings.append(
                {
                    "rule": f"manual_rule_{index}",
                    "decision": "allow",
                    "reason": raw_rule,
                }
            )
            continue

        if not isinstance(raw_rule, dict):
            findings.append(
                {
                    "rule": f"rule_{index}",
                    "decision": "review",
                    "reason": "Guardrail rule is not structured JSON.",
                }
            )
            decision = _raise_decision(decision, "review")
            continue

        rule_type = str(raw_rule.get("type", "")).lower()
        rule_name = raw_rule.get("name") or rule_type or f"rule_{index}"
        severity = str(raw_rule.get("severity", "")).lower()
        fail_decision = "block" if severity == "high" else "review"

        if rule_type in {"blocked_tool", "deny_tool"} and _rule_matches_tool(raw_rule, payload.tool_name):
            decision = _raise_decision(decision, "block")
            findings.append(
                {
                    "rule": rule_name,
                    "decision": "block",
                    "reason": raw_rule.get("reason") or f"Tool '{payload.tool_name}' is blocked.",
                }
            )
            continue

        if rule_type in {"requires_approval", "approval_required"} and _rule_matches_tool(raw_rule, payload.tool_name):
            decision = _raise_decision(decision, "review")
            findings.append(
                {
                    "rule": rule_name,
                    "decision": "review",
                    "reason": raw_rule.get("reason") or f"Tool '{payload.tool_name}' requires human approval.",
                }
            )
            continue

        if rule_type == "allowed_tools":
            tools = raw_rule.get("tools") or []
            if payload.tool_name not in tools:
                decision = _raise_decision(decision, "block")
                findings.append(
                    {
                        "rule": rule_name,
                        "decision": "block",
                        "reason": f"Tool '{payload.tool_name}' is outside the allowlist.",
                    }
                )
            continue

        if rule_type == "deny_keyword":
            field = raw_rule.get("field", "input_variables.user_message")
            value = str(_field_value(payload, field) or "").lower()
            keywords = [str(k).lower() for k in raw_rule.get("keywords", [])]
            matched = [k for k in keywords if k and k in value]
            if matched:
                decision = _raise_decision(decision, fail_decision)
                findings.append(
                    {
                        "rule": rule_name,
                        "decision": fail_decision,
                        "reason": raw_rule.get("reason") or f"Denied keyword matched in {field}.",
                        "matched": matched,
                    }
                )
            continue

        if rule_type == "max_amount":
            field = raw_rule.get("field", "tool_args.amount")
            limit = raw_rule.get("limit")
            value = _field_value(payload, field)
            try:
                over_limit = limit is not None and float(value) > float(limit)
            except (TypeError, ValueError):
                over_limit = False
            if over_limit:
                decision = _raise_decision(decision, fail_decision)
                findings.append(
                    {
                        "rule": rule_name,
                        "decision": fail_decision,
                        "reason": raw_rule.get("reason") or f"{field} exceeds limit {limit}.",
                    }
                )
            continue

        findings.append(
            {
                "rule": rule_name,
                "decision": "allow",
                "reason": raw_rule.get("reason") or "Rule registered for audit evidence.",
            }
        )

    if not findings:
        findings.append({"rule": "runtime_check", "decision": "allow", "reason": "No rule was triggered."})

    return {"decision": decision, "findings": findings}


# ==========================================
# 6. Asset APIs
# ==========================================
@app.post("/api/assets/", tags=["资产管理"])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    existing = db.query(Asset).filter(Asset.name == payload.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Asset name already exists")

    asset = Asset(
        name=payload.name,
        asset_type=payload.asset_type,
        description=payload.description,
        owner=payload.owner,
        tags=payload.tags,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)


@app.get("/api/assets/", tags=["资产管理"])
def list_assets(
    db: Session = Depends(get_db),
    q: Optional[str] = None,
    asset_type: Optional[AssetType] = None,
    owner: Optional[str] = None,
    tag: Optional[str] = None,
):
    query = db.query(Asset)

    if q:
        like = f"%{q}%"
        query = query.filter((Asset.name.ilike(like)) | (Asset.description.ilike(like)) | (Asset.owner.ilike(like)))
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if owner:
        query = query.filter(Asset.owner == owner)
    if tag:
        query = query.filter(Asset.tags.contains([tag]))

    assets = query.order_by(Asset.id.desc()).all()
    return [asset_to_dict(a) for a in assets]


@app.get("/api/assets/{asset_id}", tags=["资产管理"])
def get_asset(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return {
        **asset_to_dict(asset),
        "versions": [version_to_dict(v) for v in asset.versions],
    }


@app.patch("/api/assets/{asset_id}", tags=["资产管理"])
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    if payload.description is not None:
        asset.description = payload.description
    if payload.owner is not None:
        asset.owner = payload.owner
    if payload.tags is not None:
        asset.tags = payload.tags

    db.commit()
    db.refresh(asset)
    return asset_to_dict(asset)


# ==========================================
# 7. Version APIs
# ==========================================
@app.post("/api/assets/{asset_id}/versions/", tags=["版本控制"])
def create_asset_version(asset_id: int, payload: AssetVersionCreate, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    duplicate = (
        db.query(AssetVersion)
        .filter(AssetVersion.asset_id == asset_id, AssetVersion.version_tag == payload.version_tag)
        .first()
    )
    if duplicate:
        raise HTTPException(status_code=400, detail="Version tag already exists for this asset")

    if payload.set_active:
        db.query(AssetVersion).filter(AssetVersion.asset_id == asset_id).update(
            {AssetVersion.status: VersionStatus.approved}
        )

    version = AssetVersion(
        asset_id=asset_id,
        version_tag=payload.version_tag,
        status=VersionStatus.active if payload.set_active else VersionStatus.draft,
        system_prompt=payload.system_prompt,
        context_template=payload.context_template,
        workflow_spec=payload.workflow_spec,
        examples=payload.examples,
        guardrails=payload.guardrails,
        variables_schema=payload.variables_schema,
        change_summary=payload.change_summary,
        created_by=payload.created_by,
    )
    db.add(version)
    db.commit()
    db.refresh(version)
    return version_to_dict(version)


@app.get("/api/assets/{asset_id}/versions/", tags=["版本控制"])
def list_asset_versions(asset_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    versions = db.query(AssetVersion).filter(AssetVersion.asset_id == asset_id).order_by(AssetVersion.id.desc()).all()
    return [version_to_dict(v) for v in versions]


@app.post("/api/assets/{asset_id}/versions/{version_id}/activate", tags=["版本控制"])
def activate_version(asset_id: int, version_id: int, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    version = (
        db.query(AssetVersion)
        .filter(AssetVersion.id == version_id, AssetVersion.asset_id == asset_id)
        .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Version not found")

    db.query(AssetVersion).filter(AssetVersion.asset_id == asset_id).update(
        {AssetVersion.status: VersionStatus.approved}
    )
    version.status = VersionStatus.active
    db.commit()
    db.refresh(version)
    return version_to_dict(version)


@app.get("/api/services/assets/{name}/active", tags=["业务调用 API"])
def get_active_asset(name: str, db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.name == name).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    active_version = (
        db.query(AssetVersion)
        .filter(AssetVersion.asset_id == asset.id, AssetVersion.status == VersionStatus.active)
        .first()
    )
    if not active_version:
        raise HTTPException(status_code=404, detail="No active version found for this asset")

    return {
        "asset_name": asset.name,
        "asset_type": asset.asset_type,
        "version_id": active_version.id,
        "version_tag": active_version.version_tag,
        "system_prompt": active_version.system_prompt,
        "context_template": active_version.context_template,
        "workflow_spec": active_version.workflow_spec or {},
        "examples": active_version.examples or [],
        "guardrails": active_version.guardrails or [],
        "variables_schema": active_version.variables_schema or {},
        "change_summary": active_version.change_summary,
    }


# ==========================================
# 8. Execution logs
# ==========================================
@app.post("/api/logs/", tags=["留痕与复盘"])
def log_execution(payload: ExecutionLogCreate, db: Session = Depends(get_db)):
    version = db.query(AssetVersion).filter(AssetVersion.id == payload.asset_version_id).first()
    if not version:
        raise HTTPException(status_code=404, detail="Asset version not found")

    if payload.request_id:
        exists = db.query(ExecutionLog).filter(ExecutionLog.request_id == payload.request_id).first()
        if exists:
            raise HTTPException(status_code=400, detail="request_id already exists")

    log = ExecutionLog(
        asset_version_id=payload.asset_version_id,
        request_id=payload.request_id,
        model_name=payload.model_name,
        input_variables=payload.input_variables,
        llm_output=payload.llm_output,
        latency_ms=payload.latency_ms,
        token_usage=payload.token_usage,
        created_by=payload.created_by,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return {"status": "success", "log_id": log.id}


@app.get("/api/logs/", tags=["留痕与复盘"])
def list_logs(
    db: Session = Depends(get_db),
    asset_version_id: Optional[int] = None,
    request_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    query = db.query(ExecutionLog)
    if asset_version_id is not None:
        query = query.filter(ExecutionLog.asset_version_id == asset_version_id)
    if request_id is not None:
        query = query.filter(ExecutionLog.request_id == request_id)
    logs = query.order_by(ExecutionLog.id.desc()).limit(limit).all()
    return [
        {
            "id": log.id,
            "asset_version_id": log.asset_version_id,
            "request_id": log.request_id,
            "model_name": log.model_name,
            "input_variables": log.input_variables or {},
            "llm_output": log.llm_output,
            "latency_ms": log.latency_ms,
            "token_usage": log.token_usage,
            "created_by": log.created_by,
            "created_at": log.created_at,
        }
        for log in logs
    ]


# ==========================================
# 9. Change requests / commit links
# ==========================================
@app.post("/api/changes/", tags=["变更关联"])
def create_change_request(payload: ChangeRequestCreate, db: Session = Depends(get_db)):
    existing = db.query(ChangeRequest).filter(ChangeRequest.commit_sha == payload.commit_sha).first()
    if existing:
        raise HTTPException(status_code=400, detail="commit_sha already exists")

    if payload.asset_version_id is None and payload.asset_id is None:
        raise HTTPException(status_code=400, detail="asset_id or asset_version_id is required")

    asset = None
    version = None

    if payload.asset_version_id is not None:
        version = db.query(AssetVersion).filter(AssetVersion.id == payload.asset_version_id).first()
        if not version:
            raise HTTPException(status_code=404, detail="Asset version not found")
        asset = db.query(Asset).filter(Asset.id == version.asset_id).first()
    elif payload.asset_id is not None:
        asset = db.query(Asset).filter(Asset.id == payload.asset_id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")

    change = ChangeRequest(
        commit_sha=payload.commit_sha,
        pr_id=payload.pr_id,
        asset_id=asset.id if asset else None,
        asset_version_id=version.id if version else None,
        risk_level=payload.risk_level,
        impact_scope=payload.impact_scope,
        review_required=payload.review_required,
        review_status=payload.review_status,
        notes=payload.notes,
        created_by=payload.created_by,
    )
    db.add(change)
    db.commit()
    db.refresh(change)
    return change_request_to_dict(change)


@app.get("/api/changes/{commit_sha}", tags=["变更关联"])
def get_change_request(commit_sha: str, db: Session = Depends(get_db)):
    change = db.query(ChangeRequest).filter(ChangeRequest.commit_sha == commit_sha).first()
    if not change:
        raise HTTPException(status_code=404, detail="Change request not found")
    return change_request_to_dict(change)


@app.get("/api/changes/", tags=["变更关联"])
def list_change_requests(
    db: Session = Depends(get_db),
    risk_level: Optional[RiskLevel] = None,
    review_status: Optional[ReviewStatus] = None,
    limit: int = Query(default=100, ge=1, le=500),
):
    query = db.query(ChangeRequest)
    if risk_level:
        query = query.filter(ChangeRequest.risk_level == risk_level)
    if review_status:
        query = query.filter(ChangeRequest.review_status == review_status)

    items = query.order_by(ChangeRequest.id.desc()).limit(limit).all()
    return [change_request_to_dict(i) for i in items]


# ==========================================
# 10. CI gate
# ==========================================
@app.post("/api/ci/gate/check", tags=["CI Gate"])
def ci_gate_check(payload: GateCheckRequest, db: Session = Depends(get_db)):
    change = db.query(ChangeRequest).filter(ChangeRequest.commit_sha == payload.commit_sha).first()

    if not change:
        if payload.is_ai_related:
            return {
                "status": "block",
                "reason": "AI-related change has no linked change request / asset",
                "commit_sha": payload.commit_sha,
            }
        return {
            "status": "pass",
            "reason": "Non-AI change or no gate requirement",
            "commit_sha": payload.commit_sha,
        }

    reasons = []
    status = "pass"

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
        reasons.append("AI-related commit must be linked to an asset or asset version")

    if not reasons:
        reasons.append("All checks passed")

    return {
        "status": status,
        "commit_sha": payload.commit_sha,
        "change_request": change_request_to_dict(change),
        "reasons": reasons,
    }


# ==========================================
# 11. Runtime guardrails / audit evidence
# ==========================================
@app.post("/api/runtime/guardrails/check", tags=["运行时治理"])
def runtime_guardrail_check(payload: RuntimeGuardrailCheckRequest, db: Session = Depends(get_db)):
    version = None
    asset = None

    if payload.asset_version_id is not None:
        version = db.query(AssetVersion).filter(AssetVersion.id == payload.asset_version_id).first()
        if not version:
            raise HTTPException(status_code=404, detail="Asset version not found")
        asset = db.query(Asset).filter(Asset.id == version.asset_id).first()
    elif payload.asset_name:
        asset = db.query(Asset).filter(Asset.name == payload.asset_name).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Asset not found")
        version = (
            db.query(AssetVersion)
            .filter(AssetVersion.asset_id == asset.id, AssetVersion.status == VersionStatus.active)
            .first()
        )
        if not version:
            raise HTTPException(status_code=404, detail="No active version found for this asset")
    else:
        raise HTTPException(status_code=400, detail="asset_version_id or asset_name is required")

    result = evaluate_runtime_guardrails(version, payload)
    return {
        "status": result["decision"],
        "asset": asset_to_dict(asset) if asset else None,
        "version": {
            "id": version.id,
            "version_tag": version.version_tag,
            "status": version.status,
        },
        "tool_name": payload.tool_name,
        "actor": payload.actor,
        "findings": result["findings"],
        "checked_at": datetime.utcnow(),
    }


@app.get("/api/audit/reports/summary", tags=["审计报告"])
def audit_summary(db: Session = Depends(get_db)):
    assets = db.query(Asset).all()
    versions = db.query(AssetVersion).all()
    changes = db.query(ChangeRequest).all()
    logs = db.query(ExecutionLog).all()

    active_versions = [v for v in versions if v.status == VersionStatus.active]
    versions_with_guardrails = [v for v in versions if v.guardrails]
    high_risk_changes = [c for c in changes if c.risk_level == RiskLevel.high]
    blocked_changes = [
        c for c in changes
        if c.risk_level == RiskLevel.high and (not c.review_required or c.review_status != ReviewStatus.approved)
    ]

    return {
        "generated_at": datetime.utcnow(),
        "asset_count": len(assets),
        "version_count": len(versions),
        "active_version_count": len(active_versions),
        "guardrail_coverage_count": len(versions_with_guardrails),
        "guardrail_coverage_ratio": round(len(versions_with_guardrails) / len(versions), 3) if versions else 0,
        "change_count": len(changes),
        "high_risk_change_count": len(high_risk_changes),
        "ci_block_candidate_count": len(blocked_changes),
        "execution_log_count": len(logs),
        "assets_by_type": _enum_counter([a.asset_type for a in assets]),
        "versions_by_status": _enum_counter([v.status for v in versions]),
        "changes_by_risk": _enum_counter([c.risk_level for c in changes]),
        "changes_by_review_status": _enum_counter([c.review_status for c in changes]),
        "evidence": {
            "asset_registry": len(assets) > 0,
            "version_history": len(versions) > 0,
            "change_management": len(changes) > 0,
            "ci_gate": len(changes) > 0,
            "runtime_guardrails": len(versions_with_guardrails) > 0,
            "execution_logs": len(logs) > 0,
        },
    }


@app.post("/api/demo/seed", tags=["演示数据"])
def seed_demo_data(db: Session = Depends(get_db)):
    asset = db.query(Asset).filter(Asset.name == "loan_agent_governance").first()
    if not asset:
        asset = Asset(
            name="loan_agent_governance",
            asset_type=AssetType.workflow,
            description="Production loan assistant agent with governed context, workflow, and runtime tool policies.",
            owner="ai-platform",
            tags=["agent", "finance", "eu-ai-act", "runtime-guardrails"],
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)

    version = (
        db.query(AssetVersion)
        .filter(AssetVersion.asset_id == asset.id, AssetVersion.version_tag == "v1.0-governed")
        .first()
    )
    if not version:
        db.query(AssetVersion).filter(AssetVersion.asset_id == asset.id).update(
            {AssetVersion.status: VersionStatus.approved}
        )
        version = AssetVersion(
            asset_id=asset.id,
            version_tag="v1.0-governed",
            status=VersionStatus.active,
            system_prompt=(
                "You are a loan assistant agent. Explain decisions, cite policy context, "
                "and never execute financial tools without the configured runtime guardrails."
            ),
            context_template="customer_profile={{customer_profile}}\nloan_policy={{loan_policy}}\nregion={{region}}",
            workflow_spec={
                "steps": ["collect_context", "assess_risk", "draft_answer", "request_human_approval_for_tools"],
                "owner": "ai-platform",
            },
            examples=[
                {"input": "Can I increase my credit line?", "output": "I can explain eligibility and route approval."}
            ],
            guardrails=[
                {
                    "type": "allowed_tools",
                    "name": "finance_tool_allowlist",
                    "tools": ["lookup_policy", "create_case", "request_human_approval"],
                    "severity": "high",
                    "reason": "Only reviewed tools are allowed in regulated finance flows.",
                },
                {
                    "type": "max_amount",
                    "name": "approval_amount_limit",
                    "field": "tool_args.amount",
                    "limit": 5000,
                    "severity": "high",
                    "reason": "Amounts above 5000 require a separate approval workflow.",
                },
                {
                    "type": "deny_keyword",
                    "name": "sensitive_intent_filter",
                    "field": "input_variables.user_message",
                    "keywords": ["bypass", "ignore policy", "fake income"],
                    "severity": "medium",
                    "reason": "Suspicious intent requires review before the agent continues.",
                },
            ],
            variables_schema={
                "customer_profile": {"type": "object"},
                "loan_policy": {"type": "string"},
                "region": {"type": "string"},
            },
            change_summary="Initial governed agent workflow with CI and runtime policies.",
            created_by="demo-seed",
        )
        db.add(version)
        db.commit()
        db.refresh(version)

    change = db.query(ChangeRequest).filter(ChangeRequest.commit_sha == "demo-high-risk-001").first()
    if not change:
        change = ChangeRequest(
            commit_sha="demo-high-risk-001",
            pr_id="PR-128",
            asset_id=asset.id,
            asset_version_id=version.id,
            risk_level=RiskLevel.high,
            impact_scope=["loan_decisioning", "runtime_tools", "regulated_finance"],
            review_required=True,
            review_status=ReviewStatus.pending,
            notes="Demo high-risk prompt/workflow change awaiting human approval.",
            created_by="demo-seed",
        )
        db.add(change)

    existing_log = db.query(ExecutionLog).filter(ExecutionLog.request_id == "demo-run-001").first()
    if not existing_log:
        db.add(
            ExecutionLog(
                asset_version_id=version.id,
                request_id="demo-run-001",
                model_name="gpt-4o",
                input_variables={"user_message": "Can I increase my credit line?", "region": "EU"},
                llm_output="I can explain eligibility and create a review case for a human approver.",
                latency_ms=842,
                token_usage=318,
                created_by="demo-seed",
            )
        )

    db.commit()
    return {
        "status": "seeded",
        "asset": asset_to_dict(asset),
        "version": version_to_dict(version),
        "change": change_request_to_dict(change),
    }


# ==========================================
# 12. Health check
# ==========================================
@app.get("/health")
def health():
    return {"status": "ok", "service": "echo_agent_governance"}




