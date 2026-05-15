"""Typed data models. Loose contracts: extra fields from the server are
preserved in `.raw` so the SDK keeps working when the API adds new fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None

@dataclass
class _BaseModel:
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]):
        raise NotImplementedError

# ---- Asset ----
@dataclass
class Asset(_BaseModel):
    id: int = 0
    tenant_id: str = "default"
    namespace: str = "default"
    name: str = ""
    asset_type: str = ""
    description: str = ""
    owner: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Asset":
        return cls(
            id=data.get("id", 0),
            tenant_id=data.get("tenant_id", "default"),
            namespace=data.get("namespace", "default"),
            name=data.get("name", ""),
            asset_type=data.get("asset_type", ""),
            description=data.get("description", ""),
            owner=data.get("owner", ""),
            tags=data.get("tags") or [],
            metadata=data.get("metadata") or {},
            created_at=_parse_dt(data.get("created_at")),
            updated_at=_parse_dt(data.get("updated_at")),
            raw=data,
        )

@dataclass
class AssetVersion(_BaseModel):
    id: int = 0
    tenant_id: str = "default"
    asset_id: int = 0
    version_tag: str = ""
    status: str = ""
    system_prompt: str = ""
    context_template: str = ""
    workflow_spec: Dict[str, Any] = field(default_factory=dict)
    examples: List[Any] = field(default_factory=list)
    guardrails: List[Any] = field(default_factory=list)
    variables_schema: Dict[str, Any] = field(default_factory=dict)
    change_summary: str = ""
    created_by: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssetVersion":
        return cls(
            id=data.get("id", 0),
            tenant_id=data.get("tenant_id", "default"),
            asset_id=data.get("asset_id", 0),
            version_tag=data.get("version_tag", ""),
            status=data.get("status", ""),
            system_prompt=data.get("system_prompt", ""),
            context_template=data.get("context_template", ""),
            workflow_spec=data.get("workflow_spec") or {},
            examples=data.get("examples") or [],
            guardrails=data.get("guardrails") or [],
            variables_schema=data.get("variables_schema") or {},
            change_summary=data.get("change_summary", ""),
            created_by=data.get("created_by", ""),
            created_at=_parse_dt(data.get("created_at")),
            updated_at=_parse_dt(data.get("updated_at")),
            raw=data,
        )

@dataclass
class ChangeRequest(_BaseModel):
    id: int = 0
    tenant_id: str = "default"
    commit_sha: str = ""
    pr_id: Optional[str] = None
    asset_id: Optional[int] = None
    asset_version_id: Optional[int] = None
    risk_level: str = "low"
    impact_scope: List[str] = field(default_factory=list)
    review_required: bool = False
    review_status: str = "pending"
    notes: str = ""
    created_by: str = ""
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangeRequest":
        return cls(
            id=data.get("id", 0),
            tenant_id=data.get("tenant_id", "default"),
            commit_sha=data.get("commit_sha", ""),
            pr_id=data.get("pr_id"),
            asset_id=data.get("asset_id"),
            asset_version_id=data.get("asset_version_id"),
            risk_level=data.get("risk_level", "low"),
            impact_scope=data.get("impact_scope") or [],
            review_required=data.get("review_required", False),
            review_status=data.get("review_status", "pending"),
            notes=data.get("notes", ""),
            created_by=data.get("created_by", ""),
            created_at=_parse_dt(data.get("created_at")),
            updated_at=_parse_dt(data.get("updated_at")),
            raw=data,
        )

# ---- Gate ----
@dataclass
class GateResult(_BaseModel):
    status: str = "pass"           # pass | warn | block
    commit_sha: str = ""
    reasons: List[str] = field(default_factory=list)
    change_request: Optional[Dict[str, Any]] = None
    evaluations: List[Dict[str, Any]] = field(default_factory=list)
    review_request: Optional[Dict[str, Any]] = None

    @property
    def is_blocked(self) -> bool:
        return self.status == "block"

    @property
    def is_warning(self) -> bool:
        return self.status == "warn"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GateResult":
        return cls(
            status=data.get("status", "pass"),
            commit_sha=data.get("commit_sha", ""),
            reasons=data.get("reasons") or [],
            change_request=data.get("change_request"),
            evaluations=data.get("evaluations") or [],
            review_request=data.get("review_request"),
            raw=data,
        )

# ---- Runtime guardrail ----
@dataclass
class GuardrailFinding(_BaseModel):
    rule: str = ""
    decision: str = "allow"
    reason: str = ""
    matched: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GuardrailFinding":
        return cls(
            rule=data.get("rule", ""),
            decision=data.get("decision", "allow"),
            reason=data.get("reason", ""),
            matched=data.get("matched") or [],
            raw=data,
        )

@dataclass
class RuntimeGuardrailResult(_BaseModel):
    status: str = "allow"          # allow | review | block
    tool_name: str = ""
    actor: str = ""
    findings: List[GuardrailFinding] = field(default_factory=list)
    asset: Optional[Dict[str, Any]] = None
    version: Optional[Dict[str, Any]] = None
    checked_at: Optional[datetime] = None

    @property
    def is_blocked(self) -> bool:
        return self.status == "block"

    @property
    def needs_review(self) -> bool:
        return self.status == "review"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeGuardrailResult":
        return cls(
            status=data.get("status", "allow"),
            tool_name=data.get("tool_name", ""),
            actor=data.get("actor", ""),
            findings=[GuardrailFinding.from_dict(f) for f in (data.get("findings") or [])],
            asset=data.get("asset"),
            version=data.get("version"),
            checked_at=_parse_dt(data.get("checked_at")),
            raw=data,
        )

# ---- Evaluation ----
@dataclass
class EvaluationRun(_BaseModel):
    id: int = 0
    tenant_id: str = "default"
    suite_id: int = 0
    asset_version_id: Optional[int] = None
    change_request_id: Optional[int] = None
    status: str = "pending"
    score: int = 0
    passed_count: int = 0
    failed_count: int = 0
    error_count: int = 0
    total_count: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    triggered_by: str = ""
    mode: str = "stub"
    created_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    @property
    def passed(self) -> bool:
        return self.status == "passed"

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvaluationRun":
        return cls(
            id=data.get("id", 0),
            tenant_id=data.get("tenant_id", "default"),
            suite_id=data.get("suite_id", 0),
            asset_version_id=data.get("asset_version_id"),
            change_request_id=data.get("change_request_id"),
            status=data.get("status", "pending"),
            score=data.get("score", 0),
            passed_count=data.get("passed_count", 0),
            failed_count=data.get("failed_count", 0),
            error_count=data.get("error_count", 0),
            total_count=data.get("total_count", 0),
            results=data.get("results") or [],
            triggered_by=data.get("triggered_by", ""),
            mode=data.get("mode", "stub"),
            created_at=_parse_dt(data.get("created_at")),
            finished_at=_parse_dt(data.get("finished_at")),
            raw=data,
        )

# ---- Pagination ----
@dataclass
class Page:
    """Generic paginated response container."""
    items: List[Any] = field(default_factory=list)
    total: int = 0
    limit: int = 0
    offset: int = 0
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], item_cls=None) -> "Page":
        raw_items = data.get("items") if isinstance(data, dict) else data
        if item_cls is not None and raw_items:
            items = [item_cls.from_dict(x) for x in raw_items]
        else:
            items = list(raw_items or [])
        return cls(
            items=items,
            total=int(data.get("total", len(items))) if isinstance(data, dict) else len(items),
            limit=int(data.get("limit", len(items))) if isinstance(data, dict) else len(items),
            offset=int(data.get("offset", 0)) if isinstance(data, dict) else 0,
            raw=data if isinstance(data, dict) else {},
        )
