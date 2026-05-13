"""
Echo Agent Governance - Python SDK
===================================
Thin client around the FastAPI backend.

Usage:
    from echo_sdk import EchoClient

    echo = EchoClient(
        base_url="http://127.0.0.1:8000",
        actor="ai-platform-owner",
        roles=["owner", "approver"],
    )

    active = echo.get_active_asset("loan_agent_governance")
    decision = echo.check_runtime_guardrails(
        asset_version_id=active["version_id"],
        tool_name="approve_loan",
        tool_args={"amount": 1000},
        input_variables={"user_message": "please approve"},
        actor="demo-user",
    )
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Sequence

import requests

class EchoError(RuntimeError):
    """Raised when the Echo API returns a non-2xx response."""

    def __init__(self, status_code: int, detail: Any):
        super().__init__(f"Echo API error {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail

class EchoClient:
    """High-level wrapper around the Echo Agent Governance API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        actor: str = "demo-user",
        roles: Optional[Sequence[str]] = None,
        timeout: float = 10.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.actor = actor
        self.roles = list(roles or ["viewer"])
        self.timeout = timeout
        self.session = session or requests.Session()

    # ---------- low-level ----------
    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "X-Echo-Actor": self.actor,
            "X-Echo-Roles": ",".join(self.roles),
        }
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.base_url}{path}"
        response = self.session.request(
            method,
            url,
            params=params,
            json=json,
            headers=self._headers(),
            timeout=self.timeout,
        )
        if not response.ok:
            try:
                detail = response.json()
            except ValueError:
                detail = response.text
            raise EchoError(response.status_code, detail)
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    # ====================================================
    # Health & demo
    # ====================================================
    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def seed_demo(self) -> Dict[str, Any]:
        return self._request("POST", "/api/demo/seed")

    # ====================================================
    # Assets & versions
    # ====================================================
    def create_asset(
        self,
        name: str,
        asset_type: str,
        owner: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/assets/",
            json={
                "name": name,
                "asset_type": asset_type,
                "owner": owner,
                "description": description,
                "tags": tags or [],
                "metadata": metadata or {},
            },
        )

    def list_assets(
        self,
        q: Optional[str] = None,
        asset_type: Optional[str] = None,
        owner: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = {k: v for k, v in {
            "q": q, "asset_type": asset_type, "owner": owner, "tag": tag,
        }.items() if v is not None}
        return self._request("GET", "/api/assets/", params=params)

    def get_asset(self, asset_id: int) -> Dict[str, Any]:
        return self._request("GET", f"/api/assets/{asset_id}")

    def get_active_asset(self, name: str) -> Dict[str, Any]:
        """Resolve a published asset by name for runtime consumption."""
        return self._request("GET", f"/api/services/assets/{name}/active")

    def create_version(
        self,
        asset_id: int,
        version_tag: str,
        created_by: str,
        system_prompt: str = "",
        context_template: str = "",
        workflow_spec: Optional[Dict[str, Any]] = None,
        examples: Optional[List[Any]] = None,
        guardrails: Optional[List[Any]] = None,
        variables_schema: Optional[Dict[str, Any]] = None,
        change_summary: str = "",
        set_active: bool = True,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            f"/api/assets/{asset_id}/versions/",
            json={
                "version_tag": version_tag,
                "created_by": created_by,
                "system_prompt": system_prompt,
                "context_template": context_template,
                "workflow_spec": workflow_spec or {},
                "examples": examples or [],
                "guardrails": guardrails or [],
                "variables_schema": variables_schema or {},
                "change_summary": change_summary,
                "set_active": set_active,
            },
        )

    def list_versions(self, asset_id: int) -> List[Dict[str, Any]]:
        return self._request("GET", f"/api/assets/{asset_id}/versions/")

    def activate_version(self, asset_id: int, version_id: int) -> Dict[str, Any]:
        return self._request("POST", f"/api/assets/{asset_id}/versions/{version_id}/activate")

    def diff_versions(
        self,
        asset_id: int,
        head_version_id: int,
        against: Optional[int] = None,
    ) -> Dict[str, Any]:
        params = {"against": against} if against is not None else None
        return self._request(
            "GET",
            f"/api/assets/{asset_id}/versions/{head_version_id}/diff",
            params=params,
        )

    # ====================================================
    # Execution logs
    # ====================================================
    def log_execution(
        self,
        asset_version_id: int,
        llm_output: str,
        request_id: Optional[str] = None,
        model_name: str = "",
        input_variables: Optional[Dict[str, Any]] = None,
        latency_ms: int = 0,
        token_usage: int = 0,
        trace_id: str = "",
        span_id: str = "",
        service: str = "",
        env: str = "",
        created_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/logs/",
            json={
                "asset_version_id": asset_version_id,
                "request_id": request_id,
                "model_name": model_name,
                "input_variables": input_variables or {},
                "llm_output": llm_output,
                "latency_ms": latency_ms,
                "token_usage": token_usage,
                "trace_id": trace_id,
                "span_id": span_id,
                "service": service,
                "env": env,
                "created_by": created_by or self.actor,
            },
        )

    def list_logs(
        self,
        asset_version_id: Optional[int] = None,
        request_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        if asset_version_id is not None:
            params["asset_version_id"] = asset_version_id
        if request_id is not None:
            params["request_id"] = request_id
        return self._request("GET", "/api/logs/", params=params)

    # ====================================================
    # Change requests + CI gate
    # ====================================================
    def create_change(
        self,
        commit_sha: str,
        created_by: Optional[str] = None,
        pr_id: Optional[str] = None,
        asset_id: Optional[int] = None,
        asset_version_id: Optional[int] = None,
        risk_level: str = "low",
        impact_scope: Optional[List[str]] = None,
        review_required: bool = False,
        review_status: str = "pending",
        notes: str = "",
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/changes/",
            json={
                "commit_sha": commit_sha,
                "pr_id": pr_id,
                "asset_id": asset_id,
                "asset_version_id": asset_version_id,
                "risk_level": risk_level,
                "impact_scope": impact_scope or [],
                "review_required": review_required,
                "review_status": review_status,
                "notes": notes,
                "created_by": created_by or self.actor,
            },
        )

    def get_change(self, commit_sha: str) -> Dict[str, Any]:
        return self._request("GET", f"/api/changes/{commit_sha}")

    def list_changes(
        self,
        risk_level: Optional[str] = None,
        review_status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        if risk_level is not None:
            params["risk_level"] = risk_level
        if review_status is not None:
            params["review_status"] = review_status
        return self._request("GET", "/api/changes/", params=params)

    def check_ci_gate(
        self,
        commit_sha: str,
        is_ai_related: bool = True,
        provider: Optional[str] = None,
        project_id: Optional[str] = None,
        mr_iid: Optional[str] = None,
        pipeline_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/ci/gate/check",
            json={
                "commit_sha": commit_sha,
                "is_ai_related": is_ai_related,
                "provider": provider,
                "project_id": project_id,
                "mr_iid": mr_iid,
                "pipeline_id": pipeline_id,
            },
        )

    def check_gitlab_ci_gate_from_env(
        self,
        is_ai_related: bool = True,
        env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Read GitLab predefined CI variables and run the gate.

        Variables consulted:
            CI_COMMIT_SHA, CI_PROJECT_ID, CI_MERGE_REQUEST_IID, CI_PIPELINE_ID
        """
        e = env if env is not None else os.environ
        commit_sha = e.get("CI_COMMIT_SHA")
        if not commit_sha:
            raise EchoError(400, "CI_COMMIT_SHA is not set in environment")
        return self.check_ci_gate(
            commit_sha=commit_sha,
            is_ai_related=is_ai_related,
            provider="gitlab",
            project_id=e.get("CI_PROJECT_ID"),
            mr_iid=e.get("CI_MERGE_REQUEST_IID"),
            pipeline_id=e.get("CI_PIPELINE_ID"),
        )

    # ====================================================
    # GitLab integration
    # ====================================================
    def create_change_from_gitlab_mr(
        self,
        project_id: str,
        merge_request_iid: str,
        created_by: Optional[str] = None,
        base_url: Optional[str] = None,
        mock: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Import a MR from GitLab into Echo, auto-creating/updating the change request."""
        return self._request(
            "POST",
            "/api/integrations/gitlab/import-mr",
            json={
                "project_id": project_id,
                "merge_request_iid": merge_request_iid,
                "created_by": created_by or self.actor,
                "base_url": base_url,
                "mock": mock,
            },
        )

    def update_gitlab_status(
        self,
        project_id: str,
        commit_sha: str,
        status: str,
        name: str = "echo/agent-governance",
        target_url: str = "",
        description: str = "",
        base_url: Optional[str] = None,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/integrations/gitlab/status",
            json={
                "project_id": project_id,
                "commit_sha": commit_sha,
                "status": status,
                "name": name,
                "target_url": target_url,
                "description": description,
                "base_url": base_url,
                "dry_run": dry_run,
            },
        )

    # ====================================================
    # Runtime guardrails
    # ====================================================
    def check_runtime_guardrails(
        self,
        tool_name: str,
        asset_version_id: Optional[int] = None,
        asset_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None,
        input_variables: Optional[Dict[str, Any]] = None,
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        if asset_version_id is None and asset_name is None:
            raise EchoError(400, "asset_version_id or asset_name is required")
        return self._request(
            "POST",
            "/api/runtime/guardrails/check",
            json={
                "asset_version_id": asset_version_id,
                "asset_name": asset_name,
                "tool_name": tool_name,
                "tool_args": tool_args or {},
                "input_variables": input_variables or {},
                "actor": actor or self.actor,
            },
        )

    # ====================================================
    # Evaluations
    # ====================================================
    def create_eval_suite(
        self,
        name: str,
        cases: List[Dict[str, Any]],
        description: str = "",
        asset_id: Optional[int] = None,
        pass_threshold: int = 80,
        block_on_fail: bool = True,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/evaluations/suites/",
            json={
                "name": name,
                "description": description,
                "asset_id": asset_id,
                "pass_threshold": pass_threshold,
                "block_on_fail": block_on_fail,
                "cases": cases,
                "created_by": self.actor,
            },
        )

    def list_eval_suites(
        self,
        asset_id: Optional[int] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        params = {k: v for k, v in {
            "asset_id": asset_id, "status": status,
        }.items() if v is not None}
        return self._request("GET", "/api/evaluations/suites/", params=params)

    def run_evaluation(
        self,
        suite_id: int,
        asset_version_id: int,
        change_request_id: Optional[int] = None,
        mock_outputs: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/evaluations/run",
            json={
                "suite_id": suite_id,
                "asset_version_id": asset_version_id,
                "change_request_id": change_request_id,
                "mock_outputs": mock_outputs,
                "triggered_by": self.actor,
            },
        )

    def list_eval_runs(
        self,
        suite_id: Optional[int] = None,
        asset_version_id: Optional[int] = None,
        change_request_id: Optional[int] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        for k, v in {
            "suite_id": suite_id,
            "asset_version_id": asset_version_id,
            "change_request_id": change_request_id,
        }.items():
            if v is not None:
                params[k] = v
        return self._request("GET", "/api/evaluations/runs/", params=params)

    # ====================================================
    # Observability (Datadog)
    # ====================================================
    def emit_observability_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
        send_now: bool = False,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/observability/events/",
            json={
                "event_type": event_type,
                "payload": payload or {},
                "send_now": send_now,
            },
        )

    def flush_observability_outbox(self, limit: int = 20) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/observability/outbox/flush",
            params={"limit": limit},
        )

    def list_incidents(
        self,
        asset_id: Optional[int] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        for k, v in {
            "asset_id": asset_id, "status": status, "severity": severity,
        }.items():
            if v is not None:
                params[k] = v
        return self._request("GET", "/api/observability/incidents/", params=params)

    # ====================================================
    # Collaboration: reviews, comments, tasks
    # ====================================================
    def create_review(
        self,
        change_request_id: Optional[int] = None,
        asset_version_id: Optional[int] = None,
        required_approvals: int = 1,
        reviewers: Optional[List[str]] = None,
        reason: str = "",
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/collaboration/reviews/",
            json={
                "change_request_id": change_request_id,
                "asset_version_id": asset_version_id,
                "required_approvals": required_approvals,
                "reviewers": reviewers or [],
                "reason": reason,
                "created_by": self.actor,
            },
        )

    def list_reviews(
        self,
        status: Optional[str] = None,
        change_request_id: Optional[int] = None,
        asset_version_id: Optional[int] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        for k, v in {
            "status": status,
            "change_request_id": change_request_id,
            "asset_version_id": asset_version_id,
        }.items():
            if v is not None:
                params[k] = v
        return self._request("GET", "/api/collaboration/reviews/", params=params)

    def list_review_tasks(
        self,
        assignee: Optional[str] = None,
        status: Optional[str] = "review_pending",
    ) -> List[Dict[str, Any]]:
        """Return reviews that need someone's attention.

        Defaults to pending reviews, optionally filtered by assignee.
        """
        reviews = self.list_reviews(status=status)
        if assignee:
            filtered = []
            for r in reviews:
                names = {a.get("reviewer") for a in r.get("assignments", [])}
                if assignee in names:
                    filtered.append(r)
            return filtered
        return reviews

    def decide_review(
        self,
        review_id: int,
        decision: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            f"/api/collaboration/reviews/{review_id}/decision",
            json={"decision": decision, "notes": notes},
        )

    def approve_change(
        self,
        review_id: int,
        notes: str = "Approved via SDK",
    ) -> Dict[str, Any]:
        """Convenience wrapper: approve a pending review."""
        return self.decide_review(review_id, "approved", notes)

    def reject_change(
        self,
        review_id: int,
        notes: str = "Rejected via SDK",
    ) -> Dict[str, Any]:
        return self.decide_review(review_id, "rejected", notes)

    def request_changes(
        self,
        review_id: int,
        notes: str = "Changes requested via SDK",
    ) -> Dict[str, Any]:
        return self.decide_review(review_id, "changes_requested", notes)

    def create_comment(
        self,
        parent_type: str,
        parent_id: int,
        body: str,
        is_blocking: bool = False,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/collaboration/comments/",
            json={
                "parent_type": parent_type,
                "parent_id": parent_id,
                "body": body,
                "is_blocking": is_blocking,
                "created_by": self.actor,
            },
        )

    def resolve_comment(self, comment_id: int) -> Dict[str, Any]:
        return self._request("POST", f"/api/collaboration/comments/{comment_id}/resolve")

    def create_task(
        self,
        title: str,
        priority: str = "medium",
        assignee: str = "",
        asset_id: Optional[int] = None,
        change_request_id: Optional[int] = None,
        incident_id: Optional[int] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            "/api/collaboration/tasks/",
            json={
                "title": title,
                "priority": priority,
                "assignee": assignee,
                "asset_id": asset_id,
                "change_request_id": change_request_id,
                "incident_id": incident_id,
                "payload": payload or {},
                "created_by": self.actor,
            },
        )

    def list_tasks(
        self,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        asset_id: Optional[int] = None,
        incident_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        params = {k: v for k, v in {
            "status": status, "assignee": assignee,
            "asset_id": asset_id, "incident_id": incident_id,
        }.items() if v is not None}
        return self._request("GET", "/api/collaboration/tasks/", params=params)

    def update_task(
        self,
        task_id: int,
        status: Optional[str] = None,
        assignee: Optional[str] = None,
        priority: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "PATCH",
            f"/api/collaboration/tasks/{task_id}",
            json={k: v for k, v in {
                "status": status, "assignee": assignee, "priority": priority,
            }.items() if v is not None},
        )

    def list_activities(
        self,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        params = {"limit": limit}
        if entity_type is not None:
            params["entity_type"] = entity_type
        if entity_id is not None:
            params["entity_id"] = entity_id
        return self._request("GET", "/api/collaboration/activities/", params=params)

    # ====================================================
    # Audit
    # ====================================================
    def audit_summary(self) -> Dict[str, Any]:
        return self._request("GET", "/api/audit/reports/summary")

__all__ = ["EchoClient", "EchoError"]
