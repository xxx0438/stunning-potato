"""Synchronous HTTP client for the Echo Agent Governance API."""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional, Union

import httpx

from echo_sdk import __version__
from echo_sdk.exceptions import EchoAPIError, EchoError, from_response
from echo_sdk.models import (
    Asset,
    AssetVersion,
    ChangeRequest,
    EvaluationRun,
    GateResult,
    Page,
    RuntimeGuardrailResult,
)
from echo_sdk.retry import RetryPolicy

DEFAULT_USER_AGENT = f"echo-sdk-python/{__version__}"

# =====================================================
# Resource namespaces
# =====================================================
class _Resource:
    def __init__(self, client: "EchoClient") -> None:
        self._client = client

class _AssetsResource(_Resource):
    def list(self, *, q: Optional[str] = None, asset_type: Optional[str] = None,
             owner: Optional[str] = None, namespace: Optional[str] = None,
             tag: Optional[str] = None, limit: int = 50, offset: int = 0) -> Page:
        params = {"limit": limit, "offset": offset}
        for k, v in (("q", q), ("asset_type", asset_type), ("owner", owner),
                      ("namespace", namespace), ("tag", tag)):
            if v is not None:
                params[k] = v
        data = self._client._request("GET", "/api/assets/", params=params)
        return Page.from_dict(data, item_cls=Asset)

    def get(self, asset_id: int) -> Asset:
        data = self._client._request("GET", f"/api/assets/{asset_id}")
        return Asset.from_dict(data)

    def create(self, *, name: str, asset_type: str, owner: str,
               description: str = "", namespace: str = "default",
               tags: Optional[List[str]] = None,
               metadata: Optional[Dict[str, Any]] = None) -> Asset:
        body = {
            "name": name, "asset_type": asset_type, "owner": owner,
            "description": description, "namespace": namespace,
            "tags": tags or [], "metadata": metadata or {},
        }
        data = self._client._request("POST", "/api/assets/", json=body)
        return Asset.from_dict(data)

    def get_active(self, name: str, namespace: str = "default") -> Dict[str, Any]:
        """Fetch the active version of a named asset (service-call API)."""
        return self._client._request(
            "GET", f"/api/services/assets/{name}/active",
            params={"namespace": namespace},
        )

class _VersionsResource(_Resource):
    def list(self, asset_id: int, *, limit: int = 50, offset: int = 0) -> Page:
        data = self._client._request(
            "GET", f"/api/assets/{asset_id}/versions/",
            params={"limit": limit, "offset": offset},
        )
        return Page.from_dict(data, item_cls=AssetVersion)

    def create(self, asset_id: int, *, version_tag: str, created_by: str,
               system_prompt: str = "", context_template: str = "",
               workflow_spec: Optional[Dict[str, Any]] = None,
               examples: Optional[List[Any]] = None,
               guardrails: Optional[List[Any]] = None,
               variables_schema: Optional[Dict[str, Any]] = None,
               change_summary: str = "", set_active: bool = True) -> AssetVersion:
        body = {
            "version_tag": version_tag, "created_by": created_by,
            "system_prompt": system_prompt, "context_template": context_template,
            "workflow_spec": workflow_spec or {}, "examples": examples or [],
            "guardrails": guardrails or [], "variables_schema": variables_schema or {},
            "change_summary": change_summary, "set_active": set_active,
        }
        data = self._client._request("POST", f"/api/assets/{asset_id}/versions/", json=body)
        return AssetVersion.from_dict(data)

    def activate(self, asset_id: int, version_id: int) -> AssetVersion:
        data = self._client._request(
            "POST", f"/api/assets/{asset_id}/versions/{version_id}/activate"
        )
        return AssetVersion.from_dict(data)

    def diff(self, asset_id: int, version_id: int,
             against: Optional[int] = None) -> Dict[str, Any]:
        params = {"against": against} if against is not None else None
        return self._client._request(
            "GET", f"/api/assets/{asset_id}/versions/{version_id}/diff",
            params=params,
        )

class _ChangesResource(_Resource):
    def create(self, *, commit_sha: str, created_by: str,
               asset_id: Optional[int] = None,
               asset_version_id: Optional[int] = None,
               pr_id: Optional[str] = None,
               risk_level: str = "low",
               impact_scope: Optional[List[str]] = None,
               review_required: bool = False,
               notes: str = "") -> ChangeRequest:
        body = {
            "commit_sha": commit_sha, "pr_id": pr_id,
            "asset_id": asset_id, "asset_version_id": asset_version_id,
            "risk_level": risk_level, "impact_scope": impact_scope or [],
            "review_required": review_required, "notes": notes,
            "created_by": created_by,
        }
        data = self._client._request("POST", "/api/changes/", json=body)
        return ChangeRequest.from_dict(data)

    def get(self, commit_sha: str) -> ChangeRequest:
        data = self._client._request("GET", f"/api/changes/{commit_sha}")
        return ChangeRequest.from_dict(data)

    def list(self, *, risk_level: Optional[str] = None,
             review_status: Optional[str] = None,
             limit: int = 100, offset: int = 0) -> Page:
        params = {"limit": limit, "offset": offset}
        if risk_level:
            params["risk_level"] = risk_level
        if review_status:
            params["review_status"] = review_status
        data = self._client._request("GET", "/api/changes/", params=params)
        return Page.from_dict(data, item_cls=ChangeRequest)

class _GateResource(_Resource):
    def check(self, *, commit_sha: str, is_ai_related: bool = False,
              provider: Optional[str] = None,
              project_id: Optional[str] = None,
              mr_iid: Optional[str] = None,
              pipeline_id: Optional[str] = None) -> GateResult:
        """Run CI gate. Use `result.is_blocked` to decide CI exit code."""
        body = {
            "commit_sha": commit_sha,
            "is_ai_related": is_ai_related,
            "provider": provider,
            "project_id": project_id,
            "mr_iid": mr_iid,
            "pipeline_id": pipeline_id,
        }
        data = self._client._request("POST", "/api/ci/gate/check", json=body)
        return GateResult.from_dict(data)

class _RuntimeResource(_Resource):
    def guardrail_check(self, *,
                         asset_version_id: Optional[int] = None,
                         asset_name: Optional[str] = None,
                         tool_name: str = "",
                         tool_args: Optional[Dict[str, Any]] = None,
                         input_variables: Optional[Dict[str, Any]] = None,
                         actor: str = "") -> RuntimeGuardrailResult:
        """Pre-flight guardrail check before invoking an agent tool."""
        body = {
            "asset_version_id": asset_version_id,
            "asset_name": asset_name,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            "input_variables": input_variables or {},
            "actor": actor,
        }
        data = self._client._request("POST", "/api/runtime/guardrails/check", json=body)
        return RuntimeGuardrailResult.from_dict(data)

class _EvalResource(_Resource):
    def list_suites(self, *, asset_id: Optional[int] = None,
                     status: Optional[str] = None,
                     limit: int = 100, offset: int = 0) -> Page:
        params = {"limit": limit, "offset": offset}
        if asset_id is not None:
            params["asset_id"] = asset_id
        if status:
            params["status"] = status
        data = self._client._request("GET", "/api/evaluations/suites/", params=params)
        return Page.from_dict(data)

    def run(self, *, suite_id: int, asset_version_id: int,
            change_request_id: Optional[int] = None,
            mock_outputs: Optional[Dict[str, str]] = None,
            triggered_by: str = "") -> EvaluationRun:
        body = {
            "suite_id": suite_id, "asset_version_id": asset_version_id,
            "change_request_id": change_request_id,
            "mock_outputs": mock_outputs, "triggered_by": triggered_by,
        }
        data = self._client._request("POST", "/api/evaluations/run", json=body)
        return EvaluationRun.from_dict(data)

    def list_runs(self, *, suite_id: Optional[int] = None,
                   asset_version_id: Optional[int] = None,
                   limit: int = 50, offset: int = 0) -> Page:
        params = {"limit": limit, "offset": offset}
        if suite_id is not None:
            params["suite_id"] = suite_id
        if asset_version_id is not None:
            params["asset_version_id"] = asset_version_id
        data = self._client._request("GET", "/api/evaluations/runs/", params=params)
        return Page.from_dict(data, item_cls=EvaluationRun)

class _WebhooksResource(_Resource):
    def list_subscriptions(self, *, limit: int = 50, offset: int = 0) -> Page:
        return Page.from_dict(self._client._request(
            "GET", "/api/webhooks/subscriptions/",
            params={"limit": limit, "offset": offset},
        ))

    def create_subscription(self, *, name: str, target_url: str,
                              secret: str = "",
                              event_filters: Optional[List[str]] = None,
                              max_attempts: int = 6,
                              enabled: bool = True) -> Dict[str, Any]:
        return self._client._request("POST", "/api/webhooks/subscriptions/", json={
            "name": name, "target_url": target_url, "secret": secret,
            "event_filters": event_filters or ["*"],
            "max_attempts": max_attempts, "enabled": enabled,
        })

    def delete_subscription(self, sub_id: int) -> Dict[str, Any]:
        return self._client._request("DELETE", f"/api/webhooks/subscriptions/{sub_id}")

    def test(self, sub_id: int, *, event_type: str = "echo.test",
             sample_payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._client._request(
            "POST", f"/api/webhooks/subscriptions/{sub_id}/test",
            json={"event_type": event_type, "sample_payload": sample_payload or {}},
        )

    def list_deliveries(self, *, subscription_id: Optional[int] = None,
                         status: Optional[str] = None,
                         event_type: Optional[str] = None,
                         limit: int = 50, offset: int = 0) -> Page:
        params = {"limit": limit, "offset": offset}
        if subscription_id is not None:
            params["subscription_id"] = subscription_id
        if status:
            params["status"] = status
        if event_type:
            params["event_type"] = event_type
        return Page.from_dict(self._client._request(
            "GET", "/api/webhooks/deliveries/", params=params,
        ))

    def redeliver(self, delivery_id: int) -> Dict[str, Any]:
        return self._client._request(
            "POST", f"/api/webhooks/deliveries/{delivery_id}/redeliver"
        )

class _AuditResource(_Resource):
    def summary(self) -> Dict[str, Any]:
        return self._client._request("GET", "/api/audit/reports/summary")

    def verify_chain(self) -> Dict[str, Any]:
        return self._client._request("GET", "/api/audit/chain/verify")

# =====================================================
# Main client
# =====================================================
class EchoClient:
    """Synchronous Echo client.

    Args:
        base_url: e.g. "https://echo.example.com". Falls back to ECHO_BASE_URL.
        token: Bearer token (JWT). Falls back to ECHO_TOKEN.
        tenant_id: Tenant identifier. Falls back to ECHO_TENANT_ID.
        actor: Demo mode only — sent via X-Echo-Actor.
        roles: Demo mode only — sent via X-Echo-Roles.
        timeout: Per-request timeout in seconds.
        retry: RetryPolicy instance.
        http_client: Optional httpx.Client (advanced use).
    """

    def __init__(
        self,
        base_url: Optional[str] = None,
        token: Optional[str] = None,
        *,
        tenant_id: Optional[str] = None,
        actor: Optional[str] = None,
        roles: Optional[Union[str, List[str]]] = None,
        timeout: float = 30.0,
        retry: Optional[RetryPolicy] = None,
        http_client: Optional[httpx.Client] = None,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.base_url = (
            base_url or os.getenv("ECHO_BASE_URL") or "http://localhost:8000"
        ).rstrip("/")
        self.token = token or os.getenv("ECHO_TOKEN")
        self.tenant_id = tenant_id or os.getenv("ECHO_TENANT_ID") or "default"
        self.actor = actor or os.getenv("ECHO_ACTOR")
        roles_value = roles if roles is not None else os.getenv("ECHO_ROLES")
        if isinstance(roles_value, str):
            self.roles: List[str] = [r.strip() for r in roles_value.split(",") if r.strip()]
        else:
            self.roles = list(roles_value or [])
        self.timeout = timeout
        self.retry = retry or RetryPolicy()
        self.user_agent = user_agent
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            base_url=self.base_url, timeout=self.timeout,
        )

        # Resource namespaces
        self.assets = _AssetsResource(self)
        self.versions = _VersionsResource(self)
        self.changes = _ChangesResource(self)
        self.gate = _GateResource(self)
        self.runtime = _RuntimeResource(self)
        self.evaluations = _EvalResource(self)
        self.webhooks = _WebhooksResource(self)
        self.audit = _AuditResource(self)

    # ---- context manager ----
    def __enter__(self) -> "EchoClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    # ---- helpers ----
    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "User-Agent": self.user_agent,
            "Accept": "application/json",
            "X-Request-ID": str(uuid.uuid4()),
            "X-Echo-Tenant": self.tenant_id,
        }
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
        else:
            if self.actor:
                h["X-Echo-Actor"] = self.actor
            if self.roles:
                h["X-Echo-Roles"] = ",".join(self.roles)
        if extra:
            h.update(extra)
        return h

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health")

    def whoami(self) -> Dict[str, Any]:
        """Returns identity info — useful to verify token/tenant."""
        return self._request("GET", "/api/auth/me")

    # ---- raw request loop with retry ----
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        url = path if path.startswith(("http://", "https://")) else path
        attempt = 0
        last_exc: Optional[Exception] = None
        while True:
            attempt += 1
            try:
                resp = self._client.request(
                    method, url,
                    params={k: v for k, v in (params or {}).items() if v is not None},
                    json=json,
                    headers=self._headers(headers),
                )
            except httpx.RequestError as exc:
                last_exc = exc
                if attempt >= self.retry.max_attempts:
                    raise EchoError(f"Network error: {exc}") from exc
                self.retry.sleep(self.retry.compute_delay(attempt))
                continue

            request_id = resp.headers.get("X-Request-ID")

            if 200 <= resp.status_code < 300:
                if resp.status_code == 204 or not resp.content:
                    return {}
                try:
                    return resp.json()
                except ValueError:
                    return {"raw": resp.text}

            # Parse error body
            try:
                body = resp.json()
            except ValueError:
                body = resp.text

            retry_after: Optional[int] = None
            if resp.status_code == 429:
                try:
                    retry_after = int(resp.headers.get("Retry-After", "1"))
                except ValueError:
                    retry_after = 1

            if self.retry.should_retry(resp.status_code, attempt):
                self.retry.sleep(self.retry.compute_delay(attempt, retry_after))
                continue

            raise from_response(resp.status_code, body, request_id, retry_after)
