"""Asynchronous Echo client (mirrors EchoClient API)."""

from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any, Dict, List, Optional, Union

import httpx

from echo_sdk import __version__
from echo_sdk.exceptions import EchoError, from_response
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

DEFAULT_USER_AGENT = f"echo-sdk-python-async/{__version__}"

class AsyncEchoClient:
    """Async counterpart to EchoClient. Same surface, awaitable methods."""

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
        http_client: Optional[httpx.AsyncClient] = None,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.base_url = (base_url or os.getenv("ECHO_BASE_URL") or "http://localhost:8000").rstrip("/")
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
        self._client = http_client or httpx.AsyncClient(
            base_url=self.base_url, timeout=self.timeout,
        )

    async def __aenter__(self) -> "AsyncEchoClient":
        return self

    async def __aexit__(self, *_exc: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

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

    async def _request(self, method: str, path: str, *,
                        params: Optional[Dict[str, Any]] = None,
                        json: Optional[Dict[str, Any]] = None,
                        headers: Optional[Dict[str, str]] = None) -> Any:
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = await self._client.request(
                    method, path,
                    params={k: v for k, v in (params or {}).items() if v is not None},
                    json=json,
                    headers=self._headers(headers),
                )
            except httpx.RequestError as exc:
                if attempt >= self.retry.max_attempts:
                    raise EchoError(f"Network error: {exc}") from exc
                await asyncio.sleep(self.retry.compute_delay(attempt))
                continue

            request_id = resp.headers.get("X-Request-ID")
            if 200 <= resp.status_code < 300:
                if resp.status_code == 204 or not resp.content:
                    return {}
                try:
                    return resp.json()
                except ValueError:
                    return {"raw": resp.text}
            try:
                body = resp.json()
            except ValueError:
                body = resp.text
            retry_after = None
            if resp.status_code == 429:
                try:
                    retry_after = int(resp.headers.get("Retry-After", "1"))
                except ValueError:
                    retry_after = 1
            if self.retry.should_retry(resp.status_code, attempt):
                await asyncio.sleep(self.retry.compute_delay(attempt, retry_after))
                continue
            raise from_response(resp.status_code, body, request_id, retry_after)

    # --- public methods (subset; mirrors the sync client) ---
    async def health(self) -> Dict[str, Any]:
        return await self._request("GET", "/health")

    async def whoami(self) -> Dict[str, Any]:
        return await self._request("GET", "/api/auth/me")

    async def gate_check(self, *, commit_sha: str, is_ai_related: bool = False,
                          provider: Optional[str] = None,
                          project_id: Optional[str] = None,
                          mr_iid: Optional[str] = None,
                          pipeline_id: Optional[str] = None) -> GateResult:
        data = await self._request("POST", "/api/ci/gate/check", json={
            "commit_sha": commit_sha, "is_ai_related": is_ai_related,
            "provider": provider, "project_id": project_id,
            "mr_iid": mr_iid, "pipeline_id": pipeline_id,
        })
        return GateResult.from_dict(data)

    async def guardrail_check(self, *,
                                asset_version_id: Optional[int] = None,
                                asset_name: Optional[str] = None,
                                tool_name: str = "",
                                tool_args: Optional[Dict[str, Any]] = None,
                                input_variables: Optional[Dict[str, Any]] = None,
                                actor: str = "") -> RuntimeGuardrailResult:
        data = await self._request("POST", "/api/runtime/guardrails/check", json={
            "asset_version_id": asset_version_id,
            "asset_name": asset_name,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            "input_variables": input_variables or {},
            "actor": actor,
        })
        return RuntimeGuardrailResult.from_dict(data)

    async def list_assets(self, **kwargs: Any) -> Page:
        params = {k: v for k, v in kwargs.items() if v is not None}
        data = await self._request("GET", "/api/assets/", params=params)
        return Page.from_dict(data, item_cls=Asset)

    async def create_change(self, *, commit_sha: str, created_by: str,
                              **kwargs: Any) -> ChangeRequest:
        body = {"commit_sha": commit_sha, "created_by": created_by, **kwargs}
        data = await self._request("POST", "/api/changes/", json=body)
        return ChangeRequest.from_dict(data)

    async def run_evaluation(self, *, suite_id: int, asset_version_id: int,
                              **kwargs: Any) -> EvaluationRun:
        body = {"suite_id": suite_id, "asset_version_id": asset_version_id, **kwargs}
        data = await self._request("POST", "/api/evaluations/run", json=body)
        return EvaluationRun.from_dict(data)
