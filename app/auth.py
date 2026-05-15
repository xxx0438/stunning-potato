"""Echo 身份认证模块（JWT + demo 双模式）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from contextvars import ContextVar
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request

# ============== ContextVar ==============
current_tenant: ContextVar[Optional[str]] = ContextVar("current_tenant", default=None)
current_actor: ContextVar[str] = ContextVar("current_actor", default="-")
current_roles: ContextVar[tuple] = ContextVar("current_roles", default=())

# ============== JWT 编解码 ==============
def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def jwt_encode(payload: Dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
    if algorithm != "HS256":
        raise NotImplementedError("Only HS256 is supported in the built-in encoder.")
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_encode(sig)}"

def jwt_decode(token: str, secret: str, verify_exp: bool = True) -> Dict[str, Any]:
    try:
        h_b64, p_b64, s_b64 = token.split(".")
    except ValueError:
        raise HTTPException(status_code=401, detail="Malformed JWT")

    try:
        header = json.loads(_b64url_decode(h_b64))
        payload = json.loads(_b64url_decode(p_b64))
        signature = _b64url_decode(s_b64)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid JWT encoding")

    if header.get("alg") != "HS256":
        raise HTTPException(status_code=401, detail=f"Unsupported JWT alg: {header.get('alg')}")

    expected = hmac.new(secret.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=401, detail="Invalid JWT signature")

    if verify_exp:
        exp = payload.get("exp")
        if exp is not None and int(time.time()) >= int(exp):
            raise HTTPException(status_code=401, detail="JWT expired")

    iss = payload.get("iss")
    expected_iss = os.getenv("ECHO_JWT_ISSUER")
    if expected_iss and iss != expected_iss:
        raise HTTPException(status_code=401, detail=f"Invalid issuer: {iss}")

    aud = payload.get("aud")
    expected_aud = os.getenv("ECHO_JWT_AUDIENCE")
    if expected_aud and aud != expected_aud:
        raise HTTPException(status_code=401, detail=f"Invalid audience: {aud}")

    return payload

# ============== 主鉴权 ==============
def _auth_mode() -> str:
    return os.getenv("ECHO_AUTH_MODE", "demo").lower()

def _jwt_secret() -> str:
    secret = os.getenv("ECHO_JWT_SECRET", "")
    if not secret and _auth_mode() == "jwt":
        raise HTTPException(status_code=500, detail="ECHO_JWT_SECRET is not configured")
    return secret

def authenticate(request: Request) -> Dict[str, Any]:
    mode = _auth_mode()

    if mode == "demo":
        actor = request.headers.get("X-Echo-Actor") or "demo-user"
        roles_raw = request.headers.get("X-Echo-Roles") or "viewer"
        roles = [r.strip() for r in roles_raw.split(",") if r.strip()]
        tenant_id = (
            request.headers.get("X-Echo-Tenant")
            or os.getenv("ECHO_DEFAULT_TENANT_ID", "default")
        )
    elif mode == "jwt":
        auth_header = request.headers.get("Authorization") or ""
        if not auth_header.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer token")
        token = auth_header.split(" ", 1)[1].strip()
        payload = jwt_decode(token, _jwt_secret())
        actor = str(payload.get("sub") or payload.get("username") or "")
        if not actor:
            raise HTTPException(status_code=401, detail="JWT missing 'sub'")
        tenant_id = str(payload.get("tenant_id") or "")
        if not tenant_id:
            raise HTTPException(status_code=401, detail="JWT missing 'tenant_id'")
        roles_raw = payload.get("roles") or []
        roles = (
            [r.strip() for r in roles_raw.split(",") if r.strip()]
            if isinstance(roles_raw, str)
            else [str(r) for r in roles_raw]
        )
    else:
        raise HTTPException(status_code=500, detail=f"Unknown ECHO_AUTH_MODE: {mode}")

    current_tenant.set(tenant_id)
    current_actor.set(actor)
    current_roles.set(tuple(roles))

    return {"actor": actor, "roles": roles, "tenant_id": tenant_id}

# ============== 角色检查 ==============
def has_role(context: Dict[str, Any], allowed: List[str]) -> bool:
    roles = set(context.get("roles") or [])
    if "admin" in roles:
        return True
    return bool(roles & set(allowed))

def require_role(allowed: List[str]):
    def _check(context: Dict[str, Any] = Depends(authenticate)) -> Dict[str, Any]:
        if not has_role(context, allowed):
            raise HTTPException(
                status_code=403,
                detail=f"Requires one of roles: {', '.join(allowed)}",
            )
        return context
    return _check

# ============== 工具 ==============
def issue_demo_token(
    username: str,
    tenant_id: str = "default",
    roles: Optional[List[str]] = None,
    ttl_seconds: int = 3600,
) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "tenant_id": tenant_id,
        "roles": roles or ["viewer"],
        "iat": now,
        "exp": now + ttl_seconds,
        "iss": os.getenv("ECHO_JWT_ISSUER", "echo-local"),
    }
    return jwt_encode(payload, _jwt_secret() or "dev-secret-please-change")
