"""活动事件 hash chain：防止审计日志篡改。

每条 ActivityEvent 写入时计算 SHA-256(prev_hash + canonical_payload)，
形成单向链。验证时重算 hash 与持久化的字段比对。

环境变量：
- ECHO_HASHCHAIN_ENABLED=1   启用（默认开）
- ECHO_HASHCHAIN_SECRET=...  可选 HMAC secret，避免攻击者重算
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Optional

def is_enabled() -> bool:
    return os.getenv("ECHO_HASHCHAIN_ENABLED", "1").lower() in ("1", "true", "yes")

def _secret() -> Optional[bytes]:
    s = os.getenv("ECHO_HASHCHAIN_SECRET", "")
    return s.encode() if s else None

def _canonical_dump(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)

def compute_hash(prev_hash: Optional[str], record: Dict[str, Any]) -> str:
    """计算一条记录的链 hash。"""
    base = (prev_hash or "GENESIS") + "\n" + _canonical_dump(record)
    secret = _secret()
    if secret:
        return hmac.new(secret, base.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(base.encode()).hexdigest()

def build_record(actor: str, action: str, entity_type: str, entity_id: str,
                 summary: str, payload: Dict[str, Any], created_at_iso: str) -> Dict[str, Any]:
    """构造参与 hash 的字段集（不含 hash 自身和 id）。"""
    return {
        "actor": actor or "",
        "action": action,
        "entity_type": entity_type,
        "entity_id": entity_id or "",
        "summary": summary or "",
        "payload": payload or {},
        "created_at": created_at_iso,
    }

def verify_chain(events: list) -> Dict[str, Any]:
    """校验整条链。events 按 id asc 排序。"""
    prev = None
    broken = []
    for ev in events:
        record = build_record(
            actor=ev.actor, action=ev.action, entity_type=ev.entity_type,
            entity_id=ev.entity_id, summary=ev.summary, payload=ev.payload or {},
            created_at_iso=ev.created_at.isoformat() if ev.created_at else "",
        )
        expected = compute_hash(prev, record)
        if ev.hash_value and ev.hash_value != expected:
            broken.append({"id": ev.id, "expected": expected, "actual": ev.hash_value})
        prev = ev.hash_value or expected
    return {"total": len(events), "broken_count": len(broken), "broken": broken[:50]}
