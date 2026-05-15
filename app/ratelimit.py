"""API rate limiting（内存滑动窗口；多副本部署建议替换为 Redis）。

每个 tenant + path 组合一个独立桶。
通过环境变量配置：
- ECHO_RATELIMIT_ENABLED=1
- ECHO_RATELIMIT_PER_MINUTE=120   每分钟请求数（默认）
- ECHO_RATELIMIT_BURST=30         突发额度
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import HTTPException, Request

from app import metrics
from app.auth import current_tenant

def is_enabled() -> bool:
    return os.getenv("ECHO_RATELIMIT_ENABLED", "0").lower() in ("1", "true", "yes")

_lock = threading.Lock()
_buckets: Dict[Tuple[str, str], Deque[float]] = defaultdict(deque)

def _config() -> Tuple[int, float]:
    per_min = int(os.getenv("ECHO_RATELIMIT_PER_MINUTE", "120"))
    burst = int(os.getenv("ECHO_RATELIMIT_BURST", "30"))
    # 实际 cap = per_min + burst，窗口 60s
    return per_min + burst, 60.0

def _bucket_key(request: Request) -> Tuple[str, str]:
    tenant = current_tenant.get() or "-"
    # 按 path prefix 聚合，避免 path 爆炸
    path = request.url.path
    # 只取前两段
    parts = path.strip("/").split("/")
    bucket_path = "/" + "/".join(parts[:3]) if parts else "/"
    return (tenant, bucket_path)

def check_rate_limit(request: Request) -> None:
    """FastAPI 依赖：超限时抛 429。"""
    if not is_enabled():
        return
    # 健康检查 / metrics / docs 不限流
    if request.url.path in ("/health", "/metrics", "/docs", "/openapi.json", "/redoc"):
        return

    key = _bucket_key(request)
    cap, window = _config()
    now = time.monotonic()
    cutoff = now - window

    with _lock:
        q = _buckets[key]
        # 清理过期
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= cap:
            retry_after = max(1, int(q[0] + window - now))
            metrics.inc_ratelimit_rejection(bucket=key[1], tenant=key[0])
            raise HTTPException(
                status_code=429,
                detail=f"Rate limit exceeded ({cap}/min for {key[1]}); retry in {retry_after}s",
                headers={"Retry-After": str(retry_after)},
            )
        q.append(now)

def reset_all() -> None:
    """测试用：清空所有桶。"""
    with _lock:
        _buckets.clear()
