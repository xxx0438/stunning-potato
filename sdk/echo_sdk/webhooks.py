"""Webhook verification & signing helpers for receivers."""

from __future__ import annotations

import hashlib
import hmac
import time
from typing import Mapping, Union

BytesOrStr = Union[bytes, str]

def _encode(value: BytesOrStr) -> bytes:
    return value.encode() if isinstance(value, str) else value

def sign_webhook(secret: BytesOrStr, body: BytesOrStr, timestamp: Union[str, int]) -> str:
    """Compute the signature for outgoing webhooks.

    Format: ``sha256=<hex>`` over ``timestamp + '.' + body``.
    """
    secret_b = _encode(secret)
    body_b = _encode(body)
    ts = str(timestamp).encode()
    digest = hmac.new(secret_b, ts + b"." + body_b, hashlib.sha256).hexdigest()
    return f"sha256={digest}"

def verify_webhook(
    secret: BytesOrStr,
    body: BytesOrStr,
    headers: Mapping[str, str],
    *,
    max_age_seconds: int = 300,
    now: float | None = None,
) -> bool:
    """Verify an incoming webhook from Echo.

    Reads ``X-Echo-Signature`` + ``X-Echo-Timestamp`` from headers, recomputes
    the HMAC, and rejects stale events (>= max_age_seconds drift).

    Headers are matched case-insensitively (per RFC 7230).
    """
    norm = {k.lower(): v for k, v in headers.items()}
    sig = norm.get("x-echo-signature", "")
    ts = norm.get("x-echo-timestamp", "")
    if not sig or not ts:
        return False
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return False
    current = int(now if now is not None else time.time())
    if abs(current - ts_int) > max_age_seconds:
        return False
    expected = sign_webhook(secret, body, ts)
    return hmac.compare_digest(expected, sig)
