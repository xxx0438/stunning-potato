"""Outbound Webhooks dispatcher.

Each tenant can register one or more endpoints, optionally filtered by
event type prefix (e.g. "change.*", "gate.blocked").

Delivery model:
- Every activity event triggers a fan-out into WebhookDelivery rows.
- A background worker picks up pending deliveries, POSTs to the target URL
  with an HMAC-SHA256 signature, and applies exponential backoff on failure.
- Deliveries are tenant-scoped and integrate with Prometheus + audit log.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

import requests
from sqlalchemy.orm import Session

logger = logging.getLogger("echo.webhooks")

# ----------------------- defaults -----------------------
DEFAULT_TIMEOUT = float(os.getenv("ECHO_WEBHOOK_TIMEOUT", "10"))
DEFAULT_MAX_ATTEMPTS = int(os.getenv("ECHO_WEBHOOK_MAX_ATTEMPTS", "6"))
SIGNATURE_HEADER = "X-Echo-Signature"
DELIVERY_HEADER = "X-Echo-Delivery-ID"
TIMESTAMP_HEADER = "X-Echo-Timestamp"
EVENT_HEADER = "X-Echo-Event"
TENANT_HEADER = "X-Echo-Tenant"

def is_enabled() -> bool:
    return os.getenv("ECHO_WEBHOOKS_ENABLED", "1").lower() in ("1", "true", "yes")

def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

# ----------------------- helpers -----------------------
def event_matches(filters: Iterable[str], event_type: str) -> bool:
    """Match event_type against a list of glob-style filters.

    Supported:
    - "*" → match everything
    - "prefix.*" → starts-with
    - exact string
    """
    if not filters:
        return True
    for f in filters:
        if not f:
            continue
        if f == "*":
            return True
        if f.endswith(".*") and event_type.startswith(f[:-1]):
            return True
        if f == event_type:
            return True
    return False

def sign_payload(secret: str, body: bytes, timestamp: str) -> str:
    """HMAC-SHA256 over `timestamp.body`. Mirrors GitHub/Stripe convention."""
    msg = timestamp.encode() + b"." + body
    digest = hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()
    return f"sha256={digest}"

def verify_signature(secret: str, body: bytes, timestamp: str, signature: str,
                     max_age_seconds: int = 300) -> bool:
    """Helper for receivers: verify signature + reject stale timestamps."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs(int(time.time()) - ts) > max_age_seconds:
        return False
    expected = sign_payload(secret, body, timestamp)
    return hmac.compare_digest(expected, signature or "")

# ----------------------- core dispatch -----------------------
def enqueue_for_event(
    db: Session,
    *,
    tenant_id: str,
    event_type: str,
    payload: Dict[str, Any],
    entity_type: str = "",
    entity_id: str = "",
) -> int:
    """Fan-out: create WebhookDelivery rows for every active subscription that
    matches the event_type filter. Returns the number of deliveries enqueued.

    Models are imported lazily from main to avoid a circular import.
    """
    if not is_enabled():
        return 0

    from main import WebhookSubscription, WebhookDelivery  # late import

    subs = (
        db.query(WebhookSubscription)
        .filter(
            WebhookSubscription.tenant_id == tenant_id,
            WebhookSubscription.enabled.is_(True),
        )
        .all()
    )
    enqueued = 0
    for sub in subs:
        filters = sub.event_filters or ["*"]
        if not event_matches(filters, event_type):
            continue
        delivery = WebhookDelivery(
            tenant_id=tenant_id,
            subscription_id=sub.id,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=str(entity_id or ""),
            payload=payload,
            status="pending",
            attempts=0,
            delivery_uuid=str(uuid.uuid4()),
            next_attempt_at=_utcnow(),
        )
        db.add(delivery)
        enqueued += 1
    if enqueued:
        logger.info(
            "webhook.enqueued",
            extra={"tenant": tenant_id, "event": event_type, "count": enqueued},
        )
    return enqueued

def _deliver_one(sub, delivery) -> None:
    """Mutates `delivery` in place. Caller commits the session."""
    body_obj = {
        "id": delivery.delivery_uuid,
        "event": delivery.event_type,
        "tenant_id": delivery.tenant_id,
        "entity_type": delivery.entity_type,
        "entity_id": delivery.entity_id,
        "data": delivery.payload or {},
        "occurred_at": (delivery.created_at or _utcnow()).isoformat(),
    }
    body = json.dumps(body_obj, separators=(",", ":"), default=str).encode()
    timestamp = str(int(time.time()))
    headers = {
        "Content-Type": "application/json",
        EVENT_HEADER: delivery.event_type,
        DELIVERY_HEADER: delivery.delivery_uuid,
        TIMESTAMP_HEADER: timestamp,
        TENANT_HEADER: delivery.tenant_id,
        "User-Agent": "Echo-Webhook/2.4",
    }
    if sub.secret:
        headers[SIGNATURE_HEADER] = sign_payload(sub.secret, body, timestamp)

    delivery.attempts = (delivery.attempts or 0) + 1
    try:
        resp = requests.post(sub.target_url, data=body, headers=headers, timeout=DEFAULT_TIMEOUT)
        delivery.response_code = resp.status_code
        delivery.response_body = (resp.text or "")[:2000]
        if 200 <= resp.status_code < 300:
            delivery.status = "delivered"
            delivery.delivered_at = _utcnow()
            delivery.last_error = ""
            delivery.next_attempt_at = None
            return
        delivery.last_error = f"HTTP {resp.status_code}: {(resp.text or '')[:300]}"
    except requests.RequestException as exc:
        delivery.response_code = 0
        delivery.last_error = str(exc)[:500]

    # ---- failed attempt path ----
    max_attempts = sub.max_attempts or DEFAULT_MAX_ATTEMPTS
    if delivery.attempts >= max_attempts:
        delivery.status = "dead"
        delivery.next_attempt_at = None
    else:
        # Exponential backoff: 60s, 120s, 240s, ..., capped at 1h.
        delay = min(60 * (2 ** (delivery.attempts - 1)), 3600)
        delivery.status = "failed"
        delivery.next_attempt_at = _utcnow() + timedelta(seconds=delay)
from app import metrics as _metrics
_metrics.inc_webhook(delivery.status, delivery.event_type, delivery.tenant_id)
def flush_due(db: Session, limit: int = 25) -> int:
    """Pick up due pending/failed deliveries and try to send them.

    Returns the number processed.
    """
    if not is_enabled():
        return 0
    from main import WebhookDelivery, WebhookSubscription  # late import

    now = _utcnow()
    deliveries = (
        db.query(WebhookDelivery)
        .filter(WebhookDelivery.status.in_(("pending", "failed")))
        .filter(
            (WebhookDelivery.next_attempt_at.is_(None))
            | (WebhookDelivery.next_attempt_at <= now)
        )
        .order_by(WebhookDelivery.id.asc())
        .limit(limit)
        .all()
    )
    processed = 0
    for delivery in deliveries:
        sub = db.query(WebhookSubscription).filter(
            WebhookSubscription.id == delivery.subscription_id
        ).first()
        if not sub or not sub.enabled:
            delivery.status = "dead"
            delivery.last_error = "Subscription missing or disabled"
            delivery.next_attempt_at = None
            processed += 1
            continue
        _deliver_one(sub, delivery)
        processed += 1
    if processed:
        db.commit()
    return processed
