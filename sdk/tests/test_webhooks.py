"""Webhook signing & verification tests."""

from __future__ import annotations

from echo_sdk.webhooks import sign_webhook, verify_webhook

def test_sign_and_verify_round_trip():
    secret = "shhh"
    body = b'{"event":"change.created"}'
    ts = "1700000000"
    sig = sign_webhook(secret, body, ts)
    headers = {
        "X-Echo-Signature": sig,
        "X-Echo-Timestamp": ts,
    }
    # Use very large max_age so we don't depend on real time.
    assert verify_webhook(secret, body, headers, max_age_seconds=10**12)

def test_verify_rejects_bad_signature():
    headers = {
        "X-Echo-Signature": "sha256=deadbeef",
        "X-Echo-Timestamp": "1700000000",
    }
    assert not verify_webhook("secret", b"{}", headers, max_age_seconds=10**12)

def test_verify_rejects_wrong_secret():
    body = b'{"x":1}'
    ts = "1700000000"
    sig = sign_webhook("right", body, ts)
    headers = {"X-Echo-Signature": sig, "X-Echo-Timestamp": ts}
    assert not verify_webhook("wrong", body, headers, max_age_seconds=10**12)

def test_verify_rejects_stale_timestamp():
    body = b'{"x":1}'
    ts = "1000000000"  # year 2001 — far older than 300s window
    sig = sign_webhook("secret", body, ts)
    headers = {"X-Echo-Signature": sig, "X-Echo-Timestamp": ts}
    assert not verify_webhook("secret", body, headers, max_age_seconds=300)

def test_verify_headers_are_case_insensitive():
    body = b'{"x":1}'
    ts = "1700000000"
    sig = sign_webhook("secret", body, ts)
    headers = {"x-echo-signature": sig, "x-echo-timestamp": ts}
    assert verify_webhook("secret", body, headers, max_age_seconds=10**12)

def test_verify_missing_headers():
    assert not verify_webhook("s", b"{}", {}, max_age_seconds=10**12)
    assert not verify_webhook("s", b"{}", {"X-Echo-Signature": "x"},
                                max_age_seconds=10**12)

def test_sign_accepts_str_and_bytes():
    a = sign_webhook("s", "body", "100")
    b = sign_webhook(b"s", b"body", "100")
    assert a == b
