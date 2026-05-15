"""Exception hierarchy for the Echo SDK."""

from __future__ import annotations

from typing import Any, Optional

class EchoError(Exception):
    """Base class for all SDK errors."""

class EchoAPIError(EchoError):
    """Raised when the Echo API returns a non-2xx response."""

    def __init__(
        self,
        message: str,
        status_code: int,
        body: Optional[Any] = None,
        request_id: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body
        self.request_id = request_id

    def __str__(self) -> str:
        base = super().__str__()
        bits = [f"status={self.status_code}"]
        if self.request_id:
            bits.append(f"request_id={self.request_id}")
        return f"{base} ({', '.join(bits)})"

class AuthenticationError(EchoAPIError):
    """401 — missing/invalid credentials."""

class PermissionDeniedError(EchoAPIError):
    """403 — authenticated but lacks required role."""

class NotFoundError(EchoAPIError):
    """404 — resource not found / not visible to this tenant."""

class ValidationError(EchoAPIError):
    """400/422 — request payload rejected."""

class RateLimitError(EchoAPIError):
    """429 — rate limit exceeded. `retry_after` is in seconds."""

    def __init__(self, *args: Any, retry_after: Optional[int] = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.retry_after = retry_after

def from_response(status_code: int, body: Any, request_id: Optional[str] = None,
                  retry_after: Optional[int] = None) -> EchoAPIError:
    """Map HTTP status → typed exception."""
    detail = body.get("detail") if isinstance(body, dict) else str(body)
    msg = detail or f"HTTP {status_code}"
    if status_code == 401:
        return AuthenticationError(msg, status_code, body, request_id)
    if status_code == 403:
        return PermissionDeniedError(msg, status_code, body, request_id)
    if status_code == 404:
        return NotFoundError(msg, status_code, body, request_id)
    if status_code in (400, 422):
        return ValidationError(msg, status_code, body, request_id)
    if status_code == 429:
        return RateLimitError(msg, status_code, body, request_id, retry_after=retry_after)
    return EchoAPIError(msg, status_code, body, request_id)
