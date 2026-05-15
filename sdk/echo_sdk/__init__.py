"""Echo Agent Governance — Python SDK.

Usage:
    from echo_sdk import EchoClient

    client = EchoClient(
        base_url="https://echo.example.com",
        token="ey...",
        tenant_id="tenant-a",
    )

    # CI gate
    result = client.gate.check(commit_sha="abc123", is_ai_related=True)
    if result.status == "block":
        sys.exit(1)

    # Runtime guardrail
    decision = client.runtime.guardrail_check(
        asset_name="loan_agent",
        tool_name="lookup_policy",
        tool_args={"amount": 1500},
        input_variables={"user_message": "..."},
    )
    if decision.status == "block":
        raise PermissionError("Tool call blocked by policy")

    # Webhook verification
    from echo_sdk import verify_webhook
    if not verify_webhook(secret, request.body, request.headers):
        return 401
"""

from echo_sdk.async_client import AsyncEchoClient
from echo_sdk.client import EchoClient
from echo_sdk.exceptions import (
    AuthenticationError,
    EchoAPIError,
    EchoError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    ValidationError,
)
from echo_sdk.models import (
    Asset,
    AssetVersion,
    ChangeRequest,
    EvaluationRun,
    GateResult,
    GuardrailFinding,
    RuntimeGuardrailResult,
)
from echo_sdk.webhooks import sign_webhook, verify_webhook

__version__ = "2.5.0"

__all__ = [
    "AsyncEchoClient",
    "EchoClient",
    "EchoError",
    "EchoAPIError",
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "RateLimitError",
    "ValidationError",
    "Asset",
    "AssetVersion",
    "ChangeRequest",
    "EvaluationRun",
    "GateResult",
    "GuardrailFinding",
    "RuntimeGuardrailResult",
    "verify_webhook",
    "sign_webhook",
    "__version__",
]
