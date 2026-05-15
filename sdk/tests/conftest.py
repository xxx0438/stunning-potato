"""Shared pytest fixtures for SDK tests."""

from __future__ import annotations

import httpx
import pytest
import respx

from echo_sdk import EchoClient
from echo_sdk.retry import RetryPolicy

@pytest.fixture
def base_url() -> str:
    return "https://echo.test"

@pytest.fixture
def client(base_url: str) -> EchoClient:
    """A real EchoClient routed through respx mocks."""
    c = EchoClient(
        base_url=base_url,
        token="test-token",
        tenant_id="tenant-a",
        retry=RetryPolicy(max_attempts=1),  # disable retries by default
    )
    try:
        yield c
    finally:
        c.close()

@pytest.fixture
def respx_mock() -> respx.Router:
    """Per-test respx Router scoped to the test base_url."""
    with respx.mock(base_url="https://echo.test", assert_all_called=False) as router:
        yield router
