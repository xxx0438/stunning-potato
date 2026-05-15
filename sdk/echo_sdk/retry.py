"""Retry policy with exponential backoff + jitter."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Iterable

DEFAULT_RETRY_STATUSES = (429, 500, 502, 503, 504)

@dataclass
class RetryPolicy:
    max_attempts: int = 3
    initial_delay: float = 0.5
    backoff: float = 2.0
    max_delay: float = 30.0
    jitter: float = 0.25
    retry_statuses: Iterable[int] = DEFAULT_RETRY_STATUSES

    def should_retry(self, status_code: int, attempt: int) -> bool:
        return attempt < self.max_attempts and status_code in self.retry_statuses

    def compute_delay(self, attempt: int, retry_after: float | None = None) -> float:
        if retry_after is not None and retry_after >= 0:
            return min(retry_after, self.max_delay)
        base = min(self.initial_delay * (self.backoff ** max(attempt - 1, 0)), self.max_delay)
        if self.jitter:
            base += random.uniform(-self.jitter * base, self.jitter * base)
        return max(0.0, base)

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)
