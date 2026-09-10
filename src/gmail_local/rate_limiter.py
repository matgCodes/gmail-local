"""Rate limiting, rolling quota window, and exponential backoff retry management."""

import random
import threading
import time
from collections import deque
from typing import Callable, Deque, Optional, Tuple, TypeVar

from googleapiclient.errors import HttpError

from gmail_local.config import (
    INITIAL_BACKOFF_SCHEDULE,
    MAX_CONCURRENT_REQUESTS,
    MAX_RETRIES,
    MAX_RETRY_DEADLINE_SECS,
    METHOD_QUOTA_COSTS,
    RATE_LIMIT_MAX_UNITS,
    RATE_LIMIT_WINDOW_SECS,
)

T = TypeVar("T")


class RateLimitExceededError(Exception):
    """Raised when the application 3,000-unit rolling budget would be exceeded."""


class RequestDeadlineExceededError(Exception):
    """Raised when retries exceed the 60-second total retry deadline."""


class RateLimiter:
    """Manages rolling 60s quota tracking, concurrency caps, and jittered backoff."""

    def __init__(
        self,
        max_units: int = RATE_LIMIT_MAX_UNITS,
        window_secs: int = RATE_LIMIT_WINDOW_SECS,
        max_concurrent: int = MAX_CONCURRENT_REQUESTS,
        max_retries: int = MAX_RETRIES,
        max_deadline_secs: float = MAX_RETRY_DEADLINE_SECS,
        backoff_schedule: Optional[list] = None,
    ):
        self.max_units = max_units
        self.window_secs = window_secs
        self.max_concurrent = max_concurrent
        self.max_retries = max_retries
        self.max_deadline_secs = max_deadline_secs
        self.backoff_schedule = backoff_schedule or list(INITIAL_BACKOFF_SCHEDULE)

        self._lock = threading.Lock()
        self._semaphore = threading.Semaphore(self.max_concurrent)
        self._history: Deque[Tuple[float, int]] = deque()  # (timestamp, units)

    def _purge_expired(self, now: float) -> None:
        """Remove quota events older than window_secs."""
        cutoff = now - self.window_secs
        while self._history and self._history[0][0] < cutoff:
            self._history.popleft()

    def current_units_in_window(self, now: Optional[float] = None) -> int:
        """Calculate total quota units consumed in the current rolling window."""
        t = now if now is not None else time.time()
        with self._lock:
            self._purge_expired(t)
            return sum(units for _, units in self._history)

    def acquire_quota(self, method_name: str, now: Optional[float] = None) -> int:
        """Check and acquire quota units for a method.

        Raises RateLimitExceededError if budget is exhausted.
        """
        cost = METHOD_QUOTA_COSTS.get(method_name, 20)
        with self._lock:
            t = now if now is not None else time.time()
            self._purge_expired(t)
            current = sum(units for _, units in self._history)
            if current + cost > self.max_units:
                raise RateLimitExceededError(
                    f"Rolling 60s budget exceeded: requested {cost} units, "
                    f"currently at {current}/{self.max_units} units."
                )
            self._history.append((t, cost))
        return cost

    def is_retryable_error(self, err: Exception) -> bool:
        """Classify if an error is eligible for exponential backoff retries."""
        if isinstance(err, HttpError):
            status = err.resp.status
            if status in (429, 500, 502, 503, 504):
                return True
            if status == 403:
                # Check for rateLimitExceeded / userRateLimitExceeded
                err_str = str(err).lower()
                if "ratelimitexceeded" in err_str or "userratelimitexceeded" in err_str:
                    return True
        return False

    def execute_with_retry(
        self,
        method_name: str,
        operation: Callable[[], T],
        sleep_fn: Callable[[float], None] = time.sleep,
    ) -> T:
        """Executes operation with quota tracking, concurrency cap, and jittered retries."""
        self._semaphore.acquire()
        try:
            start_time = time.time()
            attempts = 0

            while True:
                # Acquire quota units before making call
                self.acquire_quota(method_name)
                try:
                    return operation()
                except Exception as err:
                    attempts += 1
                    if not self.is_retryable_error(err) or attempts > self.max_retries:
                        raise

                    elapsed = time.time() - start_time
                    if elapsed >= self.max_deadline_secs:
                        raise RequestDeadlineExceededError(
                            f"Retry deadline of {self.max_deadline_secs}s exceeded after {attempts} attempts."
                        ) from err

                    # Calculate jittered backoff delay
                    base_idx = min(attempts - 1, len(self.backoff_schedule) - 1)
                    base_delay = self.backoff_schedule[base_idx]
                    jitter = random.uniform(0.0, 1.0)
                    delay = base_delay + jitter

                    # Check if sleep exceeds remaining deadline
                    if elapsed + delay > self.max_deadline_secs:
                        raise RequestDeadlineExceededError(
                            f"Next retry delay ({delay:.1f}s) would exceed deadline of {self.max_deadline_secs}s."
                        ) from err

                    sleep_fn(delay)
        finally:
            self._semaphore.release()
