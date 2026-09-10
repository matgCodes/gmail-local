"""Tests for RateLimiter and backoff retries."""

import time
import pytest
from googleapiclient.errors import HttpError
from httplib2 import Response

from gmail_local.config import (
    METHOD_QUOTA_COSTS,
    RATE_LIMIT_MAX_UNITS,
    RATE_LIMIT_WINDOW_SECS,
)
from gmail_local.rate_limiter import (
    RateLimiter,
    RateLimitExceededError,
    RequestDeadlineExceededError,
)


def test_quota_tracking_and_exhaustion():
    limiter = RateLimiter(max_units=100, window_secs=60)

    # 4 calls to messages.get @ 20 units = 80 units
    for _ in range(4):
        cost = limiter.acquire_quota("users.messages.get")
        assert cost == 20

    assert limiter.current_units_in_window() == 80

    # 5th call @ 20 units brings total to 100 units
    cost5 = limiter.acquire_quota("users.messages.get")
    assert cost5 == 20
    assert limiter.current_units_in_window() == 100

    # 6th call exceeds max_units (100)
    with pytest.raises(RateLimitExceededError) as excinfo:
        limiter.acquire_quota("users.messages.get")
    assert "requested 20 units" in str(excinfo.value)
    assert "currently at 100/100 units" in str(excinfo.value)


def test_acquire_quota_method_costs_and_default():
    limiter = RateLimiter()
    # Known method costs
    assert limiter.acquire_quota("users.messages.list", now=10.0) == 5
    assert limiter.acquire_quota("users.messages.get", now=10.0) == 20
    assert limiter.acquire_quota("users.messages.attachments.get", now=10.0) == 20
    assert limiter.acquire_quota("users.history.list", now=10.0) == 2
    assert limiter.acquire_quota("users.labels.list", now=10.0) == 1
    # Unknown method falls back to default 20
    assert limiter.acquire_quota("users.messages.unknownMethod", now=10.0) == 20
    assert limiter.current_units_in_window(now=10.0) == 68


def test_is_retryable_error():
    limiter = RateLimiter()

    # All standard retryable status codes
    for status in (429, 500, 502, 503, 504):
        err = HttpError(Response({"status": status}), b"Transient Error")
        assert limiter.is_retryable_error(err) is True, f"Status {status} must be retryable"

    # Non-retryable 5xx status codes
    for status in (501, 505):
        err = HttpError(Response({"status": status}), b"Server Error")
        assert limiter.is_retryable_error(err) is False, f"Status {status} must not be retryable"

    # 403 variants
    err403_rate = HttpError(Response({"status": 403}), b"rateLimitExceeded")
    assert limiter.is_retryable_error(err403_rate) is True

    err403_user_rate = HttpError(Response({"status": 403}), b"userRateLimitExceeded")
    assert limiter.is_retryable_error(err403_user_rate) is True

    err403_perm = HttpError(Response({"status": 403}), b"insufficientPermissions")
    assert limiter.is_retryable_error(err403_perm) is False

    # Other non-retryable codes
    for status in (400, 401, 404, 409):
        err = HttpError(Response({"status": status}), b"Client Error")
        assert limiter.is_retryable_error(err) is False, f"Status {status} must not be retryable"

    # Non-HttpError exceptions
    assert limiter.is_retryable_error(ValueError("error")) is False
    assert limiter.is_retryable_error(Exception()) is False


def test_execute_with_retry_succeeds_after_transient():
    limiter = RateLimiter(max_retries=3, max_deadline_secs=10)
    attempts = 0
    sleeps = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise HttpError(Response({"status": 429}), b"Too many requests")
        return "SUCCESS"

    result = limiter.execute_with_retry(
        "users.messages.list",
        mock_op,
        sleep_fn=lambda s: sleeps.append(s),
    )

    assert result == "SUCCESS"
    assert attempts == 3
    assert len(sleeps) == 2
    # Check that each sleep delay has jitter within [schedule, schedule + 1.0]
    assert 1.0 <= sleeps[0] <= 2.0
    assert 2.0 <= sleeps[1] <= 3.0
    # Quota charged 3 times @ 5 units = 15 units
    assert limiter.current_units_in_window() == 15


def test_execute_with_retry_non_retryable_raises_immediately():
    limiter = RateLimiter(max_retries=3, max_deadline_secs=10)
    attempts = 0
    sleeps = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        raise HttpError(Response({"status": 401}), b"Unauthorized")

    with pytest.raises(HttpError) as excinfo:
        limiter.execute_with_retry(
            "users.messages.get",
            mock_op,
            sleep_fn=lambda s: sleeps.append(s),
        )

    assert excinfo.value.resp.status == 401
    assert attempts == 1
    assert len(sleeps) == 0


def test_execute_with_retry_exceeds_max_retries_raises_original():
    limiter = RateLimiter(max_retries=2, max_deadline_secs=100)
    attempts = 0
    sleeps = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        raise HttpError(Response({"status": 503}), b"Service Unavailable")

    with pytest.raises(HttpError) as excinfo:
        limiter.execute_with_retry(
            "users.messages.list",
            mock_op,
            sleep_fn=lambda s: sleeps.append(s),
        )

    assert excinfo.value.resp.status == 503
    # Initial attempt + 2 retries = 3 attempts total
    assert attempts == 3
    assert len(sleeps) == 2


def test_execute_with_retry_fails_on_deadline():
    limiter = RateLimiter(max_retries=5, max_deadline_secs=0.01)

    def mock_op():
        time.sleep(0.02)
        raise HttpError(Response({"status": 429}), b"Too many requests")

    with pytest.raises(RequestDeadlineExceededError) as excinfo:
        limiter.execute_with_retry("users.messages.list", mock_op, sleep_fn=lambda s: None)

    assert "Retry deadline of 0.01s exceeded after" in str(excinfo.value)


def test_execute_with_retry_next_delay_exceeds_deadline():
    """When current elapsed is within deadline, but adding next delay exceeds it."""
    limiter = RateLimiter(max_retries=5, max_deadline_secs=1.5, backoff_schedule=[2.0])

    def mock_op():
        raise HttpError(Response({"status": 429}), b"Too many requests")

    with pytest.raises(RequestDeadlineExceededError) as excinfo:
        limiter.execute_with_retry("users.messages.list", mock_op, sleep_fn=lambda s: None)

    assert "Next retry delay" in str(excinfo.value)
    assert "would exceed deadline of 1.5s" in str(excinfo.value)


def test_execute_with_retry_backoff_schedule_clamping():
    """When retries exceed backoff_schedule length, delay clamps to last schedule element."""
    limiter = RateLimiter(
        max_retries=4,
        max_deadline_secs=100,
        backoff_schedule=[1.0, 2.0],  # Length 2
    )
    attempts = 0
    delays = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        if attempts < 4:
            raise HttpError(Response({"status": 503}), b"Service Unavailable")
        return "OK"

    limiter.execute_with_retry(
        "users.messages.list",
        mock_op,
        sleep_fn=lambda d: delays.append(d),
    )

    assert len(delays) == 3
    # Attempt 1 -> index 0 (1.0 + jitter)
    assert 1.0 <= delays[0] <= 2.0
    # Attempt 2 -> index 1 (2.0 + jitter)
    assert 2.0 <= delays[1] <= 3.0
    # Attempt 3 -> index clamped to 1 (2.0 + jitter)
    assert 2.0 <= delays[2] <= 3.0


def test_execute_with_retry_exact_jitter_call(monkeypatch):
    """Verify random.uniform is called with exact range (0.0, 1.0)."""
    uniform_calls = []

    def mock_uniform(a, b):
        uniform_calls.append((a, b))
        return 0.42

    monkeypatch.setattr("random.uniform", mock_uniform)

    limiter = RateLimiter(max_retries=1, max_deadline_secs=10, backoff_schedule=[5.0])
    attempts = 0
    sleeps = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HttpError(Response({"status": 503}), b"Fail")
        return "OK"

    limiter.execute_with_retry("users.messages.list", mock_op, sleep_fn=lambda s: sleeps.append(s))
    assert uniform_calls == [(0.0, 1.0)]
    assert sleeps == [5.42]


def test_purge_expired_strict_boundary():
    """Event at t0 is kept while now <= t0 + window_secs (cutoff <= t0), and evicted when now > t0 + window_secs."""
    limiter = RateLimiter(window_secs=60)
    limiter.acquire_quota("users.messages.list", now=100.0)

    # At 159.999s: 100.0 is within window (cutoff = 99.999) -> kept
    assert limiter.current_units_in_window(now=159.999) == 5

    # At exactly 160.0s: cutoff = 100.0, 100.0 < 100.0 is False -> kept
    assert limiter.current_units_in_window(now=160.0) == 5

    # At 160.0001s: cutoff = 100.0001 > 100.0 -> evicted
    assert limiter.current_units_in_window(now=160.0001) == 0


def test_execute_with_retry_exact_deadline_boundary(monkeypatch):
    """When elapsed == max_deadline_secs exactly, >= must trip and raise deadline error."""
    clock_values = [0.0, 10.0, 10.0]
    monkeypatch.setattr("time.time", lambda: clock_values.pop(0))

    limiter = RateLimiter(max_retries=3, max_deadline_secs=10.0)

    def mock_op():
        raise HttpError(Response({"status": 429}), b"Rate limited")

    with pytest.raises(RequestDeadlineExceededError) as excinfo:
        limiter.execute_with_retry("users.messages.list", mock_op, sleep_fn=lambda s: None)

    assert "Retry deadline of 10.0s exceeded after 1 attempts." in str(excinfo.value)


def test_execute_with_retry_exact_next_delay_boundary(monkeypatch):
    """When elapsed + delay == max_deadline_secs exactly, > condition must permit retry sleep."""
    clock_values = [0.0, 0.0]
    monkeypatch.setattr("time.time", lambda: clock_values.pop(0) if clock_values else 0.0)
    monkeypatch.setattr("random.uniform", lambda a, b: 0.0)

    limiter = RateLimiter(max_retries=1, max_deadline_secs=1.0, backoff_schedule=[1.0])
    attempts = 0
    sleeps = []

    def mock_op():
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise HttpError(Response({"status": 503}), b"Service Unavailable")
        return "SUCCESS"

    result = limiter.execute_with_retry("users.messages.list", mock_op, sleep_fn=lambda s: sleeps.append(s))
    assert result == "SUCCESS"
    assert sleeps == [1.0]


def test_semaphore_concurrency_released_on_error():
    limiter = RateLimiter(max_concurrent=1)

    # Initial semaphore value is 1
    assert limiter._semaphore._value == 1

    def failing_op():
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        limiter.execute_with_retry("users.messages.list", failing_op)

    # Semaphore must be cleanly released back to 1
    assert limiter._semaphore._value == 1
