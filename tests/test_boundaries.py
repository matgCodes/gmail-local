"""Explicit boundary-condition tests ($N-1, N, N+1$) for all security and disclosure bounds."""

import base64
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from gmail_local.audit import AuditLogger
from gmail_local.config import (
    MAX_ATTACHMENT_BYTES_AGGREGATE,
    MAX_ATTACHMENT_BYTES_PER_FILE,
    MAX_DECODED_BODY_BYTES,
    MAX_READ_MESSAGES,
    MAX_SEARCH_BOUND,
    RATE_LIMIT_MAX_UNITS,
)
from gmail_local.rate_limiter import RateLimitExceededError, RateLimiter
from gmail_local.retrieval import GmailRetriever, RetrievalBoundError


@pytest.fixture
def retriever(tmp_path: Path):
    audit = AuditLogger(log_path=tmp_path / "boundary_audit.log")
    limiter = RateLimiter(max_units=100_000)
    return GmailRetriever(
        audit_logger=audit,
        rate_limiter=limiter,
        service=MagicMock(),
    )


class TestSearchCeilingBoundaries:
    """Tests N-1, N, N+1 on Search Bound (MAX_SEARCH_BOUND = 75)."""

    def test_search_at_ceiling_minus_one(self, retriever):
        # 74 is valid
        retriever._service.users().messages().list().execute.return_value = {"messages": []}
        results = retriever.search_messages("test", max_results=MAX_SEARCH_BOUND - 1)
        assert results == []

    def test_search_at_exact_ceiling(self, retriever):
        # 75 is valid
        retriever._service.users().messages().list().execute.return_value = {"messages": []}
        results = retriever.search_messages("test", max_results=MAX_SEARCH_BOUND)
        assert results == []

    def test_search_at_ceiling_plus_one(self, retriever):
        # 76 must be rejected
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.search_messages("test", max_results=MAX_SEARCH_BOUND + 1)
        assert "must be between 1 and 75" in str(exc.value)

    def test_search_at_zero(self, retriever):
        # 0 must be rejected
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.search_messages("test", max_results=0)
        assert "must be between 1 and 75" in str(exc.value)

    def test_search_negative(self, retriever):
        # Negative numbers must be rejected
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.search_messages("test", max_results=-5)
        assert "must be between 1 and 75" in str(exc.value)


class TestReadCeilingBoundaries:
    """Tests N-1, N, N+1 on Read Messages Ceiling (MAX_READ_MESSAGES = 10)."""

    def test_read_at_ceiling_minus_one(self, retriever):
        retriever._service.users().messages().get().execute.return_value = {
            "id": "m", "payload": {"headers": [], "body": {}}
        }
        # 9 messages allowed
        ids = [f"m_{i}" for i in range(MAX_READ_MESSAGES - 1)]
        msgs = retriever.get_messages(ids)
        assert len(msgs) == 9

    def test_read_at_exact_ceiling(self, retriever):
        retriever._service.users().messages().get().execute.return_value = {
            "id": "m", "payload": {"headers": [], "body": {}}
        }
        # 10 messages allowed
        ids = [f"m_{i}" for i in range(MAX_READ_MESSAGES)]
        msgs = retriever.get_messages(ids)
        assert len(msgs) == 10

    def test_read_at_ceiling_plus_one(self, retriever):
        # 11 messages rejected
        ids = [f"m_{i}" for i in range(MAX_READ_MESSAGES + 1)]
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.get_messages(ids)
        assert "maximum allowed per read is 10" in str(exc.value)

    def test_read_empty_list(self, retriever):
        msgs = retriever.get_messages([])
        assert msgs == []


class TestBodyBytesBoundaries:
    """Tests N, N+1 on Aggregate Body Limit (MAX_DECODED_BODY_BYTES = 1 MiB)."""

    def test_body_at_exact_1_mib(self, retriever):
        # Exactly 1,048,576 bytes
        exact_text = "X" * MAX_DECODED_BODY_BYTES
        b64 = base64.urlsafe_b64encode(exact_text.encode("utf-8")).decode("utf-8")
        retriever._service.users().messages().get().execute.return_value = {
            "id": "m1",
            "payload": {"mimeType": "text/plain", "headers": [], "body": {"data": b64}},
        }

        msgs = retriever.get_messages(["m1"])
        assert len(msgs) == 1
        assert msgs[0].body_bytes == MAX_DECODED_BODY_BYTES

    def test_body_at_1_mib_plus_one_byte(self, retriever):
        # Exactly 1,048,577 bytes
        overflow_text = "X" * (MAX_DECODED_BODY_BYTES + 1)
        b64 = base64.urlsafe_b64encode(overflow_text.encode("utf-8")).decode("utf-8")
        retriever._service.users().messages().get().execute.return_value = {
            "id": "m1",
            "payload": {"mimeType": "text/plain", "headers": [], "body": {"data": b64}},
        }

        msgs = retriever.get_messages(["m1"])
        # Body was held and discarded immediately
        assert len(msgs) == 0


class TestAttachmentBytesBoundaries:
    """Tests N, N+1 on Single (25 MiB) and Aggregate (50 MiB) Attachment Limits."""

    def test_single_attachment_at_exact_25_mib(self, retriever, tmp_path: Path):
        data = b"Y" * MAX_ATTACHMENT_BYTES_PER_FILE
        retriever._service.users().messages().attachments().get().execute.return_value = {
            "data": base64.urlsafe_b64encode(data).decode("utf-8"),
            "size": len(data),
        }
        dest = tmp_path / "exact_25mb.bin"
        installed = retriever.download_attachments([("m1", "att1", dest)])
        assert len(installed) == 1
        assert dest.exists()
        assert dest.stat().st_size == MAX_ATTACHMENT_BYTES_PER_FILE

    def test_single_attachment_at_25_mib_plus_one_byte(self, retriever, tmp_path: Path):
        data = b"Y" * (MAX_ATTACHMENT_BYTES_PER_FILE + 1)
        retriever._service.users().messages().attachments().get().execute.return_value = {
            "data": base64.urlsafe_b64encode(data).decode("utf-8"),
            "size": len(data),
        }
        dest = tmp_path / "overflow_25mb.bin"
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.download_attachments([("m1", "att1", dest)])
        assert "exceeds 25 MiB single-file limit" in str(exc.value)
        assert not dest.exists()

    def test_aggregate_attachments_at_exact_50_mib(self, retriever, tmp_path: Path):
        # Two files of 25 MiB each = exactly 50 MiB
        data = b"Z" * MAX_ATTACHMENT_BYTES_PER_FILE

        def mock_att(userId, messageId, id):
            req = MagicMock()
            req.execute.return_value = {
                "data": base64.urlsafe_b64encode(data).decode("utf-8"),
                "size": len(data),
            }
            return req

        retriever._service.users().messages().attachments().get.side_effect = mock_att

        dest1 = tmp_path / "part1_25mb.bin"
        dest2 = tmp_path / "part2_25mb.bin"
        installed = retriever.download_attachments([("m1", "a1", dest1), ("m1", "a2", dest2)])
        assert len(installed) == 2
        assert dest1.stat().st_size + dest2.stat().st_size == MAX_ATTACHMENT_BYTES_AGGREGATE

    def test_aggregate_attachments_at_50_mib_plus_one_byte(self, retriever, tmp_path: Path):
        # 3 files: 20 MiB + 20 MiB + (10 MiB + 1 byte) = 50 MiB + 1 byte
        # All individual files are <= 25 MiB, so single-file check passes, tripping aggregate limit!
        data_20m = b"Z" * (20 * 1024 * 1024)
        data_10m_plus1 = b"Z" * (10 * 1024 * 1024 + 1)

        def mock_att(userId, messageId, id):
            req = MagicMock()
            d = data_10m_plus1 if id == "a3" else data_20m
            req.execute.return_value = {
                "data": base64.urlsafe_b64encode(d).decode("utf-8"),
                "size": len(d),
            }
            return req

        retriever._service.users().messages().attachments().get.side_effect = mock_att

        dest1 = tmp_path / "part1.bin"
        dest2 = tmp_path / "part2.bin"
        dest3 = tmp_path / "part3.bin"
        selections = [("m1", "a1", dest1), ("m1", "a2", dest2), ("m1", "a3", dest3)]
        with pytest.raises(RetrievalBoundError) as exc:
            retriever.download_attachments(selections)
        assert "exceed 50 MiB aggregate limit" in str(exc.value)
        assert not dest3.exists()


class TestRateLimiterBoundaries:
    """Tests exact boundary saturation (3,000 units) and window expiration."""

    def test_rate_limiter_exact_3000_units(self):
        limiter = RateLimiter(max_units=RATE_LIMIT_MAX_UNITS, window_secs=60)
        # Cost of users.history.list is 2 units. 1500 * 2 = exactly 3,000 units.
        for _ in range(1500):
            limiter.acquire_quota("users.history.list")

        assert limiter.current_units_in_window() == 3000

        # Requesting 1 more unit must raise RateLimitExceededError
        with pytest.raises(RateLimitExceededError) as exc:
            limiter.acquire_quota("users.labels.list")  # 1 unit cost
        assert "Rolling 60s budget exceeded" in str(exc.value)

    def test_rate_limiter_window_roll_off(self):
        limiter = RateLimiter(max_units=100, window_secs=60)
        t0 = 1000.0

        # Simulate quota usage at t0
        limiter.acquire_quota("users.messages.get", now=t0)  # 20 units
        assert limiter.current_units_in_window(now=t0) == 20

        # At t0 + 59s: still inside window
        assert limiter.current_units_in_window(now=t0 + 59.0) == 20

        # At t0 + 60.1s: expired, drops back to 0 units
        assert limiter.current_units_in_window(now=t0 + 60.1) == 0
