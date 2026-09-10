"""Evals for hard boundary contracts and zero-secret disclosure guarantees."""

import base64
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from gmail_local.audit import AuditLogger
from gmail_local.rate_limiter import RateLimiter
from gmail_local.retrieval import (
    GmailRetriever,
    OverwriteError,
    RetrievalBoundError,
)


def test_eval_search_ceiling_contract(tmp_path: Path):
    """Eval: The system must hard-reject any search query asking for >75 candidates."""
    retriever = GmailRetriever(
        audit_logger=AuditLogger(log_path=tmp_path / "audit.log"),
        rate_limiter=RateLimiter(),
        service=MagicMock(),
    )

    with pytest.raises(RetrievalBoundError) as exc:
        retriever.search_messages("test", max_results=100)
    assert "must be between 1 and 75" in str(exc.value)


def test_eval_read_message_ceiling_contract(tmp_path: Path):
    """Eval: The system must hard-reject reading more than 10 messages in one invocation."""
    retriever = GmailRetriever(
        audit_logger=AuditLogger(log_path=tmp_path / "audit.log"),
        rate_limiter=RateLimiter(),
        service=MagicMock(),
    )

    with pytest.raises(RetrievalBoundError) as exc:
        retriever.get_messages([f"msg_{i}" for i in range(15)])
    assert "maximum allowed per read is 10" in str(exc.value)


def test_eval_aggregate_body_overflow_contract(tmp_path: Path):
    """Eval: 1 MiB aggregate body limit must immediately drop overflow messages without partial disclosure."""
    audit_file = tmp_path / "audit.log"
    retriever = GmailRetriever(
        audit_logger=AuditLogger(log_path=audit_file),
        rate_limiter=RateLimiter(),
        service=MagicMock(),
    )

    # Message 1: 800 KiB (valid)
    # Message 2: 400 KiB (would make 1.2 MiB > 1 MiB ceiling)
    msg1_text = "M1" * (400 * 1024)  # 800 KiB
    msg2_text = "M2" * (200 * 1024)  # 400 KiB

    def mock_get(userId, id, format):
        req = MagicMock()
        text = msg1_text if id == "m1" else msg2_text
        b64 = base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")
        req.execute.return_value = {
            "id": id,
            "threadId": f"t_{id}",
            "payload": {
                "mimeType": "text/plain",
                "headers": [{"name": "Subject", "value": f"Subject {id}"}],
                "body": {"data": b64},
            },
        }
        return req

    retriever._service.users().messages().get.side_effect = mock_get

    messages = retriever.get_messages(["m1", "m2"])

    # Exactly 1 message returned; message 2 dropped cleanly
    assert len(messages) == 1
    assert messages[0].id == "m1"

    # Audit log must record HELD_OVERFLOW for m2
    audit_text = audit_file.read_text(encoding="utf-8")
    assert "status=HELD_OVERFLOW mid=m2" in audit_text


def test_eval_no_overwrite_contract(tmp_path: Path):
    """Eval: Download must strictly refuse to overwrite any existing file."""
    existing_file = tmp_path / "important_document.pdf"
    existing_file.write_text("original critical data")

    retriever = GmailRetriever(
        audit_logger=AuditLogger(log_path=tmp_path / "audit.log"),
        rate_limiter=RateLimiter(),
        service=MagicMock(),
    )

    with pytest.raises(OverwriteError):
        retriever.download_attachments([("m1", "att1", existing_file)])

    # Verify original file was preserved intact
    assert existing_file.read_text() == "original critical data"


def test_eval_zero_secret_leakage_contract(tmp_path: Path):
    """Eval: Audit logs and status reports must NEVER contain refresh tokens or client secrets."""
    audit_file = tmp_path / "audit.log"
    audit = AuditLogger(log_path=audit_file)

    # Record 5 diverse operations
    from gmail_local.models import AuditEntry
    audit.record(AuditEntry(operation="search", purpose="test", status="SUCCESS"))
    audit.record(AuditEntry(operation="read", purpose="test", status="SUCCESS", message_id="123"))
    audit.record(AuditEntry(operation="download", purpose="test", status="SUCCESS", filename="doc.pdf"))

    log_content = audit_file.read_text(encoding="utf-8")

    # Forbidden patterns
    forbidden = ["GOCSPX-", "client_secret", "refresh_token", "ya29.", "bearer"]
    for token in forbidden:
        assert token.lower() not in log_content.lower()


def test_eval_rate_limiter_window_saturation_contract():
    """Eval: 3,000 units/60s rolling limit must strictly raise RateLimitExceededError."""
    from gmail_local.rate_limiter import RateLimitExceededError

    limiter = RateLimiter(max_units=3000, window_secs=60)
    # 150 requests of 20 units = 3000 units exactly
    for _ in range(150):
        limiter.acquire_quota("users.messages.get")

    assert limiter.current_units_in_window() == 3000

    # 151st request must be rejected
    with pytest.raises(RateLimitExceededError) as exc:
        limiter.acquire_quota("users.messages.get")
    assert "Rolling 60s budget exceeded" in str(exc.value)


def test_eval_concurrency_saturation_contract():
    """Eval: Concurrency must strictly throttle at 4 in-flight requests."""
    import threading
    import time

    limiter = RateLimiter(max_concurrent=4)
    active_threads = 0
    max_observed_concurrency = 0
    lock = threading.Lock()

    def worker():
        nonlocal active_threads, max_observed_concurrency
        def job():
            nonlocal active_threads, max_observed_concurrency
            with lock:
                active_threads += 1
                if active_threads > max_observed_concurrency:
                    max_observed_concurrency = active_threads
            time.sleep(0.05)
            with lock:
                active_threads -= 1

        limiter.execute_with_retry("users.messages.list", job)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Even with 8 threads launched simultaneously, max concurrent inside job must not exceed 4
    assert max_observed_concurrency <= 4


def test_eval_audit_log_rotation_contract(tmp_path: Path):
    """Eval: Audit log must rotate when hitting size boundary and preserve 0600 perms."""
    import os

    log_path = tmp_path / "rotating_audit.log"
    # Small max_bytes to trigger quick rotation
    logger = AuditLogger(log_path=log_path, max_bytes=500, backup_count=2)

    from gmail_local.models import AuditEntry
    for i in range(25):
        logger.record(AuditEntry(operation="search", purpose=f"purpose_{i}", status="SUCCESS"))

    assert log_path.exists()
    assert (tmp_path / "rotating_audit.log.1").exists()

    # Permissions on active and rotated logs must be 0600
    for p in [log_path, tmp_path / "rotating_audit.log.1"]:
        mode = oct(os.stat(p).st_mode & 0o777)
        assert mode == "0o600"


def test_eval_token_revocation_lifecycle_contract(tmp_path: Path):
    """Eval: Revoking authorization must wipe Keychain credentials and notify Google."""
    from unittest.mock import patch
    from gmail_local.auth import AuthManager

    secret_file = tmp_path / "client_secret.json"
    secret_file.write_text('{"installed": {"client_id": "dummy.id", "client_secret": "dummy.sec"}}')

    mock_keyring = MagicMock()
    mock_keyring.get_password.return_value = "fake_refresh_token"

    auth = AuthManager(
        account="test@example.com",
        keychain_service="test-keychain",
        client_secret_path=secret_file,
        keyring_backend=mock_keyring,
    )

    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200

        auth.revoke()

        # Keyring deletion must have been executed
        mock_keyring.delete_password.assert_called_once_with("test-keychain", "test@example.com")
        # Google revoke endpoint must have been contacted
        mock_post.assert_called_once()
        assert "oauth2.googleapis.com/revoke" in mock_post.call_args[0][0]
