"""Tests for GmailSender: guarded transmission, MIME dispatch, and tamper detection."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from gmail_local.composer import create_frozen_draft
from gmail_local.models import FrozenAttachment, FrozenDraft, FrozenDraftValidationError
from gmail_local.sender import GmailSender


def test_sender_send_staged_draft():
    mock_auth = MagicMock()
    mock_service = MagicMock()
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()
    mock_audit = MagicMock()

    send_mock = MagicMock()
    send_mock.execute.return_value = {
        "id": "sent_msg_001",
        "threadId": "thread_001",
        "labelIds": ["SENT"],
    }
    mock_service.users().drafts().send.return_value = send_mock

    sender = GmailSender(
        auth=mock_auth,
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=mock_audit,
    )

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Quarterly Update",
        body_text="All systems operational.",
    )
    # Simulate staged draft
    from dataclasses import replace
    staged_draft = replace(draft, draft_id="r-987654321")

    res = sender.send(staged_draft, purpose="test_send")
    assert res["id"] == "sent_msg_001"
    assert res["threadId"] == "thread_001"
    assert res["draft_id"] == "r-987654321"
    assert res["fingerprint"] == staged_draft.compute_fingerprint()

    # Verify rate limiter charged users.drafts.send
    assert mock_rate_limiter.execute_with_retry.call_args[0][0] == "users.drafts.send"

    # Verify service call
    mock_service.users().drafts().send.assert_called_once_with(
        userId="me",
        body={"id": "r-987654321"},
    )

    # Verify audit log
    mock_audit.log_entry.assert_called_once()
    entry = mock_audit.log_entry.call_args[0][0]
    assert entry.operation == "send_message"
    assert entry.draft_id == "r-987654321"
    assert entry.message_id == "sent_msg_001"
    assert entry.fingerprint == staged_draft.compute_fingerprint()
    assert entry.status == "SUCCESS"


def test_sender_send_unstaged_raw_message():
    mock_auth = MagicMock()
    mock_service = MagicMock()
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()
    mock_audit = MagicMock()

    send_mock = MagicMock()
    send_mock.execute.return_value = {
        "id": "sent_msg_002",
        "threadId": "thread_002",
        "labelIds": ["SENT"],
    }
    mock_service.users().messages().send.return_value = send_mock

    sender = GmailSender(
        auth=mock_auth,
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=mock_audit,
    )

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Direct Raw Send",
        body_text="Sending without staging to Gmail Drafts.",
    )
    assert draft.draft_id is None

    res = sender.send(draft, purpose="test_raw_send")
    assert res["id"] == "sent_msg_002"
    assert res["threadId"] == "thread_002"
    assert res["draft_id"] is None
    assert res["fingerprint"] == draft.compute_fingerprint()

    # Verify rate limiter charged users.messages.send
    assert mock_rate_limiter.execute_with_retry.call_args[0][0] == "users.messages.send"

    # Verify service call was users().messages().send
    mock_service.users().messages().send.assert_called_once()
    call_kwargs = mock_service.users().messages().send.call_args[1]
    assert call_kwargs["userId"] == "me"
    assert "raw" in call_kwargs["body"]


def test_sender_attachment_tamper_detection(tmp_path: Path):
    att_file = tmp_path / "invoice.pdf"
    att_file.write_bytes(b"Original Invoice Content")

    draft = create_frozen_draft(
        to=["accounts@example.com"],
        subject="Invoice",
        body_text="Please find attached.",
        attachment_paths=[att_file],
    )

    # Tamper with file before sending
    att_file.write_bytes(b"TAMPERED Malicious Content")

    sender = GmailSender(
        auth=MagicMock(),
        service=MagicMock(),
        rate_limiter=MagicMock(),
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="failed integrity check"):
        sender.send(draft)


def test_sender_attachment_missing_detection(tmp_path: Path):
    att_file = tmp_path / "memo.pdf"
    att_file.write_bytes(b"Memo Content")

    draft = create_frozen_draft(
        to=["team@example.com"],
        subject="Memo",
        body_text="Please find attached.",
        attachment_paths=[att_file],
    )

    # Delete file before sending
    att_file.unlink()

    sender = GmailSender(
        auth=MagicMock(),
        service=MagicMock(),
        rate_limiter=MagicMock(),
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="failed integrity check"):
        sender.send(draft)
