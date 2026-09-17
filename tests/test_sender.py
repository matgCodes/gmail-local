"""Tests for GmailSender: guarded transmission, MIME dispatch, and tamper detection."""

import base64
from dataclasses import replace
import hashlib
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from gmail_local.composer import build_mime_message, create_frozen_draft
from gmail_local.models import FrozenAttachment, FrozenDraft, FrozenDraftValidationError
from gmail_local.sender import GmailSender


def test_sender_send_staged_draft():
    mock_auth = MagicMock()
    mock_service = MagicMock()
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()
    mock_audit = MagicMock()

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Quarterly Update",
        body_text="All systems operational.",
    )
    staged_draft = replace(draft, draft_id="r-987654321")

    # Mock remote draft get (raw format)
    mime_msg = build_mime_message(staged_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-987654321",
        "message": {"id": "msg_draft_1", "raw": raw_b64},
    }

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

    res = sender.send(staged_draft, purpose="test_send")
    assert res["id"] == "sent_msg_001"
    assert res["threadId"] == "thread_001"
    assert res["draft_id"] == "r-987654321"
    assert res["fingerprint"] == staged_draft.compute_fingerprint()
    assert res["local_attachment_verified"] is True
    assert res["remote_draft_verified"] is True
    assert res["gmail_send_accepted"] is True
    assert res["recipient_ui_verified"] is False

    # Verify rate limiter charged users.drafts.get and users.drafts.send
    calls = [c[0][0] for c in mock_rate_limiter.execute_with_retry.call_args_list]
    assert "users.drafts.get" in calls
    assert "users.drafts.send" in calls

    # Verify service call
    mock_service.users().drafts().send.assert_called_once_with(
        userId="me",
        body={"id": "r-987654321"},
    )

    # Verify audit log (verify_remote_draft and send_message)
    assert mock_audit.log_entry.call_count == 2
    entries = [c[0][0] for c in mock_audit.log_entry.call_args_list]
    assert any(e.operation == "verify_remote_draft" and e.status == "SUCCESS" for e in entries)
    assert any(e.operation == "send_message" and e.status == "SUCCESS" for e in entries)


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
    assert res["local_attachment_verified"] is True
    assert res["remote_draft_verified"] is False
    assert res["gmail_send_accepted"] is True

    # Verify rate limiter charged users.messages.send
    assert mock_rate_limiter.execute_with_retry.call_args[0][0] == "users.messages.send"

    # Verify service call was users().messages().send
    mock_service.users().messages().send.assert_called_once()
    call_kwargs = mock_service.users().messages().send.call_args[1]
    assert call_kwargs["userId"] == "me"
    assert "raw" in call_kwargs["body"]


def test_sender_remote_draft_readback_matching_attachment_allows_send(tmp_path: Path):
    att_file = tmp_path / "schedule.ics"
    att_bytes = b"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nSUMMARY:Meeting\r\nEND:VCALENDAR\r\n"
    att_file.write_bytes(att_bytes)

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Meeting Schedule",
        body_text="See attached calendar.",
        attachment_paths=[att_file],
        attachment_mode="snapshot",
    )
    staged_draft = replace(draft, draft_id="r-valid-123")

    mime_msg = build_mime_message(staged_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-valid-123",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_service.users().drafts().send().execute.return_value = {
        "id": "sent-100",
        "threadId": "t-100",
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    res = sender.send(staged_draft)
    assert res["id"] == "sent-100"
    assert res["remote_draft_verified"] is True


def test_sender_remote_draft_missing_attachment_fails_closed(tmp_path: Path):
    att_file = tmp_path / "data.csv"
    att_file.write_bytes(b"col1,col2\r\nval1,val2\r\n")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Report CSV",
        body_text="See attached CSV.",
        attachment_paths=[att_file],
    )
    staged_draft = replace(draft, draft_id="r-missing-att")

    # Simulate remote draft having no attachments (e.g. stripped on server)
    stripped_draft = replace(staged_draft, attachments=[])
    mime_msg = build_mime_message(stripped_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-missing-att",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="count.*does not match approved frozen draft count"):
        sender.send(staged_draft)


def test_sender_remote_draft_renamed_attachment_fails_closed(tmp_path: Path):
    att_file = tmp_path / "original.pdf"
    att_file.write_bytes(b"%PDF-1.4 sample content")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="PDF Document",
        body_text="Document attached.",
        attachment_paths=[att_file],
    )
    staged_draft = replace(draft, draft_id="r-renamed-att")

    # Create remote draft with renamed attachment
    renamed_file = tmp_path / "renamed.pdf"
    renamed_file.write_bytes(b"%PDF-1.4 sample content")
    renamed_draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="PDF Document",
        body_text="Document attached.",
        attachment_paths=[renamed_file],
    )
    mime_msg = build_mime_message(renamed_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-renamed-att",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="missing in remote draft readback"):
        sender.send(staged_draft)


def test_sender_remote_draft_retyped_attachment_fails_closed(tmp_path: Path):
    att_file = tmp_path / "event.ics"
    att_file.write_bytes(b"BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Calendar Snapshot",
        body_text="Snapshot.",
        attachment_paths=[att_file],
        attachment_mode="snapshot",  # text/calendar; charset=UTF-8
    )
    staged_draft = replace(draft, draft_id="r-retyped")

    # Simulate remote draft having application/octet-stream instead
    compat_draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Calendar Snapshot",
        body_text="Snapshot.",
        attachment_paths=[att_file],
        attachment_mode="compatibility",  # application/octet-stream
    )
    mime_msg = build_mime_message(compat_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-retyped",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="MIME type mismatch in remote draft"):
        sender.send(staged_draft)


def test_sender_remote_draft_resized_attachment_fails_closed(tmp_path: Path):
    att_file = tmp_path / "notes.txt"
    att_file.write_bytes(b"12345")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Notes",
        body_text="Notes attached.",
        attachment_paths=[att_file],
    )
    staged_draft = replace(draft, draft_id="r-resized")

    # Simulate remote draft having different size
    other_file = tmp_path / "other.txt"
    other_file.write_bytes(b"1234567890")
    # Change file path back to notes.txt filename
    other_draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Notes",
        body_text="Notes attached.",
        attachment_paths=[other_file],
    )
    # Re-wrap with filename 'notes.txt'
    mod_att = replace(other_draft.attachments[0], filename="notes.txt")
    other_draft = replace(other_draft, attachments=[mod_att])

    mime_msg = build_mime_message(other_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-resized",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="size mismatch in remote draft"):
        sender.send(staged_draft)


def test_sender_remote_draft_hash_mismatch_fails_closed(tmp_path: Path):
    att_file = tmp_path / "secret.bin"
    att_file.write_bytes(b"AAAA")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Binary",
        body_text="Binary attached.",
        attachment_paths=[att_file],
    )
    staged_draft = replace(draft, draft_id="r-hash-mismatch")

    # Simulate remote draft having same size (4 bytes) but different bytes
    alt_file = tmp_path / "alt.bin"
    alt_file.write_bytes(b"BBBB")
    alt_draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Binary",
        body_text="Binary attached.",
        attachment_paths=[alt_file],
    )
    mod_att = replace(alt_draft.attachments[0], filename="secret.bin")
    alt_draft = replace(alt_draft, attachments=[mod_att])

    mime_msg = build_mime_message(alt_draft)
    raw_b64 = base64.urlsafe_b64encode(mime_msg.as_bytes()).decode("utf-8")

    mock_service = MagicMock()
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-hash-mismatch",
        "message": {"id": "m-1", "raw": raw_b64},
    }
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    sender = GmailSender(
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=MagicMock(),
    )

    with pytest.raises(FrozenDraftValidationError, match="SHA-256 digest mismatch"):
        sender.send(staged_draft)


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
