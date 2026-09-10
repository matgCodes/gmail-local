"""Tests for GmailComposer: MIME construction, payload serialization, and draft creation."""

import base64
from email import message_from_bytes
from email.policy import default
from pathlib import Path
import pytest

from gmail_local.composer import (
    build_draft_payload,
    build_mime_message,
    create_frozen_draft,
)
from gmail_local.models import (
    FrozenAttachment,
    FrozenDraft,
    FrozenDraftValidationError,
)


def test_create_frozen_draft_basic():
    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Test Subject",
        body_text="Hello world!",
        cc=["cc@example.com"],
        bcc=["bcc@example.com"],
    )
    assert isinstance(draft, FrozenDraft)
    assert draft.to == ["recipient@example.com"]
    assert draft.subject == "Test Subject"
    assert draft.body_text == "Hello world!"
    assert draft.cc == ["cc@example.com"]
    assert draft.bcc == ["bcc@example.com"]
    assert len(draft.compute_fingerprint()) == 64


def test_create_frozen_draft_with_attachment_file(tmp_path: Path):
    att_file = tmp_path / "document.pdf"
    att_file.write_bytes(b"%PDF-1.4 sample content")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Report",
        body_text="Attached is your report.",
        attachment_paths=[att_file],
    )
    assert len(draft.attachments) == 1
    att = draft.attachments[0]
    assert att.filename == "document.pdf"
    assert att.size_bytes == len(b"%PDF-1.4 sample content")
    assert att.mime_type == "application/pdf"
    assert len(att.sha256) == 64


def test_build_mime_message_plain_text():
    draft = FrozenDraft(
        to=["recipient@example.com"],
        subject="Plain Text Email",
        body_text="This is a simple plain text body.",
        cc=["cc@example.com"],
    )
    msg = build_mime_message(draft)

    assert msg["To"] == "recipient@example.com"
    assert msg["Cc"] == "cc@example.com"
    assert msg["Subject"] == "Plain Text Email"
    assert msg.get_content().strip() == "This is a simple plain text body."
    assert msg.get_content_type() == "text/plain"


def test_build_mime_message_alternative_html():
    draft = FrozenDraft(
        to=["recipient@example.com"],
        subject="HTML Email",
        body_text="Plain fallback.",
        body_html="<p>Rich text</p>",
    )
    msg = build_mime_message(draft)

    assert msg["To"] == "recipient@example.com"
    assert msg["Subject"] == "HTML Email"
    assert msg.is_multipart()

    # Verify both parts exist in multipart/alternative
    parts = list(msg.iter_parts())
    types = [p.get_content_type() for p in parts]
    assert "text/plain" in types
    assert "text/html" in types


def test_build_mime_message_with_attachments(tmp_path: Path):
    file1 = tmp_path / "hello.txt"
    file1.write_text("Hello from attachment", encoding="utf-8")

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Attachment Test",
        body_text="See attachment.",
        attachment_paths=[file1],
    )
    msg = build_mime_message(draft)

    assert msg.is_multipart()
    # Find attachment part
    att_parts = [p for p in msg.iter_attachments()]
    assert len(att_parts) == 1
    att_part = att_parts[0]
    assert att_part.get_filename() == "hello.txt"
    assert att_part.get_payload(decode=True) == b"Hello from attachment"


def test_build_mime_message_threading_headers():
    draft = FrozenDraft(
        to=["recipient@example.com"],
        subject="Re: Previous Subject",
        body_text="Follow up reply.",
        in_reply_to="<original-123@mail.gmail.com>",
        references=["<root-000@mail.gmail.com>", "<original-123@mail.gmail.com>"],
    )
    msg = build_mime_message(draft)

    assert msg["In-Reply-To"] == "<original-123@mail.gmail.com>"
    assert "<root-000@mail.gmail.com>" in msg["References"]
    assert "<original-123@mail.gmail.com>" in msg["References"]


def test_build_draft_payload_base64url():
    draft = FrozenDraft(
        to=["recipient@example.com"],
        subject="Payload Test",
        body_text="Testing base64url payload serialization.",
    )
    payload = build_draft_payload(draft)

    assert "message" in payload
    assert "raw" in payload["message"]

    # Decode base64url
    raw_str = payload["message"]["raw"]
    # Re-pad if necessary
    padding = 4 - (len(raw_str) % 4)
    if padding and padding < 4:
        raw_str += "=" * padding

    decoded_bytes = base64.urlsafe_b64decode(raw_str)
    reconstructed = message_from_bytes(decoded_bytes, policy=default)

    assert reconstructed["To"] == "recipient@example.com"
    assert reconstructed["Subject"] == "Payload Test"
    assert reconstructed.get_content().strip() == "Testing base64url payload serialization."


def test_draft_manager_save_draft():
    from unittest.mock import MagicMock
    from gmail_local.composer import GmailDraftManager

    mock_auth = MagicMock()
    mock_service = MagicMock()
    mock_rate_limiter = MagicMock()
    mock_audit = MagicMock()

    mock_service.users().drafts().create().execute.return_value = {
        "id": "r-123456789",
        "message": {"id": "msg_draft_1"},
    }

    manager = GmailDraftManager(
        auth=mock_auth,
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=mock_audit,
    )

    draft = create_frozen_draft(
        to=["recipient@example.com"],
        subject="Draft Save Test",
        body_text="Testing saving draft.",
    )

    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()

    saved_draft = manager.save_draft(draft, purpose="test_save")
    assert saved_draft.draft_id == "r-123456789"
    assert saved_draft.compute_fingerprint() == draft.compute_fingerprint()

    # Verify execute_with_retry call
    assert mock_rate_limiter.execute_with_retry.call_args[0][0] == "users.drafts.create"
    # Verify audit log
    mock_audit.record.assert_called_once()
    audit_entry = mock_audit.record.call_args[0][0]
    assert audit_entry.operation == "draft_create"
    assert audit_entry.draft_id == "r-123456789"
    assert audit_entry.fingerprint == draft.compute_fingerprint()


def test_draft_manager_list_and_get():
    from unittest.mock import MagicMock
    from gmail_local.composer import GmailDraftManager

    mock_auth = MagicMock()
    mock_service = MagicMock()
    mock_rate_limiter = MagicMock()
    mock_rate_limiter.execute_with_retry.side_effect = lambda method, fn: fn()
    mock_audit = MagicMock()

    mock_service.users().drafts().list().execute.return_value = {
        "drafts": [{"id": "r-1", "message": {"id": "m-1"}}]
    }
    mock_service.users().drafts().get().execute.return_value = {
        "id": "r-1",
        "message": {"id": "m-1", "snippet": "Hello"},
    }

    manager = GmailDraftManager(
        auth=mock_auth,
        service=mock_service,
        rate_limiter=mock_rate_limiter,
        audit_logger=mock_audit,
    )

    drafts = manager.list_drafts(max_results=5)
    assert len(drafts) == 1
    assert drafts[0]["id"] == "r-1"
    assert mock_rate_limiter.execute_with_retry.call_args_list[0][0][0] == "users.drafts.list"

    draft = manager.get_draft("r-1")
    assert draft["id"] == "r-1"
    assert mock_rate_limiter.execute_with_retry.call_args_list[1][0][0] == "users.drafts.get"


def test_local_draft_storage_and_resolution(tmp_path: Path):
    from gmail_local.composer import load_draft_locally, save_draft_locally

    draft = create_frozen_draft(
        to=["target@example.com"],
        subject="Local Staging Test",
        body_text="Testing persistent local draft caching.",
    )
    fp = draft.compute_fingerprint()

    # Save to local drafts directory
    saved_path = save_draft_locally(draft, drafts_dir=tmp_path)
    assert saved_path.exists()
    assert saved_path.name == f"{fp}.json"

    # Load by exact path
    loaded_by_path = load_draft_locally(str(saved_path), drafts_dir=tmp_path)
    assert loaded_by_path.compute_fingerprint() == fp

    # Load by fingerprint
    loaded_by_fp = load_draft_locally(fp, drafts_dir=tmp_path)
    assert loaded_by_fp.compute_fingerprint() == fp

    # Load by fingerprint prefix (first 16 chars)
    loaded_by_prefix = load_draft_locally(fp[:16], drafts_dir=tmp_path)
    assert loaded_by_prefix.compute_fingerprint() == fp

    # Nonexistent identifier
    with pytest.raises(FileNotFoundError):
        load_draft_locally("nonexistent_fingerprint", drafts_dir=tmp_path)

