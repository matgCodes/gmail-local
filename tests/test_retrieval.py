"""Tests for GmailRetriever and strict boundary enforcement."""

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


@pytest.fixture
def mock_audit(tmp_path: Path):
    return AuditLogger(log_path=tmp_path / "test_audit.log")


@pytest.fixture
def mock_rate_limiter():
    return RateLimiter(max_units=10000)


def test_search_bound_validation(mock_audit, mock_rate_limiter):
    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=MagicMock(),
    )

    with pytest.raises(RetrievalBoundError):
        retriever.search_messages("test", max_results=0)

    with pytest.raises(RetrievalBoundError):
        retriever.search_messages("test", max_results=76)  # Exceeds 75 ceiling


def test_search_extracts_headers_only(mock_audit, mock_rate_limiter):
    mock_service = MagicMock()
    # Mock messages().list()
    mock_service.users().messages().list().execute.return_value = {
        "messages": [{"id": "m1", "threadId": "t1"}]
    }
    # Mock messages().get()
    mock_service.users().messages().get().execute.return_value = {
        "id": "m1",
        "threadId": "t1",
        "payload": {
            "headers": [
                {"name": "Date", "value": "Wed, 09 Sep 2026 12:00:00 -0700"},
                {"name": "From", "value": "court@example.gov"},
                {"name": "To", "value": "me@example.com"},
                {"name": "Subject", "value": "Notice of Filing"},
            ]
        },
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    results = retriever.search_messages("court", max_results=5)
    assert len(results) == 1
    c = results[0]
    assert c.id == "m1"
    assert c.sender == "court@example.gov"
    assert c.subject == "Notice of Filing"
    assert c.preview is None


def test_read_bound_rejects_more_than_10_messages(mock_audit, mock_rate_limiter):
    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=MagicMock(),
    )

    with pytest.raises(RetrievalBoundError):
        retriever.get_messages(["msg_" + str(i) for i in range(11)])


def test_read_bound_discards_overflow_body_at_1_mib(mock_audit, mock_rate_limiter):
    mock_service = MagicMock()

    # Create a message body of 700 KiB and another of 500 KiB (total 1.2 MiB > 1 MiB limit)
    large_text_700k = "A" * (700 * 1024)
    large_text_500k = "B" * (500 * 1024)

    def mock_get(userId, id, format):
        req = MagicMock()
        text = large_text_700k if id == "m1" else large_text_500k
        b64 = base64.urlsafe_b64encode(text.encode("utf-8")).decode("utf-8")
        req.execute.return_value = {
            "id": id,
            "threadId": "t_" + id,
            "payload": {
                "mimeType": "text/plain",
                "headers": [{"name": "Subject", "value": "Sub " + id}],
                "body": {"data": b64},
            },
        }
        return req

    mock_service.users().messages().get.side_effect = mock_get

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    # Request both m1 and m2
    results = retriever.get_messages(["m1", "m2"])

    # m1 (700 KiB) is within 1 MiB -> accepted
    # m2 (500 KiB) would make 1.2 MiB -> discarded immediately, read stopped!
    assert len(results) == 1
    assert results[0].id == "m1"
    assert results[0].body_bytes == 700 * 1024

    # Verify audit log recorded HELD_OVERFLOW
    audit_content = mock_audit.log_path.read_text(encoding="utf-8")
    assert "status=HELD_OVERFLOW" in audit_content
    assert "mid=m2" in audit_content


def test_download_rejects_overwrite(mock_audit, mock_rate_limiter, tmp_path: Path):
    target = tmp_path / "existing.pdf"
    target.write_text("already here")

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=MagicMock(),
    )

    with pytest.raises(OverwriteError):
        retriever.download_attachments([("m1", "att1", target)])


def test_download_atomic_and_size_checks(mock_audit, mock_rate_limiter, tmp_path: Path):
    mock_service = MagicMock()
    file_bytes = b"hello world pdf content"
    b64_data = base64.urlsafe_b64encode(file_bytes).decode("utf-8")

    mock_service.users().messages().attachments().get().execute.return_value = {
        "data": b64_data,
        "size": len(file_bytes),
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    dest = tmp_path / "downloaded.pdf"
    results = retriever.download_attachments([("m1", "att1", dest)])

    assert len(results) == 1
    assert dest.exists()
    assert dest.read_bytes() == file_bytes


def test_download_cleans_up_staging_on_failure(mock_audit, mock_rate_limiter, tmp_path: Path):
    mock_service = MagicMock()
    # Simulate an error during attachment fetching
    mock_service.users().messages().attachments().get().execute.side_effect = RuntimeError("API failed")

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    dest = tmp_path / "will_fail.pdf"
    with pytest.raises(RuntimeError):
        retriever.download_attachments([("m1", "att1", dest)])

    assert not dest.exists()
    # Confirm no leftover .tmp files
    tmp_files = list(tmp_path.glob(".*.tmp.*"))
    assert len(tmp_files) == 0


def test_download_to_directory_uses_original_filename(mock_audit, mock_rate_limiter, tmp_path: Path):
    mock_service = MagicMock()
    file_bytes = b"image png data"
    b64_data = base64.urlsafe_b64encode(file_bytes).decode("utf-8")

    # Mock list_attachments via messages().get()
    mock_service.users().messages().get().execute.return_value = {
        "id": "m1",
        "payload": {
            "parts": [
                {
                    "filename": "chart.png",
                    "mimeType": "image/png",
                    "body": {"attachmentId": "att1", "size": len(file_bytes)},
                }
            ]
        },
    }
    # Mock attachments().get()
    mock_service.users().messages().attachments().get().execute.return_value = {
        "data": b64_data,
        "size": len(file_bytes),
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    # Supply directory as destination
    download_dir = tmp_path / "downloads"
    download_dir.mkdir()

    results = retriever.download_attachments([("m1", "att1", download_dir)])

    assert len(results) == 1
    expected_file = download_dir / "chart.png"
    assert results[0] == expected_file
    assert expected_file.exists()
    assert expected_file.read_bytes() == file_bytes


def test_download_to_directory_handles_ephemeral_attachment_ids(mock_audit, mock_rate_limiter, tmp_path: Path):
    """When Google returns differing ephemeral attachment IDs across calls, single attachment still resolves original filename."""
    mock_service = MagicMock()
    file_bytes = b"sample content"
    b64_data = base64.urlsafe_b64encode(file_bytes).decode("utf-8")

    # list_attachments returns dynamic ID "ephemeral_id_2"
    mock_service.users().messages().get().execute.return_value = {
        "id": "m1",
        "payload": {
            "parts": [
                {
                    "filename": "court_filing.pdf",
                    "mimeType": "application/pdf",
                    "body": {"attachmentId": "ephemeral_id_2", "size": len(file_bytes)},
                }
            ]
        },
    }
    mock_service.users().messages().attachments().get().execute.return_value = {
        "data": b64_data,
        "size": len(file_bytes),
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    download_dir = tmp_path / "downloads_ephemeral"
    download_dir.mkdir()

    # Pass 300-char ID from prior get_messages call: "ephemeral_id_1" + "A" * 300
    prior_att_id = "ephemeral_id_1_" + "A" * 300
    results = retriever.download_attachments([("m1", prior_att_id, download_dir)])

    assert len(results) == 1
    expected_file = download_dir / "court_filing.pdf"
    assert results[0] == expected_file
    assert expected_file.exists()
    assert expected_file.read_bytes() == file_bytes


def test_get_history_success(mock_audit, mock_rate_limiter):
    mock_service = MagicMock()
    mock_service.users().history().list().execute.return_value = {
        "historyId": "99999",
        "history": [
            {
                "messagesAdded": [{"message": {"id": "m101"}}],
                "messagesDeleted": [{"message": {"id": "m50"}}],
            },
            {
                "messagesAdded": [{"message": {"id": "m102"}}, {"message": {"id": "m101"}}],
            },
        ],
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    delta = retriever.get_history("10000")
    assert delta.history_id == "99999"
    assert not delta.is_expired
    assert delta.messages_added == ["m101", "m102"]  # deduplicated preserving order
    assert delta.messages_deleted == ["m50"]


def test_get_history_404_expired(mock_audit, mock_rate_limiter):
    from googleapiclient.errors import HttpError

    class FakeResponse:
        status = 404
        reason = "Not Found"

    mock_service = MagicMock()
    mock_service.users().history().list().execute.side_effect = HttpError(
        FakeResponse(), b"History ID expired"
    )

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    delta = retriever.get_history("expired_id")
    assert delta.is_expired is True
    assert delta.history_id == "expired_id"
    assert delta.messages_added == []
    assert delta.messages_deleted == []


def test_get_thread_summary(mock_audit, mock_rate_limiter):
    mock_service = MagicMock()
    mock_service.users().threads().get().execute.return_value = {
        "id": "thread_abc",
        "messages": [
            {
                "id": "m1",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "alice@example.com"},
                        {"name": "Subject", "value": "Project Update"},
                    ]
                },
            },
            {
                "id": "m2",
                "payload": {
                    "headers": [
                        {"name": "From", "value": "bob@example.com"},
                        {"name": "Subject", "value": "Re: Project Update"},
                    ]
                },
            },
        ],
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    summary = retriever.get_thread("thread_abc")
    assert summary.thread_id == "thread_abc"
    assert summary.message_count == 2
    assert summary.subject == "Project Update"
    assert "alice@example.com" in summary.participants
    assert "bob@example.com" in summary.participants
    assert summary.message_ids == ["m1", "m2"]


def test_list_labels(mock_audit, mock_rate_limiter):
    mock_service = MagicMock()
    mock_service.users().labels().list().execute.return_value = {
        "labels": [
            {"id": "Label_1", "name": "Work", "type": "user"},
            {"id": "INBOX", "name": "INBOX", "type": "system"},
            {"id": "UNREAD", "name": "UNREAD", "type": "system"},
            {"id": "Label_2", "name": "Personal", "type": "user"},
        ]
    }

    retriever = GmailRetriever(
        audit_logger=mock_audit,
        rate_limiter=mock_rate_limiter,
        service=mock_service,
    )

    labels = retriever.list_labels()
    assert len(labels) == 4
    # Verify system labels are sorted first
    assert labels[0].type == "system"
    assert labels[1].type == "system"
    assert labels[2].type == "user"
    assert labels[3].type == "user"
    assert labels[2].name == "Personal"  # alphabetical within user
    assert labels[3].name == "Work"
