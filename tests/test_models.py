"""Tests for domain models."""

from gmail_local.models import (
    AttachmentDescriptor,
    AuditEntry,
    CandidateMessage,
    SelectedMessage,
)


def test_candidate_message():
    c = CandidateMessage(
        id="123",
        thread_id="t1",
        date="2026-09-09",
        sender="sender@example.com",
        recipient="me@example.com",
        subject="Test Subject",
    )
    assert c.id == "123"
    assert c.preview is None


def test_audit_entry_serialization():
    entry = AuditEntry(
        operation="test_op",
        purpose="testing purpose",
        status="SUCCESS",
        message_id="msg999",
        filename="report.pdf",
        destination="/tmp/report.pdf",
    )
    line = entry.to_log_line()
    assert "op=test_op" in line
    assert "purpose=testing_purpose" in line
    assert "status=SUCCESS" in line
    assert "mid=msg999" in line
    assert "file=report.pdf" in line
    assert "dest=/tmp/report.pdf" in line
