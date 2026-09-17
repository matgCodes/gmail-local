"""Tests for domain models."""

from gmail_local.models import (
    AttachmentDescriptor,
    AuditEntry,
    CandidateMessage,
    FrozenAttachment,
    FrozenDraft,
    FrozenDraftValidationError,
    SelectedMessage,
)
import pytest


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
        draft_id="r-102938",
        fingerprint="abcd1234efgh5678",
        filename="report.pdf",
        destination="/tmp/report.pdf",
    )
    line = entry.to_log_line()
    assert "op=test_op" in line
    assert "purpose=testing_purpose" in line
    assert "status=SUCCESS" in line
    assert "mid=msg999" in line
    assert "did=r-102938" in line
    assert "fp=abcd1234efgh5678" in line
    assert "file=report.pdf" in line
    assert "dest=/tmp/report.pdf" in line


def test_frozen_draft_fingerprint_determinism():
    d1 = FrozenDraft(
        to=["alice@example.com", "bob@example.com"],
        subject="Meeting Notes",
        body_text="Here are the notes.",
        cc=["carol@example.com"],
        attachments=[
            FrozenAttachment(
                filename="b.txt",
                mime_type="text/plain",
                file_path="/tmp/b.txt",
                size_bytes=10,
                sha256="hash_b",
            ),
            FrozenAttachment(
                filename="a.txt",
                mime_type="text/plain",
                file_path="/tmp/a.txt",
                size_bytes=10,
                sha256="hash_a",
            ),
        ],
    )
    # d2 has different order of to and attachments, but same content
    d2 = FrozenDraft(
        to=["bob@example.com", "alice@example.com"],
        subject="Meeting Notes",
        body_text="Here are the notes.",
        cc=["carol@example.com"],
        attachments=[
            FrozenAttachment(
                filename="a.txt",
                mime_type="text/plain",
                file_path="/tmp/a.txt",
                size_bytes=10,
                sha256="hash_a",
            ),
            FrozenAttachment(
                filename="b.txt",
                mime_type="text/plain",
                file_path="/tmp/b.txt",
                size_bytes=10,
                sha256="hash_b",
            ),
        ],
    )
    fp1 = d1.compute_fingerprint()
    fp2 = d2.compute_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64  # sha256 hex string


def test_frozen_draft_fingerprint_tamper_sensitivity():
    d1 = FrozenDraft(
        to=["alice@example.com"],
        subject="Original Subject",
        body_text="Body text",
    )
    d2 = FrozenDraft(
        to=["alice@example.com"],
        subject="Tampered Subject",
        body_text="Body text",
    )
    assert d1.compute_fingerprint() != d2.compute_fingerprint()


def test_frozen_draft_validation_success():
    draft = FrozenDraft(
        to=["alice@example.com"],
        subject="Valid Subject",
        body_text="Valid Body",
    )
    draft.validate()  # Should not raise


def test_frozen_draft_validation_recipient_bounds():
    # Empty recipients
    with pytest.raises(FrozenDraftValidationError, match="At least one recipient"):
        FrozenDraft(to=[], subject="Hi", body_text="Hello").validate()

    # Exceeding 10 recipients
    too_many = [f"user{i}@example.com" for i in range(11)]
    with pytest.raises(FrozenDraftValidationError, match="exceeds maximum bound of 10"):
        FrozenDraft(to=too_many, subject="Hi", body_text="Hello").validate()


def test_frozen_draft_validation_crlf_injection():
    with pytest.raises(FrozenDraftValidationError, match="CRLF characters detected in to address"):
        FrozenDraft(to=["alice@example.com\r\ncc:eve@example.com"], subject="Hi", body_text="Hello").validate()

    with pytest.raises(FrozenDraftValidationError, match="CRLF characters detected in subject"):
        FrozenDraft(to=["alice@example.com"], subject="Subject\nInjected-Header: evil", body_text="Hello").validate()


def test_frozen_draft_validation_size_bounds():
    # Body exceeding 1 MiB
    huge_body = "x" * (1_048_576 + 1)
    with pytest.raises(FrozenDraftValidationError, match="Aggregate message body .* exceeds maximum bound"):
        FrozenDraft(to=["alice@example.com"], subject="Hi", body_text=huge_body).validate()

    # Attachment exceeding 25 MiB
    huge_att = FrozenAttachment(
        filename="huge.bin",
        mime_type="application/octet-stream",
        file_path="/tmp/huge.bin",
        size_bytes=26_214_401,
        sha256="fakehash",
    )
    with pytest.raises(FrozenDraftValidationError, match="exceeds per-file bound"):
        FrozenDraft(to=["alice@example.com"], subject="Hi", body_text="Hello", attachments=[huge_att]).validate()


def test_frozen_draft_serialization_roundtrip():
    att = FrozenAttachment(
        filename="notes.txt",
        mime_type="text/plain",
        file_path="/tmp/notes.txt",
        size_bytes=100,
        sha256="abc123hash",
    )
    draft = FrozenDraft(
        to=["bob@example.com"],
        subject="Project Status",
        body_text="Here is the status report.",
        cc=["carol@example.com"],
        bcc=["dave@example.com"],
        body_html="<p>Here is the status report.</p>",
        thread_id="thread-123",
        in_reply_to="<msg-123@domain.com>",
        references=["<msg-100@domain.com>", "<msg-123@domain.com>"],
        attachments=[att],
        draft_id="r6067898827920447571",
    )
    d = draft.to_dict()
    restored = FrozenDraft.from_dict(d)
    assert restored.to == draft.to
    assert restored.subject == draft.subject
    assert restored.body_text == draft.body_text
    assert restored.cc == draft.cc
    assert restored.bcc == draft.bcc
    assert restored.body_html == draft.body_html
    assert restored.thread_id == draft.thread_id
    assert restored.in_reply_to == draft.in_reply_to
    assert restored.references == draft.references
    assert len(restored.attachments) == 1
    assert restored.attachments[0] == att
    assert restored.draft_id == draft.draft_id
    assert restored.compute_fingerprint() == draft.compute_fingerprint()


def test_cleanup_plan_fingerprint_and_canonicalization():
    from gmail_local.models import (
        CleanupAction,
        CleanupPlan,
        CleanupTarget,
    )

    t1 = CleanupTarget(
        message_id="msg_b",
        thread_id="th_b",
        sender="bob@example.com",
        subject="Promo B",
        date="2026-09-01",
        action=CleanupAction.TRASH,
    )
    t2 = CleanupTarget(
        message_id="msg_a",
        thread_id="th_a",
        sender="alice@example.com",
        subject="Promo A",
        date="2026-09-02",
        action=CleanupAction.TRASH,
    )

    # Permuted targets in plan1 vs plan2
    p1 = CleanupPlan(
        query="older_than:30d category:promotions",
        action_type=CleanupAction.TRASH,
        targets=[t1, t2],
    )
    p2 = CleanupPlan(
        query="  older_than:30d category:promotions  ",
        action_type=CleanupAction.TRASH,
        targets=[t2, t1],
    )

    fp1 = p1.compute_fingerprint()
    fp2 = p2.compute_fingerprint()
    assert fp1 == fp2
    assert len(fp1) == 64


def test_cleanup_plan_validation_boundaries():
    from gmail_local.models import (
        CleanupAction,
        CleanupPlan,
        CleanupPlanValidationError,
        CleanupTarget,
    )

    # Empty targets
    with pytest.raises(CleanupPlanValidationError, match="at least one target"):
        CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=[]).validate()

    # Empty message_id
    t_empty = CleanupTarget(
        message_id="   ",
        thread_id="th1",
        sender="s@e.com",
        subject="sub",
        date="2026-09-01",
        action=CleanupAction.TRASH,
    )
    with pytest.raises(CleanupPlanValidationError, match="empty message_id"):
        CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=[t_empty]).validate()

    # CRLF in message_id
    t_crlf_id = CleanupTarget(
        message_id="msg\r\n123",
        thread_id="th1",
        sender="s@e.com",
        subject="sub",
        date="2026-09-01",
        action=CleanupAction.TRASH,
    )
    with pytest.raises(CleanupPlanValidationError, match="CRLF"):
        CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=[t_crlf_id]).validate()

    # CRLF in label
    t_crlf_lbl = CleanupTarget(
        message_id="msg123",
        thread_id="th1",
        sender="s@e.com",
        subject="sub",
        date="2026-09-01",
        action=CleanupAction.ADD_LABEL,
        add_labels=["valid", "bad\nlbl"],
    )
    with pytest.raises(CleanupPlanValidationError, match="CRLF"):
        CleanupPlan(query="test", action_type=CleanupAction.ADD_LABEL, targets=[t_crlf_lbl]).validate()

    # Exceeding batch ceiling (75)
    targets_76 = [
        CleanupTarget(
            message_id=f"msg_{i}",
            thread_id=f"th_{i}",
            sender="s@e.com",
            subject=f"sub {i}",
            date="2026-09-01",
            action=CleanupAction.TRASH,
        )
        for i in range(76)
    ]
    with pytest.raises(CleanupPlanValidationError, match="exceeds maximum batch bound of 75"):
        CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=targets_76).validate()


def test_cleanup_plan_serialization_roundtrip_and_handoff():
    from gmail_local.models import (
        CleanupAction,
        CleanupPlan,
        CleanupTarget,
    )

    targets = [
        CleanupTarget(
            message_id="m1",
            thread_id="t1",
            sender="news@site.com",
            subject="Weekly Digest",
            date="2026-08-01",
            action=CleanupAction.ARCHIVE,
            remove_labels=["INBOX"],
        )
    ]
    plan = CleanupPlan(
        query="from:news@site.com is:unread",
        action_type=CleanupAction.ARCHIVE,
        targets=targets,
    )
    d = plan.to_dict()
    restored = CleanupPlan.from_dict(d)

    assert restored.query == plan.query
    assert restored.action_type == plan.action_type
    assert len(restored.targets) == 1
    assert restored.targets[0].message_id == "m1"
    assert restored.targets[0].remove_labels == ["INBOX"]
    assert restored.compute_fingerprint() == plan.compute_fingerprint()

    handoff = plan.to_handoff_summary()
    assert "CLEANUP HANDOFF" in handoff
    assert plan.compute_fingerprint() in handoff
    assert "Target Count:       1 messages" in handoff
    assert "Weekly Digest" in handoff


