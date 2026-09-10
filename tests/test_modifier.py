"""Tests for GmailModifier, Staged Cleanup Plans, and Manual Modify Gate enforcement."""

from pathlib import Path
from unittest.mock import MagicMock
import pytest

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.models import (
    CleanupAction,
    CleanupPlan,
    CleanupPlanValidationError,
    CleanupTarget,
)
from gmail_local.modifier import (
    GmailModifier,
    ManualModifyGateViolationError,
    SecurityViolationError,
    load_plan_locally,
    save_plan_locally,
)
from gmail_local.rate_limiter import RateLimiter


@pytest.fixture
def mock_modifier(tmp_path: Path):
    auth_mock = MagicMock(spec=AuthManager)
    rate_limiter_mock = RateLimiter(max_units=10000, window_secs=60)
    audit_file = tmp_path / "audit.log"
    audit_logger = AuditLogger(log_path=audit_file)
    plans_dir = tmp_path / "plans"
    service_mock = MagicMock()

    modifier = GmailModifier(
        auth=auth_mock,
        rate_limiter=rate_limiter_mock,
        audit_logger=audit_logger,
        service=service_mock,
        plans_dir=plans_dir,
    )
    return modifier, service_mock, tmp_path


def test_save_and_load_cleanup_plan_locally(tmp_path: Path):
    plans_dir = tmp_path / "plans"
    target = CleanupTarget(
        message_id="msg_001",
        thread_id="th_001",
        sender="promo@store.com",
        subject="50% Off Sale",
        date="2026-08-15",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(
        query="from:promo@store.com older_than:30d",
        action_type=CleanupAction.TRASH,
        targets=[target],
    )

    saved_path = save_plan_locally(plan, plans_dir=plans_dir)
    assert saved_path.exists()
    assert saved_path.name == f"{plan.compute_fingerprint()}.json"

    # 1. Load by full fingerprint
    loaded = load_plan_locally(plan.compute_fingerprint(), plans_dir=plans_dir)
    assert loaded.compute_fingerprint() == plan.compute_fingerprint()
    assert loaded.targets[0].subject == "50% Off Sale"

    # 2. Load by fingerprint prefix (first 10 chars)
    prefix = plan.compute_fingerprint()[:10]
    loaded_prefix = load_plan_locally(prefix, plans_dir=plans_dir)
    assert loaded_prefix.compute_fingerprint() == plan.compute_fingerprint()

    # 3. Load by direct path
    loaded_path = load_plan_locally(str(saved_path), plans_dir=plans_dir)
    assert loaded_path.compute_fingerprint() == plan.compute_fingerprint()

    # 4. Unknown identifier raises FileNotFoundError
    with pytest.raises(FileNotFoundError, match="No local cleanup plan found"):
        load_plan_locally("nonexistent_fp", plans_dir=plans_dir)


def test_build_plan(mock_modifier):
    modifier, service_mock, tmp_path = mock_modifier

    # Mock list messages
    service_mock.users().messages().list().execute.return_value = {
        "messages": [{"id": "m1", "threadId": "t1"}, {"id": "m2", "threadId": "t2"}]
    }

    # Mock get message metadata
    def mock_get(userId, id, format, metadataHeaders):
        sub = "Promo 1" if id == "m1" else "Promo 2"
        return {
            "id": id,
            "threadId": f"t_{id}",
            "internalDate": "1725900000000",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": sub},
                    {"name": "From", "value": "store@example.com"},
                    {"name": "Date", "value": "Wed, 09 Sep 2026 12:00:00 -0700"},
                ]
            },
        }

    service_mock.users().messages().get().execute.side_effect = [
        mock_get("me", "m1", "metadata", ["Subject", "From", "Date"]),
        mock_get("me", "m2", "metadata", ["Subject", "From", "Date"]),
    ]

    plan = modifier.build_plan(
        query="label:promotions older_than:30d",
        action=CleanupAction.TRASH,
        limit=10,
    )

    assert plan.action_type == CleanupAction.TRASH
    assert len(plan.targets) == 2
    assert plan.targets[0].message_id == "m1"
    assert plan.targets[0].subject == "Promo 1"
    assert plan.targets[1].message_id == "m2"
    assert plan.targets[1].subject == "Promo 2"

    # Verify plan was saved to plans_dir
    fp = plan.compute_fingerprint()
    assert (modifier.plans_dir / f"{fp}.json").exists()

    # Verify audit log recorded plan creation
    audit_content = (tmp_path / "audit.log").read_text()
    assert "op=cleanup_plan" in audit_content
    assert f"fp={fp}" in audit_content


def test_apply_plan_trash(mock_modifier):
    modifier, service_mock, tmp_path = mock_modifier

    target = CleanupTarget(
        message_id="msg_trash_1",
        thread_id="th_1",
        sender="s@e.com",
        subject="Spam Deal",
        date="2026-09-01",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(
        query="from:spam",
        action_type=CleanupAction.TRASH,
        targets=[target],
    )

    service_mock.users().messages().trash().execute.return_value = {"id": "msg_trash_1"}

    res = modifier.apply_plan(plan, confirm=True)
    assert res["status"] == "SUCCESS"
    assert res["processed"] == 1
    assert res["action"] == "trash"

    service_mock.users().messages().trash.assert_called_with(userId="me", id="msg_trash_1")

    # Verify audit entry
    audit_content = (tmp_path / "audit.log").read_text()
    assert "op=trash" in audit_content
    assert "mid=msg_trash_1" in audit_content
    assert f"fp={plan.compute_fingerprint()}" in audit_content


def test_apply_plan_archive(mock_modifier):
    modifier, service_mock, tmp_path = mock_modifier

    target = CleanupTarget(
        message_id="msg_arc_1",
        thread_id="th_1",
        sender="notifications@app.com",
        subject="Alert Notice",
        date="2026-09-01",
        action=CleanupAction.ARCHIVE,
        remove_labels=["INBOX"],
    )
    plan = CleanupPlan(
        query="from:notifications",
        action_type=CleanupAction.ARCHIVE,
        targets=[target],
    )

    service_mock.users().messages().modify().execute.return_value = {"id": "msg_arc_1"}

    res = modifier.apply_plan(plan, confirm=True)
    assert res["status"] == "SUCCESS"
    assert res["processed"] == 1
    assert res["action"] == "archive"

    service_mock.users().messages().modify.assert_called_with(
        userId="me",
        id="msg_arc_1",
        body={"removeLabelIds": ["INBOX"]},
    )

    audit_content = (tmp_path / "audit.log").read_text()
    assert "op=archive" in audit_content
    assert "mid=msg_arc_1" in audit_content


def test_apply_plan_mark_read(mock_modifier):
    modifier, service_mock, tmp_path = mock_modifier

    target = CleanupTarget(
        message_id="msg_read_1",
        thread_id="th_1",
        sender="notifications@app.com",
        subject="Alert Notice",
        date="2026-09-01",
        action=CleanupAction.MARK_READ,
        remove_labels=["UNREAD"],
    )
    plan = CleanupPlan(
        query="label:unread",
        action_type=CleanupAction.MARK_READ,
        targets=[target],
    )

    service_mock.users().messages().modify().execute.return_value = {"id": "msg_read_1"}

    res = modifier.apply_plan(plan, confirm=True)
    assert res["status"] == "SUCCESS"

    service_mock.users().messages().modify.assert_called_with(
        userId="me",
        id="msg_read_1",
        body={"removeLabelIds": ["UNREAD"]},
    )

    audit_content = (tmp_path / "audit.log").read_text()
    assert "op=mark_read" in audit_content


def test_manual_modify_gate_non_interactive_violation(mock_modifier):
    modifier, service_mock, _ = mock_modifier

    target = CleanupTarget(
        message_id="msg_1",
        thread_id="th_1",
        sender="s@e.com",
        subject="Sub",
        date="2026-09-01",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=[target])

    # Calling apply_plan without confirm and without interactive mode must raise ManualModifyGateViolationError
    with pytest.raises(ManualModifyGateViolationError, match="Manual Modify Gate violation"):
        modifier.apply_plan(plan, confirm=False, interactive=False)

    # Confirm that no modify API calls were made
    service_mock.users().messages().trash.assert_not_called()
    service_mock.users().messages().modify.assert_not_called()


def test_untrash(mock_modifier):
    modifier, service_mock, tmp_path = mock_modifier

    service_mock.users().messages().untrash().execute.return_value = {"id": "msg_untrash_1"}

    res = modifier.untrash("msg_untrash_1")
    assert res["status"] == "SUCCESS"
    assert res["message_id"] == "msg_untrash_1"

    service_mock.users().messages().untrash.assert_called_with(userId="me", id="msg_untrash_1")

    audit_content = (tmp_path / "audit.log").read_text()
    assert "op=untrash" in audit_content
    assert "mid=msg_untrash_1" in audit_content


def test_permanent_delete_strictly_forbidden(mock_modifier):
    modifier, _, _ = mock_modifier
    # If any method tries to call permanent delete, it must be explicitly blocked
    with pytest.raises(SecurityViolationError, match="Permanent deletion"):
        modifier.delete_message_permanently("msg_123")
