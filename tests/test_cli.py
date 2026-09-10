"""Tests for Gmail Local CLI commands and argument parsing."""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from gmail_local.cli import build_parser, main
from gmail_local.models import (
    AttachmentDescriptor,
    CandidateMessage,
    HistoryDelta,
    LabelInfo,
    SelectedMessage,
    ThreadSummary,
)


def test_parser_subcommands_registration():
    parser = build_parser()
    subcommands = parser._subparsers._actions[1].choices.keys()
    expected = {
        "status",
        "login",
        "revoke",
        "search",
        "preview",
        "read",
        "attachments",
        "download",
        "history",
        "thread",
        "labels",
        "compose-status",
        "compose-login",
        "compose-revoke",
        "draft",
        "drafts",
    }
    assert expected.issubset(subcommands)


@patch("gmail_local.cli.GmailRetriever")
def test_cli_status_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.auth.get_status.return_value = {
        "account": "test@example.com",
        "keychain_service": "gmail-local-retrieval",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    }

    exit_code = main(["status"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Account:          test@example.com" in captured.out
    assert "Token Valid:      Yes" in captured.out


@patch("gmail_local.cli.AuthManager")
def test_cli_compose_status_command(mock_auth_cls, capsys):
    mock_trans_auth = MagicMock()
    mock_auth_cls.for_transmission.return_value = mock_trans_auth
    mock_trans_auth.get_status.return_value = {
        "account": "test@example.com",
        "keychain_service": "gmail-local-transmission",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.compose",
    }

    exit_code = main(["compose-status"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "=== Gmail Local Transmission Status ===" in captured.out
    assert "Account:          test@example.com" in captured.out
    assert "Keychain Service: gmail-local-transmission" in captured.out
    assert "https://www.googleapis.com/auth/gmail.compose" in captured.out


@patch("gmail_local.cli.AuthManager")
def test_cli_compose_login_command(mock_auth_cls, capsys):
    mock_trans_auth = MagicMock()
    mock_auth_cls.for_transmission.return_value = mock_trans_auth
    mock_trans_auth.run_interactive_login.return_value = "test@example.com"

    exit_code = main(["compose-login", "--no-browser"])
    assert exit_code == 0
    mock_trans_auth.run_interactive_login.assert_called_once_with(open_browser=False)
    captured = capsys.readouterr()
    assert "Successfully authorized transmission" in captured.out


@patch("gmail_local.cli.AuthManager")
def test_cli_compose_revoke_command(mock_auth_cls, capsys):
    mock_trans_auth = MagicMock()
    mock_auth_cls.for_transmission.return_value = mock_trans_auth

    exit_code = main(["compose-revoke"])
    assert exit_code == 0
    mock_trans_auth.revoke.assert_called_once()
    captured = capsys.readouterr()
    assert "Successfully revoked transmission credentials" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_search_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.search_messages.return_value = [
        CandidateMessage(
            id="msg_1",
            thread_id="th_1",
            date="2026-09-10",
            sender="court@example.gov",
            recipient="me@example.com",
            subject="Case Schedule",
        )
    ]

    exit_code = main(["search", "from:court", "--limit", "5"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Found 1 candidate(s)" in captured.out
    assert "court@example.gov" in captured.out
    assert "Case Schedule" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_preview_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.preview_candidates.return_value = [
        CandidateMessage(
            id="msg_1",
            thread_id="th_1",
            date="2026-09-10",
            sender="alice@example.com",
            recipient="me@example.com",
            subject="Hello",
            preview="Here is the snippet of the message...",
        )
    ]

    exit_code = main(["preview", "msg_1"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Candidate Previews (1)" in captured.out
    assert "Here is the snippet" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_read_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.get_messages.return_value = [
        SelectedMessage(
            id="msg_1",
            thread_id="th_1",
            date="2026-09-10",
            sender="info@bank.com",
            recipient="me@example.com",
            subject="Monthly Statement",
            body_text="Your balance is $5,000.",
            body_bytes=23,
            attachments=[],
        )
    ]

    exit_code = main(["read", "msg_1"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Retrieved 1 Full Message(s)" in captured.out
    assert "Your balance is $5,000." in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_attachments_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.list_attachments.return_value = [
        AttachmentDescriptor(
            message_id="msg_1",
            attachment_id="att_1",
            filename="invoice.pdf",
            mime_type="application/pdf",
            size_bytes=1024,
            is_inline=False,
        )
    ]

    exit_code = main(["attachments", "msg_1"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "invoice.pdf" in captured.out
    assert "1024 bytes" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_download_command(mock_retriever_cls, capsys, tmp_path: Path):
    mock_retriever = mock_retriever_cls.return_value
    dest = tmp_path / "out.pdf"
    mock_retriever.download_attachments.return_value = [dest]

    exit_code = main(["download", "msg_1", "att_1", "--dest", str(dest)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert f"Successfully downloaded attachment to: {dest}" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_history_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.get_history.return_value = HistoryDelta(
        history_id="12345",
        messages_added=["m1", "m2"],
        messages_deleted=[],
        is_expired=False,
    )

    exit_code = main(["history", "10000"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "History Delta (Since 10000)" in captured.out
    assert "m1, m2" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_thread_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.get_thread.return_value = ThreadSummary(
        thread_id="th_99",
        message_count=3,
        subject="Strategy Discussion",
        participants=["bob@example.com", "alice@example.com"],
        message_ids=["m1", "m2", "m3"],
    )

    exit_code = main(["thread", "th_99"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Conversation Thread: th_99" in captured.out
    assert "Strategy Discussion" in captured.out
    assert "bob@example.com" in captured.out


@patch("gmail_local.cli.GmailRetriever")
def test_cli_labels_command(mock_retriever_cls, capsys):
    mock_retriever = mock_retriever_cls.return_value
    mock_retriever.list_labels.return_value = [
        LabelInfo(id="INBOX", name="INBOX", type="system"),
        LabelInfo(id="Work", name="Work", type="user"),
    ]

    exit_code = main(["labels"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "Mailbox Labels (2)" in captured.out
    assert "INBOX" in captured.out
    assert "Work" in captured.out


def test_cli_draft_command_local_only(capsys):
    exit_code = main([
        "draft",
        "--to", "alice@example.com",
        "--subject", "Local Meeting Notes",
        "--body", "Here are the notes.",
        "--local-only",
    ])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "=== SEND HANDOFF ===" in captured.out
    assert "Draft Fingerprint:" in captured.out
    assert "alice@example.com" in captured.out
    assert "Local Only" in captured.out


@patch("gmail_local.cli.GmailDraftManager")
def test_cli_draft_command_push_to_gmail(mock_dm_cls, capsys):
    mock_dm = mock_dm_cls.return_value
    mock_dm.save_draft.side_effect = lambda draft, purpose: draft.__class__(
        to=draft.to,
        subject=draft.subject,
        body_text=draft.body_text,
        cc=draft.cc,
        bcc=draft.bcc,
        body_html=draft.body_html,
        in_reply_to=draft.in_reply_to,
        references=draft.references,
        attachments=draft.attachments,
        draft_id="r-987654321",
    )

    exit_code = main([
        "draft",
        "--to", "alice@example.com",
        "--subject", "Cloud Draft Notes",
        "--body", "Body content.",
    ])
    assert exit_code == 0
    mock_dm.save_draft.assert_called_once()
    captured = capsys.readouterr()
    assert "=== SEND HANDOFF ===" in captured.out
    assert "r-987654321" in captured.out
    assert "Staged to Gmail Drafts" in captured.out


@patch("gmail_local.cli.GmailDraftManager")
def test_cli_drafts_list_command(mock_dm_cls, capsys):
    mock_dm = mock_dm_cls.return_value
    mock_dm.list_drafts.return_value = [
        {"id": "r-1", "message": {"id": "m-1"}},
        {"id": "r-2", "message": {"id": "m-2"}},
    ]

    exit_code = main(["drafts", "list", "--limit", "5"])
    assert exit_code == 0
    mock_dm.list_drafts.assert_called_once_with(max_results=5, purpose="list_drafts")
    captured = capsys.readouterr()
    assert "Found 2 draft(s)" in captured.out
    assert "r-1" in captured.out
    assert "r-2" in captured.out


@patch("sys.stdin.isatty", return_value=False)
def test_cli_send_non_interactive_without_confirm_fails(mock_isatty, capsys, tmp_path: Path):
    from gmail_local.composer import create_frozen_draft, save_draft_locally
    draft = create_frozen_draft(
        to=["target@example.com"],
        subject="Non-interactive Send Test",
        body_text="Testing send without confirm.",
    )
    save_draft_locally(draft, drafts_dir=tmp_path)
    fp = draft.compute_fingerprint()

    with patch("gmail_local.cli.DRAFTS_DIR", tmp_path):
        exit_code = main(["send", "--draft", fp])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Manual Send Gate" in captured.err
    assert "--confirm" in captured.err


@patch("sys.stdin.isatty", return_value=False)
@patch("gmail_local.cli.GmailSender")
def test_cli_send_with_confirm_succeeds(mock_sender_cls, mock_isatty, capsys, tmp_path: Path):
    from gmail_local.composer import create_frozen_draft, save_draft_locally
    mock_sender = mock_sender_cls.return_value
    mock_sender.send.return_value = {
        "id": "sent_12345",
        "threadId": "th_12345",
        "draft_id": None,
        "fingerprint": "mock_fp",
    }

    draft = create_frozen_draft(
        to=["target@example.com"],
        subject="Confirmed Send Test",
        body_text="Testing confirmed send.",
    )
    save_draft_locally(draft, drafts_dir=tmp_path)
    fp = draft.compute_fingerprint()

    with patch("gmail_local.cli.DRAFTS_DIR", tmp_path):
        exit_code = main(["send", "--draft", fp, "--confirm"])
    assert exit_code == 0
    mock_sender.send.assert_called_once()
    captured = capsys.readouterr()
    assert "TRANSMISSION RECEIPT" in captured.out
    assert "sent_12345" in captured.out


@patch("sys.stdin.isatty", return_value=True)
@patch("builtins.input", return_value="no")
def test_cli_send_interactive_denied(mock_input, mock_isatty, capsys, tmp_path: Path):
    from gmail_local.composer import create_frozen_draft, save_draft_locally
    draft = create_frozen_draft(
        to=["target@example.com"],
        subject="Interactive Denial Test",
        body_text="Testing user abort.",
    )
    save_draft_locally(draft, drafts_dir=tmp_path)
    fp = draft.compute_fingerprint()

    with patch("gmail_local.cli.DRAFTS_DIR", tmp_path):
        exit_code = main(["send", "--draft", fp])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Transmission aborted" in captured.err


@patch("sys.stdin.isatty", return_value=True)
@patch("builtins.input", return_value="yes")
@patch("gmail_local.cli.GmailSender")
def test_cli_send_interactive_accepted(mock_sender_cls, mock_input, mock_isatty, capsys, tmp_path: Path):
    from gmail_local.composer import create_frozen_draft, save_draft_locally
    mock_sender = mock_sender_cls.return_value
    mock_sender.send.return_value = {
        "id": "sent_interactive_999",
        "threadId": "th_999",
        "draft_id": None,
        "fingerprint": "mock_fp",
    }

    draft = create_frozen_draft(
        to=["target@example.com"],
        subject="Interactive Acceptance Test",
        body_text="Testing user confirmation.",
    )
    save_draft_locally(draft, drafts_dir=tmp_path)
    fp = draft.compute_fingerprint()

    with patch("gmail_local.cli.DRAFTS_DIR", tmp_path):
        exit_code = main(["send", "--draft", fp])
    assert exit_code == 0
    mock_sender.send.assert_called_once()
    captured = capsys.readouterr()
    assert "TRANSMISSION RECEIPT" in captured.out
    assert "sent_interactive_999" in captured.out


def test_cli_send_draft_not_found(capsys, tmp_path: Path):
    with patch("gmail_local.cli.DRAFTS_DIR", tmp_path):
        exit_code = main(["send", "--draft", "unknown_identifier_12345", "--confirm"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Draft not found" in captured.err


@patch("gmail_local.cli.AuthManager")
def test_cli_modify_status(mock_auth_cls, capsys):
    mock_auth = mock_auth_cls.for_modification.return_value
    mock_auth.get_status.return_value = {
        "account": "user@example.com",
        "keychain_service": "gmail-local-modify",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.modify",
    }
    exit_code = main(["modify-status"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "=== Gmail Local Modification Status ===" in captured.out
    assert "gmail-local-modify" in captured.out
    assert "https://www.googleapis.com/auth/gmail.modify" in captured.out


@patch("gmail_local.cli.AuthManager")
def test_cli_modify_login(mock_auth_cls, capsys):
    mock_auth = mock_auth_cls.for_modification.return_value
    mock_auth.run_interactive_login.return_value = "user@example.com"

    exit_code = main(["modify-login", "--no-browser"])
    assert exit_code == 0
    mock_auth.run_interactive_login.assert_called_once_with(open_browser=False)
    captured = capsys.readouterr()
    assert "Successfully authorized modification" in captured.out


@patch("gmail_local.cli.AuthManager")
def test_cli_modify_revoke(mock_auth_cls, capsys):
    mock_auth = mock_auth_cls.for_modification.return_value

    exit_code = main(["modify-revoke"])
    assert exit_code == 0
    mock_auth.revoke.assert_called_once()
    captured = capsys.readouterr()
    assert "Successfully revoked modification credentials" in captured.out


@patch("gmail_local.cli.GmailModifier")
def test_cli_cleanup_plan_command(mock_mod_cls, capsys):
    from gmail_local.models import CleanupAction, CleanupPlan, CleanupTarget
    target = CleanupTarget(
        message_id="msg_1",
        thread_id="th_1",
        sender="promo@shop.com",
        subject="Big Discount",
        date="2026-08-01",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(
        query="older_than:30d",
        action_type=CleanupAction.TRASH,
        targets=[target],
    )
    mock_mod = mock_mod_cls.return_value
    mock_mod.build_plan.return_value = plan

    exit_code = main(["cleanup", "plan", "--query", "older_than:30d", "--action", "trash"])
    assert exit_code == 0
    mock_mod.build_plan.assert_called_once()
    captured = capsys.readouterr()
    assert "CLEANUP HANDOFF" in captured.out
    assert plan.compute_fingerprint() in captured.out


@patch("gmail_local.cli.load_plan_locally")
def test_cli_cleanup_preview_command(mock_load_plan, capsys):
    from gmail_local.models import CleanupAction, CleanupPlan, CleanupTarget
    target = CleanupTarget(
        message_id="msg_2",
        thread_id="th_2",
        sender="newsletter@site.com",
        subject="Monthly Brief",
        date="2026-08-10",
        action=CleanupAction.ARCHIVE,
        remove_labels=["INBOX"],
    )
    plan = CleanupPlan(
        query="label:newsletter",
        action_type=CleanupAction.ARCHIVE,
        targets=[target],
    )
    mock_load_plan.return_value = plan

    exit_code = main(["cleanup", "preview", "mock_fp"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "=== CLEANUP PLAN PREVIEW ===" in captured.out
    assert "msg_2" in captured.out
    assert "Monthly Brief" in captured.out


@patch("sys.stdin.isatty", return_value=False)
@patch("gmail_local.cli.load_plan_locally")
def test_cli_cleanup_apply_non_interactive_without_confirm_fails(mock_load_plan, mock_isatty, capsys):
    from gmail_local.models import CleanupAction, CleanupPlan, CleanupTarget
    target = CleanupTarget(
        message_id="msg_3",
        thread_id="th_3",
        sender="ad@site.com",
        subject="Sale",
        date="2026-08-10",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(query="label:ads", action_type=CleanupAction.TRASH, targets=[target])
    mock_load_plan.return_value = plan

    exit_code = main(["cleanup", "apply", "--plan", "some_fp"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "Manual Modify Gate violation" in captured.err
    assert "--confirm" in captured.err


@patch("sys.stdin.isatty", return_value=False)
@patch("gmail_local.cli.GmailModifier")
@patch("gmail_local.cli.load_plan_locally")
def test_cli_cleanup_apply_with_confirm_succeeds(mock_load_plan, mock_mod_cls, mock_isatty, capsys):
    from gmail_local.models import CleanupAction, CleanupPlan, CleanupTarget
    target = CleanupTarget(
        message_id="msg_4",
        thread_id="th_4",
        sender="ad@site.com",
        subject="Sale Today",
        date="2026-08-10",
        action=CleanupAction.TRASH,
    )
    plan = CleanupPlan(query="label:ads", action_type=CleanupAction.TRASH, targets=[target])
    mock_load_plan.return_value = plan
    mock_mod = mock_mod_cls.return_value
    mock_mod.apply_plan.return_value = {
        "status": "SUCCESS",
        "fingerprint": plan.compute_fingerprint(),
        "processed": 1,
        "action": "trash",
    }

    exit_code = main(["cleanup", "apply", "--plan", "some_fp", "--confirm"])
    assert exit_code == 0
    mock_mod.apply_plan.assert_called_once()
    captured = capsys.readouterr()
    assert "CLEANUP EXECUTION RECEIPT" in captured.out
    assert "Processed:       1 messages" in captured.out


@patch("gmail_local.cli.GmailModifier")
def test_cli_cleanup_untrash_command(mock_mod_cls, capsys):
    mock_mod = mock_mod_cls.return_value
    mock_mod.untrash.return_value = {"status": "SUCCESS", "message_id": "msg_restore_99"}

    exit_code = main(["cleanup", "untrash", "msg_restore_99"])
    assert exit_code == 0
    mock_mod.untrash.assert_called_once_with("msg_restore_99", purpose="cleanup_untrash")
    captured = capsys.readouterr()
    assert "Restored message 'msg_restore_99' from Trash" in captured.out


