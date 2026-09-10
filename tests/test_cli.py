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
