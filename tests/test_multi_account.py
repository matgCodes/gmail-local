"""Tests for explicit account selection and login identity verification (issue #18, phase 1)."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthError, AuthManager, IdentityMismatchError
from gmail_local.cli import main
from gmail_local.config import resolve_account
from gmail_local.models import AuditEntry


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def get_password(self, service, username):
        return self.store.get((service, username))

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


def _secret(tmp_path: Path) -> Path:
    secret_file = tmp_path / "client_secret.json"
    secret_file.write_text(json.dumps({"installed": {"client_id": "c1", "token_uri": "uri"}}))
    return secret_file


def _flow_returning(refresh_token="new-refresh-token"):
    creds = MagicMock()
    creds.refresh_token = refresh_token
    creds.granted_scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    flow = MagicMock()
    flow.run_local_server.return_value = creds
    return flow, creds


# --- resolve_account precedence ---------------------------------------------


def test_flag_wins_over_env_and_file(tmp_path: Path):
    account_file = tmp_path / "account.txt"
    account_file.write_text("file@example.com\n")
    assert resolve_account("flag@example.com", {"GMAIL_ACCOUNT": "env@example.com"}, account_file) == "flag@example.com"


def test_env_wins_over_file(tmp_path: Path):
    account_file = tmp_path / "account.txt"
    account_file.write_text("file@example.com\n")
    assert resolve_account(None, {"GMAIL_ACCOUNT": "env@example.com"}, account_file) == "env@example.com"


def test_file_is_the_fallback(tmp_path: Path):
    account_file = tmp_path / "account.txt"
    account_file.write_text("file@example.com\n")
    assert resolve_account(None, {}, account_file) == "file@example.com"


def test_placeholder_when_nothing_configured(tmp_path: Path):
    assert resolve_account(None, {}, tmp_path / "missing.txt") == "user@example.com"


def test_blank_flag_is_rejected(tmp_path: Path):
    with pytest.raises(ValueError):
        resolve_account("  ", {}, tmp_path / "missing.txt")


# --- login identity verification --------------------------------------------


def test_login_passes_login_hint(tmp_path: Path):
    flow, _ = _flow_returning()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=FakeKeyring()
    )
    manager.identity_resolver = lambda creds: "new@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow):
        manager.run_interactive_login(open_browser=False)
    assert flow.run_local_server.call_args.kwargs["login_hint"] == "new@example.com"


def test_login_stores_token_when_mailbox_matches_ignoring_case(tmp_path: Path):
    flow, _ = _flow_returning()
    keyring_mock = FakeKeyring()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="New@Example.com", keyring_backend=keyring_mock
    )
    manager.identity_resolver = lambda creds: "new@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow):
        assert manager.run_interactive_login(open_browser=False) == "New@Example.com"
    assert keyring_mock.store == {("gmail-local-retrieval", "New@Example.com"): "new-refresh-token"}


def test_login_mismatch_stores_nothing_and_revokes_new_token(tmp_path: Path):
    flow, _ = _flow_returning()
    keyring_mock = FakeKeyring()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=keyring_mock
    )
    manager.identity_resolver = lambda creds: "primary@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow), patch(
        "gmail_local.auth._revoke_token"
    ) as revoke:
        with pytest.raises(IdentityMismatchError) as excinfo:
            manager.run_interactive_login(open_browser=False)
    assert keyring_mock.store == {}
    revoke.assert_called_once_with("new-refresh-token")
    assert "new@example.com" in str(excinfo.value)
    assert "primary@example.com" in str(excinfo.value)


def test_mismatch_does_not_touch_existing_token_for_label(tmp_path: Path):
    flow, _ = _flow_returning()
    keyring_mock = FakeKeyring()
    keyring_mock.set_password("gmail-local-retrieval", "new@example.com", "existing-token")
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=keyring_mock
    )
    manager.identity_resolver = lambda creds: "primary@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow), patch(
        "gmail_local.auth._revoke_token"
    ):
        with pytest.raises(IdentityMismatchError):
            manager.run_interactive_login(open_browser=False)
    assert keyring_mock.store == {("gmail-local-retrieval", "new@example.com"): "existing-token"}


def test_only_retrieval_grant_verifies_identity_in_phase_1():
    assert AuthManager.for_retrieval().identity_resolver is not None
    assert AuthManager.for_transmission().identity_resolver is None
    assert AuthManager.for_modification().identity_resolver is None
    assert AuthManager.for_calendar().identity_resolver is None
    assert AuthManager.for_availability().identity_resolver is None


# --- status reports the verified mailbox ------------------------------------


def _status_manager(tmp_path: Path, mailbox: str) -> AuthManager:
    keyring_mock = FakeKeyring()
    keyring_mock.set_password("gmail-local-retrieval", "new@example.com", "tok")
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=keyring_mock
    )
    manager.identity_resolver = lambda creds: mailbox
    valid_creds = MagicMock()
    valid_creds.valid = True
    manager.get_credentials = lambda: valid_creds
    return manager


def test_status_reports_verified_mailbox(tmp_path: Path):
    status = _status_manager(tmp_path, "NEW@example.com").get_status()
    assert status["mailbox"] == "NEW@example.com"
    assert status["mailbox_matches"] is True


def test_status_flags_mailbox_mismatch(tmp_path: Path):
    status = _status_manager(tmp_path, "primary@example.com").get_status()
    assert status["mailbox"] == "primary@example.com"
    assert status["mailbox_matches"] is False


@patch("gmail_local.cli.GmailRetriever")
def test_cli_status_fails_on_mailbox_mismatch(mock_retriever_cls, capsys):
    mock_retriever_cls.return_value.auth.get_status.return_value = {
        "account": "new@example.com",
        "keychain_service": "gmail-local-retrieval",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "mailbox": "primary@example.com",
        "mailbox_matches": False,
    }
    assert main(["status"]) == 1
    out = capsys.readouterr().out
    assert "Mailbox:          primary@example.com (DOES NOT MATCH account)" in out


# --- CLI selection ----------------------------------------------------------


@patch("gmail_local.cli.GmailRetriever")
def test_account_before_subcommand_routes_retrieval(mock_retriever_cls, capsys):
    mock_retriever_cls.return_value.search_messages.return_value = []
    assert main(["--account", "new@example.com", "search", "from:x"]) == 0
    mock_retriever_cls.assert_called_once_with(account="new@example.com")
    assert "account: new@example.com" in capsys.readouterr().err


@patch("gmail_local.cli.GmailRetriever")
def test_account_after_subcommand_routes_retrieval(mock_retriever_cls, capsys):
    mock_retriever_cls.return_value.search_messages.return_value = []
    assert main(["search", "from:x", "--account", "new@example.com"]) == 0
    mock_retriever_cls.assert_called_once_with(account="new@example.com")
    assert "account: new@example.com" in capsys.readouterr().err


@patch("gmail_local.cli.GmailRetriever")
def test_conflicting_account_positions_are_rejected(mock_retriever_cls, capsys):
    assert main(["--account", "a@example.com", "search", "x", "--account", "b@example.com"]) == 2
    mock_retriever_cls.assert_not_called()
    assert "a@example.com" in capsys.readouterr().err


@patch("gmail_local.cli.DEFAULT_ACCOUNT", "primary@example.com")
@patch("gmail_local.cli.GmailRetriever")
def test_no_flag_uses_default_account_and_prints_it(mock_retriever_cls, capsys):
    mock_retriever_cls.return_value.search_messages.return_value = []
    assert main(["search", "from:x"]) == 0
    mock_retriever_cls.assert_called_once_with(account="primary@example.com")
    assert "account: primary@example.com" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [
        ["compose-status"],
        ["send", "--draft", "abc123"],
        ["cleanup", "apply", "--plan", "abc123"],
        ["calendar-login"],
        ["availability", "windows", "--from", "2026-10-21", "--to", "2026-10-22", "--timezone", "UTC", "--hours-json", "{}"],
        ["triage", "scan"],
    ],
)
@patch("gmail_local.cli.DEFAULT_ACCOUNT", "primary@example.com")
@patch("gmail_local.cli.GmailSender")
@patch("gmail_local.cli.GmailModifier")
@patch("gmail_local.cli.AuthManager")
@patch("gmail_local.cli.GmailRetriever")
def test_non_retrieval_commands_refuse_non_default_account(
    mock_retriever_cls, mock_auth_cls, mock_modifier_cls, mock_sender_cls, argv, capsys
):
    assert main(["--account", "new@example.com", *argv]) == 2
    mock_retriever_cls.assert_not_called()
    mock_auth_cls.assert_not_called()
    mock_modifier_cls.assert_not_called()
    mock_sender_cls.assert_not_called()
    assert "#18" in capsys.readouterr().err


@patch("gmail_local.cli.DEFAULT_ACCOUNT", "primary@example.com")
@patch("gmail_local.cli.AuthManager")
@patch("gmail_local.cli.GmailRetriever")
def test_non_retrieval_command_accepts_default_account_explicitly(mock_retriever_cls, mock_auth_cls, capsys):
    mock_auth_cls.for_transmission.return_value.get_status.return_value = {
        "account": "primary@example.com",
        "keychain_service": "gmail-local-transmission",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.compose",
    }
    assert main(["--account", "PRIMARY@example.com", "compose-status"]) == 0


# --- audit records the account ----------------------------------------------


def test_audit_entry_records_account():
    entry = AuditEntry(operation="search", purpose="p", status="success", account="new@example.com")
    assert "acct=new@example.com" in entry.to_log_line()


def test_audit_logger_stamps_its_account(tmp_path: Path):
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_path, account="new@example.com")
    logger.record(AuditEntry(operation="search", purpose="p", status="success"))
    assert "acct=new@example.com" in log_path.read_text()


def test_login_skips_login_hint_for_placeholder_account(tmp_path: Path):
    flow, _ = _flow_returning()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="user@example.com", keyring_backend=FakeKeyring()
    )
    manager.identity_resolver = lambda creds: "user@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow):
        manager.run_interactive_login(open_browser=False)
    assert "login_hint" not in flow.run_local_server.call_args.kwargs


def test_identity_lookup_failure_stores_nothing_and_revokes(tmp_path: Path):
    flow, _ = _flow_returning()
    keyring_mock = FakeKeyring()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=keyring_mock
    )

    def failing_lookup(creds):
        raise ConnectionError("offline")

    manager.identity_resolver = failing_lookup
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow), patch(
        "gmail_local.auth._revoke_token"
    ) as revoke:
        with pytest.raises(AuthError) as excinfo:
            manager.run_interactive_login(open_browser=False)
    assert keyring_mock.store == {}
    revoke.assert_called_once_with("new-refresh-token")
    assert "new-refresh-token" not in str(excinfo.value)


def test_mismatch_when_revoke_fails_tells_operator_to_remove_access(tmp_path: Path):
    flow, _ = _flow_returning()
    manager = AuthManager.for_retrieval(
        client_secret_path=_secret(tmp_path), account="new@example.com", keyring_backend=FakeKeyring()
    )
    manager.identity_resolver = lambda creds: "primary@example.com"
    with patch("gmail_local.auth.InstalledAppFlow.from_client_secrets_file", return_value=flow), patch(
        "gmail_local.auth._revoke_token", side_effect=ConnectionError("offline")
    ):
        with pytest.raises(IdentityMismatchError) as excinfo:
            manager.run_interactive_login(open_browser=False)
    assert "could not be revoked" in str(excinfo.value)
    assert "myaccount.google.com/permissions" in str(excinfo.value)


@patch("gmail_local.cli.GmailRetriever")
def test_cli_login_reports_identity_mismatch_without_traceback(mock_retriever_cls, capsys):
    mock_retriever_cls.return_value.auth.run_interactive_login.side_effect = IdentityMismatchError("signed in as other")
    assert main(["--account", "new@example.com", "login", "--no-browser"]) == 1
    assert "signed in as other" in capsys.readouterr().err


def test_test_runs_never_see_the_real_account():
    from gmail_local.config import DEFAULT_ACCOUNT

    assert DEFAULT_ACCOUNT == "user@example.com"


def test_status_lookup_failure_keeps_token_valid_and_mailbox_unknown(tmp_path: Path):
    manager = _status_manager(tmp_path, "unused")

    def failing_lookup(creds):
        raise ConnectionError("offline")

    manager.identity_resolver = failing_lookup
    status = manager.get_status()
    assert status["is_valid"] is True
    assert status["mailbox"] is None
    assert status["mailbox_matches"] is None
