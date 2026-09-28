"""Tests for AuthManager and Keychain interactions."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gmail_local.auth import AuthManager, MissingClientSecretError, MissingTokenError


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def set_password(self, service, username, password):
        self.store[(service, username)] = password

    def get_password(self, service, username):
        return self.store.get((service, username))

    def delete_password(self, service, username):
        self.store.pop((service, username), None)


def test_missing_client_secret(tmp_path: Path):
    manager = AuthManager(client_secret_path=tmp_path / "nonexistent.json")
    with pytest.raises(MissingClientSecretError):
        manager.load_client_config()


def test_valid_desktop_client_config(tmp_path: Path):
    secret_file = tmp_path / "client_secret.json"
    secret_file.write_text(
        json.dumps({
            "installed": {
                "client_id": "test-client-id.apps.googleusercontent.com",
                "client_secret": "test-secret",
                "token_uri": "https://oauth2.googleapis.com/token",
            }
        })
    )
    manager = AuthManager(client_secret_path=secret_file)
    config = manager.load_client_config()
    assert "installed" in config
    assert config["installed"]["client_id"] == "test-client-id.apps.googleusercontent.com"


def test_keychain_token_missing_raises_error(tmp_path: Path):
    secret_file = tmp_path / "client_secret.json"
    secret_file.write_text(json.dumps({"installed": {"client_id": "c1", "token_uri": "uri"}}))

    keyring_mock = FakeKeyring()
    manager = AuthManager(
        client_secret_path=secret_file,
        keyring_backend=keyring_mock,
        account="test@example.com",
    )

    with pytest.raises(MissingTokenError):
        manager.get_credentials()


def test_status_reporting(tmp_path: Path):
    secret_file = tmp_path / "client_secret.json"
    secret_file.write_text(json.dumps({"installed": {"client_id": "c1", "token_uri": "uri"}}))

    keyring_mock = FakeKeyring()
    manager = AuthManager(
        client_secret_path=secret_file,
        keyring_backend=keyring_mock,
        account="test@example.com",
    )

    status = manager.get_status()
    assert status["account"] == "test@example.com"
    assert status["has_client_secret"] is True
    assert status["has_keychain_token"] is False
    assert status["is_valid"] is False

    # Simulate token stored
    keyring_mock.set_password("gmail-local-retrieval", "test@example.com", "fake-refresh-token")
    status2 = manager.get_status()
    assert status2["has_keychain_token"] is True


def test_transmission_auth_manager_defaults_and_isolation(tmp_path: Path):
    from gmail_local.config import (
        CLIENT_SECRET_TRANSMISSION_FILE,
        KEYCHAIN_SERVICE_TRANSMISSION,
        TRANSMISSION_SCOPE,
    )

    keyring_mock = FakeKeyring()
    # Populate retrieval token
    keyring_mock.set_password("gmail-local-retrieval", "test@example.com", "retrieval-token")

    # Create transmission manager
    trans_manager = AuthManager.for_transmission(
        account="test@example.com",
        keyring_backend=keyring_mock,
    )

    assert trans_manager.keychain_service == KEYCHAIN_SERVICE_TRANSMISSION
    assert trans_manager.client_secret_path == CLIENT_SECRET_TRANSMISSION_FILE
    assert trans_manager.scopes == [TRANSMISSION_SCOPE]

    # Crucial ADR 0003 isolation test: transmission manager must NOT see the retrieval token!
    status = trans_manager.get_status()
    assert status["keychain_service"] == KEYCHAIN_SERVICE_TRANSMISSION
    assert status["scope"] == TRANSMISSION_SCOPE
    assert status["has_keychain_token"] is False  # Must be isolated from retrieval token!

    # Store transmission token and verify it does NOT overwrite retrieval token
    keyring_mock.set_password(KEYCHAIN_SERVICE_TRANSMISSION, "test@example.com", "trans-token")
    assert trans_manager.get_status()["has_keychain_token"] is True
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"

    # Revoke transmission token and verify retrieval token remains intact
    from unittest.mock import patch
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        trans_manager.revoke()

    assert trans_manager.get_status()["has_keychain_token"] is False
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"


def test_modification_auth_manager_defaults_and_isolation(tmp_path: Path):
    from gmail_local.config import (
        CLIENT_SECRET_MODIFY_FILE,
        KEYCHAIN_SERVICE_MODIFY,
        MODIFY_SCOPE,
    )

    keyring_mock = FakeKeyring()
    # Populate existing retrieval and transmission tokens
    keyring_mock.set_password("gmail-local-retrieval", "test@example.com", "retrieval-token")
    keyring_mock.set_password("gmail-local-transmission", "test@example.com", "transmission-token")

    # Create modification manager
    modify_manager = AuthManager.for_modification(
        account="test@example.com",
        keyring_backend=keyring_mock,
    )

    assert modify_manager.keychain_service == KEYCHAIN_SERVICE_MODIFY
    assert modify_manager.client_secret_path == CLIENT_SECRET_MODIFY_FILE
    assert modify_manager.scopes == [MODIFY_SCOPE]

    # Crucial ADR 0003/0010 isolation test: modify manager must NOT see retrieval or transmission tokens!
    status = modify_manager.get_status()
    assert status["keychain_service"] == KEYCHAIN_SERVICE_MODIFY
    assert status["scope"] == MODIFY_SCOPE
    assert status["has_keychain_token"] is False

    # Store modify token and verify it does NOT overwrite others
    keyring_mock.set_password(KEYCHAIN_SERVICE_MODIFY, "test@example.com", "modify-token")
    assert modify_manager.get_status()["has_keychain_token"] is True
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"
    assert keyring_mock.get_password("gmail-local-transmission", "test@example.com") == "transmission-token"

    # Revoke modify token and verify others remain intact
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        modify_manager.revoke()

    assert modify_manager.get_status()["has_keychain_token"] is False
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"
    assert keyring_mock.get_password("gmail-local-transmission", "test@example.com") == "transmission-token"


def test_calendar_auth_manager_defaults_and_isolation(tmp_path: Path):
    from gmail_local.config import (
        CALENDAR_SCOPE,
        KEYCHAIN_SERVICE_CALENDAR,
    )

    keyring_mock = FakeKeyring()
    # Populate existing tokens across other services
    keyring_mock.set_password("gmail-local-retrieval", "test@example.com", "retrieval-token")
    keyring_mock.set_password("gmail-local-transmission", "test@example.com", "transmission-token")
    keyring_mock.set_password("gmail-local-modify", "test@example.com", "modify-token")

    # 1. Test fallback to client_secret_meet.json when calendar secret doesn't exist
    cal_secret = tmp_path / "client_secret_calendar.json"
    meet_secret = tmp_path / "client_secret_meet.json"
    meet_secret.write_text(json.dumps({"installed": {"client_id": "meet-c1", "token_uri": "uri"}}))

    with patch("gmail_local.auth.CLIENT_SECRET_CALENDAR_FILE", cal_secret), \
         patch("gmail_local.auth.CLIENT_SECRET_MEET_FILE", meet_secret):
        cal_manager = AuthManager.for_calendar(
            account="test@example.com",
            keyring_backend=keyring_mock,
        )
        assert cal_manager.client_secret_path == meet_secret

    # 2. Test preference for client_secret_calendar.json when it does exist
    cal_secret.write_text(json.dumps({"installed": {"client_id": "cal-c1", "token_uri": "uri"}}))
    with patch("gmail_local.auth.CLIENT_SECRET_CALENDAR_FILE", cal_secret), \
         patch("gmail_local.auth.CLIENT_SECRET_MEET_FILE", meet_secret):
        cal_manager2 = AuthManager.for_calendar(
            account="test@example.com",
            keyring_backend=keyring_mock,
        )
        assert cal_manager2.client_secret_path == cal_secret

    # 3. Verify scope and keychain service isolation
    assert cal_manager.keychain_service == KEYCHAIN_SERVICE_CALENDAR
    assert cal_manager.scopes == [CALENDAR_SCOPE]

    status = cal_manager.get_status()
    assert status["keychain_service"] == KEYCHAIN_SERVICE_CALENDAR
    assert status["scope"] == CALENDAR_SCOPE
    assert status["has_keychain_token"] is False

    # Store calendar token and verify other services are isolated
    keyring_mock.set_password(KEYCHAIN_SERVICE_CALENDAR, "test@example.com", "cal-token")
    assert cal_manager.get_status()["has_keychain_token"] is True
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"
    assert keyring_mock.get_password("gmail-local-transmission", "test@example.com") == "transmission-token"
    assert keyring_mock.get_password("gmail-local-modify", "test@example.com") == "modify-token"

    # Revoke calendar token
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        cal_manager.revoke()

    assert cal_manager.get_status()["has_keychain_token"] is False
    assert keyring_mock.get_password("gmail-local-retrieval", "test@example.com") == "retrieval-token"
    assert keyring_mock.get_password("gmail-local-transmission", "test@example.com") == "transmission-token"
    assert keyring_mock.get_password("gmail-local-modify", "test@example.com") == "modify-token"


AVAILABILITY = "https://www.googleapis.com/auth/calendar.freebusy"
OTHER_GRANTS = {
    "gmail-local-retrieval": "retrieval-token",
    "gmail-local-transmission": "transmission-token",
    "gmail-local-modify": "modify-token",
    "gmail-local-calendar": "calendar-token",
}


def _availability_manager(tmp_path: Path, keyring_mock: FakeKeyring) -> AuthManager:
    secret_file = tmp_path / "client_secret_availability.json"
    secret_file.write_text(json.dumps({"installed": {"client_id": "avail-c1", "token_uri": "uri"}}))
    return AuthManager.for_availability(
        client_secret_path=secret_file,
        account="test@example.com",
        keyring_backend=keyring_mock,
    )


def _mock_flow(mock_flow_cls, granted_scopes, refresh_token="avail-refresh-token"):
    creds = MagicMock()
    creds.granted_scopes = granted_scopes
    creds.refresh_token = refresh_token
    mock_flow_cls.from_client_secrets_file.return_value.run_local_server.return_value = creds


def test_availability_auth_manager_defaults_and_isolation():
    from gmail_local.config import (
        AVAILABILITY_SCOPE,
        CLIENT_SECRET_AVAILABILITY_FILE,
        KEYCHAIN_SERVICE,
        KEYCHAIN_SERVICE_AVAILABILITY,
        KEYCHAIN_SERVICE_CALENDAR,
        KEYCHAIN_SERVICE_MODIFY,
        KEYCHAIN_SERVICE_TRANSMISSION,
    )

    keyring_mock = FakeKeyring()
    for service, token in OTHER_GRANTS.items():
        keyring_mock.set_password(service, "test@example.com", token)

    avail_manager = AuthManager.for_availability(account="test@example.com", keyring_backend=keyring_mock)

    assert AVAILABILITY_SCOPE == AVAILABILITY
    assert avail_manager.scopes == [AVAILABILITY]
    assert avail_manager.client_secret_path == CLIENT_SECRET_AVAILABILITY_FILE
    assert avail_manager.keychain_service == KEYCHAIN_SERVICE_AVAILABILITY == "gmail-local-availability"
    assert avail_manager.keychain_service not in {
        KEYCHAIN_SERVICE,
        KEYCHAIN_SERVICE_TRANSMISSION,
        KEYCHAIN_SERVICE_MODIFY,
        KEYCHAIN_SERVICE_CALENDAR,
    }
    assert avail_manager.verify_granted_scopes is True

    status = avail_manager.get_status()
    assert status["keychain_service"] == KEYCHAIN_SERVICE_AVAILABILITY
    assert status["scope"] == AVAILABILITY
    assert status["has_keychain_token"] is False

    keyring_mock.set_password(KEYCHAIN_SERVICE_AVAILABILITY, "test@example.com", "avail-token")
    assert avail_manager.get_status()["has_keychain_token"] is True

    # availability-revoke clears only gmail-local-availability
    with patch("requests.post") as mock_post:
        mock_post.return_value.status_code = 200
        avail_manager.revoke()
    assert mock_post.call_args.kwargs["params"] == {"token": "avail-token"}

    assert avail_manager.get_status()["has_keychain_token"] is False
    for service, token in OTHER_GRANTS.items():
        assert keyring_mock.get_password(service, "test@example.com") == token


def test_availability_auth_manager_has_no_meet_secret_fallback(tmp_path: Path):
    meet_secret = tmp_path / "client_secret_meet.json"
    meet_secret.write_text(json.dumps({"installed": {"client_id": "meet-c1", "token_uri": "uri"}}))

    with patch("gmail_local.auth.CLIENT_SECRET_MEET_FILE", meet_secret), \
         patch("gmail_local.auth.CLIENT_SECRET_CALENDAR_FILE", meet_secret):
        manager = AuthManager.for_availability(
            client_secret_path=tmp_path / "client_secret_availability.json",
            keyring_backend=FakeKeyring(),
        )
        assert manager.client_secret_path == tmp_path / "client_secret_availability.json"
        with pytest.raises(MissingClientSecretError):
            manager.load_client_config()


def test_existing_grants_do_not_verify_granted_scopes():
    keyring_mock = FakeKeyring()
    for factory in (
        AuthManager.for_retrieval,
        AuthManager.for_transmission,
        AuthManager.for_modification,
        AuthManager.for_calendar,
    ):
        assert factory(keyring_backend=keyring_mock).verify_granted_scopes is False


@patch("gmail_local.auth.InstalledAppFlow")
def test_availability_login_stores_token_when_granted_scopes_match(mock_flow_cls, tmp_path: Path):
    keyring_mock = FakeKeyring()
    manager = _availability_manager(tmp_path, keyring_mock)
    _mock_flow(mock_flow_cls, [AVAILABILITY])

    assert manager.run_interactive_login(open_browser=False) == "test@example.com"

    mock_flow_cls.from_client_secrets_file.assert_called_once_with(
        str(manager.client_secret_path),
        scopes=[AVAILABILITY],
        autogenerate_code_verifier=True,
    )
    assert keyring_mock.store == {("gmail-local-availability", "test@example.com"): "avail-refresh-token"}


@pytest.mark.parametrize(
    "granted_scopes",
    [
        [AVAILABILITY, "https://www.googleapis.com/auth/calendar.events.owned"],
        [AVAILABILITY, "https://www.googleapis.com/auth/calendar"],
        ["https://www.googleapis.com/auth/calendar.readonly"],
        [],
        None,
    ],
    ids=["extra-write-scope", "extra-full-calendar", "substituted", "empty", "not-reported"],
)
@patch("gmail_local.auth.InstalledAppFlow")
def test_availability_login_discards_token_on_scope_mismatch(mock_flow_cls, granted_scopes, tmp_path: Path):
    from gmail_local.auth import ScopeMismatchError

    keyring_mock = FakeKeyring()
    manager = _availability_manager(tmp_path, keyring_mock)
    _mock_flow(mock_flow_cls, granted_scopes)

    with pytest.raises(ScopeMismatchError) as excinfo:
        manager.run_interactive_login(open_browser=False)

    assert keyring_mock.store == {}
    assert "avail-refresh-token" not in str(excinfo.value)
    assert "gmail-local-availability" in str(excinfo.value)


@patch("gmail_local.auth.InstalledAppFlow")
def test_availability_login_converts_oauthlib_scope_change_warning(mock_flow_cls, tmp_path: Path, monkeypatch):
    from oauthlib.oauth2.rfc6749.parameters import parse_token_response

    from gmail_local.auth import ScopeMismatchError

    keyring_mock = FakeKeyring()
    manager = _availability_manager(tmp_path, keyring_mock)

    # Produce the bare Warning the installed oauthlib raises when the token response scope differs.
    monkeypatch.delenv("OAUTHLIB_RELAX_TOKEN_SCOPE", raising=False)
    token_response = json.dumps({
        "access_token": "leaked-access-token",
        "refresh_token": "leaked-refresh-token",
        "token_type": "Bearer",
        "scope": f"{AVAILABILITY} https://www.googleapis.com/auth/calendar.events.owned",
    })
    with pytest.raises(Warning) as raised:
        parse_token_response(token_response, scope=[AVAILABILITY])
    mock_flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = raised.value

    with pytest.raises(ScopeMismatchError) as excinfo:
        manager.run_interactive_login(open_browser=False)

    assert keyring_mock.store == {}
    assert "Extra:     https://www.googleapis.com/auth/calendar.events.owned" in str(excinfo.value)
    assert "leaked" not in str(excinfo.value)
    assert excinfo.value.__cause__ is None
    assert excinfo.value.__suppress_context__ is True


@patch("gmail_local.auth.InstalledAppFlow")
def test_availability_login_reraises_unrelated_warning(mock_flow_cls, tmp_path: Path):
    keyring_mock = FakeKeyring()
    manager = _availability_manager(tmp_path, keyring_mock)
    mock_flow_cls.from_client_secrets_file.return_value.run_local_server.side_effect = Warning("unrelated")

    with pytest.raises(Warning, match="unrelated"):
        manager.run_interactive_login(open_browser=False)
    assert keyring_mock.store == {}


@patch("gmail_local.auth.InstalledAppFlow")
def test_existing_grant_login_behavior_unchanged_by_scope_check(mock_flow_cls, tmp_path: Path):
    keyring_mock = FakeKeyring()
    secret_file = tmp_path / "client_secret_calendar.json"
    secret_file.write_text(json.dumps({"installed": {"client_id": "cal-c1", "token_uri": "uri"}}))
    manager = AuthManager.for_calendar(
        client_secret_path=secret_file, account="test@example.com", keyring_backend=keyring_mock
    )
    _mock_flow(mock_flow_cls, None, refresh_token="cal-refresh-token")

    manager.run_interactive_login(open_browser=False)
    assert keyring_mock.store == {("gmail-local-calendar", "test@example.com"): "cal-refresh-token"}


def test_availability_missing_token_suggests_availability_login(tmp_path: Path):
    manager = _availability_manager(tmp_path, FakeKeyring())
    with pytest.raises(MissingTokenError, match="gmail-local availability-login"):
        manager.get_credentials()


