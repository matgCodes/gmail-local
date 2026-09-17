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


