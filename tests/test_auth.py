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

