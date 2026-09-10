"""Tests for AuthManager and Keychain interactions."""

import json
from pathlib import Path
from unittest.mock import MagicMock

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
