"""OAuth2 installed-application authorization and secure macOS Keychain storage."""

import json
from pathlib import Path
from typing import Any, Dict, Optional

import keyring
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

from gmail_local.config import (
    CLIENT_SECRET_FILE,
    DEFAULT_ACCOUNT,
    KEYCHAIN_SERVICE,
    RETRIEVAL_SCOPE,
)


class AuthError(Exception):
    """Base error for authentication failures."""


class MissingClientSecretError(AuthError):
    """Raised when client_secret.json does not exist."""


class MissingTokenError(AuthError):
    """Raised when no refresh token exists in the Keychain."""


class TokenRevocationError(AuthError):
    """Raised when revoking the token fails."""


class AuthManager:
    """Manages Desktop OAuth authorization flow and Keychain credential storage."""

    def __init__(
        self,
        client_secret_path: Path = CLIENT_SECRET_FILE,
        keychain_service: str = KEYCHAIN_SERVICE,
        account: str = DEFAULT_ACCOUNT,
        keyring_backend: Any = keyring,
    ):
        self.client_secret_path = client_secret_path
        self.keychain_service = keychain_service
        self.account = account
        self.keyring = keyring_backend

    def load_client_config(self) -> Dict[str, Any]:
        """Loads and verifies the Desktop App client JSON configuration."""
        if not self.client_secret_path.exists():
            raise MissingClientSecretError(
                f"OAuth client configuration not found at {self.client_secret_path}.\n"
                "Please download the Desktop App client JSON from Google Cloud Console."
            )
        with open(self.client_secret_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Confirm Desktop App format (installed)
        if "installed" not in data:
            raise AuthError(
                "Client configuration is not a 'Desktop app' (missing 'installed' block). "
                "Ensure you created an OAuth client of type 'Desktop app'."
            )
        return data

    def run_interactive_login(self, open_browser: bool = True) -> str:
        """Executes the loopback InstalledAppFlow with PKCE in the system browser.

        Stores the obtained refresh token in macOS Keychain and returns account.
        """
        self.load_client_config()

        flow = InstalledAppFlow.from_client_secrets_file(
            str(self.client_secret_path),
            scopes=[RETRIEVAL_SCOPE],
            autogenerate_code_verifier=True,  # Enforces PKCE S256
        )

        creds = flow.run_local_server(
            port=0,
            open_browser=open_browser,
            prompt="consent",
            access_type="offline",
        )

        if not creds.refresh_token:
            raise AuthError(
                "No refresh token was returned by Google. Ensure 'prompt=consent' and "
                "'access_type=offline' were granted."
            )

        # Store refresh token securely in OS Keychain
        self.keyring.set_password(
            self.keychain_service,
            self.account,
            creds.refresh_token,
        )
        return self.account

    def get_credentials(self) -> Credentials:
        """Retrieves refresh token from Keychain and refreshes access token if needed."""
        refresh_token = self.keyring.get_password(self.keychain_service, self.account)
        if not refresh_token:
            raise MissingTokenError(
                f"No refresh token found in Keychain for service '{self.keychain_service}', "
                f"account '{self.account}'. Run 'gmail-local login' to authorize."
            )

        client_config = self.load_client_config()["installed"]
        creds = Credentials(
            token=None,
            refresh_token=refresh_token,
            token_uri=client_config["token_uri"],
            client_id=client_config["client_id"],
            client_secret=client_config.get("client_secret"),
            scopes=[RETRIEVAL_SCOPE],
        )

        # Refresh access token
        creds.refresh(Request())
        return creds

    def get_status(self) -> Dict[str, Any]:
        """Inspects connection and authorization status without exposing secrets."""
        has_secret = self.client_secret_path.exists()
        refresh_token = self.keyring.get_password(self.keychain_service, self.account)
        has_token = refresh_token is not None

        is_valid = False
        if has_secret and has_token:
            try:
                creds = self.get_credentials()
                is_valid = creds.valid
            except Exception:
                is_valid = False

        return {
            "account": self.account,
            "keychain_service": self.keychain_service,
            "has_client_secret": has_secret,
            "has_keychain_token": has_token,
            "is_valid": is_valid,
            "scope": RETRIEVAL_SCOPE,
        }

    def revoke(self) -> bool:
        """Revokes token authorization with Google and deletes Keychain entry."""
        import requests

        refresh_token = self.keyring.get_password(self.keychain_service, self.account)
        revoked_remotely = False
        if refresh_token:
            resp = requests.post(
                "https://oauth2.googleapis.com/revoke",
                params={"token": refresh_token},
                headers={"content-type": "application/x-www-form-urlencoded"},
                timeout=10,
            )
            revoked_remotely = resp.status_code == 200

        try:
            self.keyring.delete_password(self.keychain_service, self.account)
        except keyring.errors.PasswordDeleteError:
            pass

        return True
