"""Configuration constants and security boundaries for Gmail Local Integration."""

import os
from pathlib import Path

# Scopes: Strict least-privilege retrieval only
RETRIEVAL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"

# Standard Local Paths
CONFIG_DIR = Path.home() / ".config" / "gmail-local"
CLIENT_SECRET_FILE = CONFIG_DIR / "client_secret.json"


def _resolve_default_account() -> str:
    """Resolves active Gmail account from environment or local config, avoiding committed PII."""
    if "GMAIL_ACCOUNT" in os.environ:
        return os.environ["GMAIL_ACCOUNT"]
    account_file = CONFIG_DIR / "account.txt"
    if account_file.exists():
        try:
            val = account_file.read_text(encoding="utf-8").strip()
            if val:
                return val
        except OSError:
            pass
    return "user@example.com"


# Keychain Identifiers
KEYCHAIN_SERVICE = "gmail-local-retrieval"
DEFAULT_ACCOUNT = _resolve_default_account()

STATE_DIR = Path.home() / ".local" / "state" / "gmail-local"
AUDIT_LOG_FILE = STATE_DIR / "audit.log"
DEFAULT_DOWNLOAD_DIR = Path.home() / "Downloads"

# Privacy & Content Disclosure Bounds (ADRs 0006, 0007, 0008)
DEFAULT_SEARCH_BOUND = 10
MAX_SEARCH_BOUND = 75
MAX_READ_MESSAGES = 10
MAX_DECODED_BODY_BYTES = 1_048_576  # 1 MiB

MAX_ATTACHMENT_BYTES_PER_FILE = 26_214_400  # 25 MiB
MAX_ATTACHMENT_BYTES_AGGREGATE = 52_428_800  # 50 MiB

# Audit Log Rotation Bounds (ADR 0008)
MAX_AUDIT_LOG_BYTES = 5_242_880  # 5 MiB
AUDIT_LOG_BACKUP_COUNT = 3

# Rate Limiting & Throttling (ADR 0007)
RATE_LIMIT_WINDOW_SECS = 60
RATE_LIMIT_MAX_UNITS = 3000  # 50% of Google's 6,000/min per-user limit
MAX_CONCURRENT_REQUESTS = 4
MAX_RETRIES = 4  # 1 initial + 4 retries = 5 attempts
MAX_RETRY_DEADLINE_SECS = 60
INITIAL_BACKOFF_SCHEDULE = [1.0, 2.0, 4.0, 8.0]

# Google Method Quota Costs (Google Reference)
METHOD_QUOTA_COSTS = {
    "users.messages.list": 5,
    "users.messages.get": 20,
    "users.messages.attachments.get": 20,
    "users.history.list": 2,
    "users.threads.get": 10,
    "users.threads.list": 10,
    "users.labels.list": 1,
    "users.labels.get": 1,
}
