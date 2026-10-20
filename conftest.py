"""Keeps test runs hermetic: the Operator's real account (account.txt) never reaches test output."""

import os

os.environ["GMAIL_ACCOUNT"] = "user@example.com"
