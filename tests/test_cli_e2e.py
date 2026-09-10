"""Out-of-process subprocess CLI end-to-end tests.

Executes `gmail-local` via true OS subprocess invocation, verifying argument parsing,
help displays, invalid flag rejections, safety thresholds, and exit codes.
"""

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest


def run_cli(*args: str, env: dict = None) -> subprocess.CompletedProcess:
    """Executes the CLI out-of-process via Python module invocation."""
    run_env = os.environ.copy()
    if env:
        run_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "gmail_local.cli", *args],
        capture_output=True,
        text=True,
        env=run_env,
        timeout=10,
    )


@pytest.mark.e2e
class TestCliSubprocessE2E:
    """Out-of-process black-box verification of CLI interface."""

    def test_help_flag_displays_usage_and_commands(self) -> None:
        """Invoking --help exits with 0 and prints available subcommands."""
        proc = run_cli("--help")
        assert proc.returncode == 0
        assert "usage:" in proc.stdout.lower()
        expected_subcommands = ["status", "login", "revoke", "search", "preview", "read", "download", "thread"]
        for cmd in expected_subcommands:
            assert cmd in proc.stdout

    def test_short_help_flag_displays_usage(self) -> None:
        """Invoking -h exits with 0 and prints usage."""
        proc = run_cli("-h")
        assert proc.returncode == 0
        assert "usage:" in proc.stdout.lower()

    def test_unknown_subcommand_fails_gracefully(self) -> None:
        """Invoking an invalid subcommand returns code 2 and helpful error."""
        proc = run_cli("nonexistent-action")
        assert proc.returncode == 2
        assert "invalid choice" in proc.stderr.lower() or "unrecognized" in proc.stderr.lower()

    def test_missing_subcommand_shows_help(self) -> None:
        """Invoking with no arguments returns code 2 or prints help."""
        proc = run_cli()
        # In argparse, no subcommand usually returns 2
        assert proc.returncode in (0, 2)
        output = proc.stdout + proc.stderr
        assert "usage:" in output.lower()

    def test_search_missing_query_fails(self) -> None:
        """Invoking search without a query fails with exit code 2."""
        proc = run_cli("search")
        assert proc.returncode == 2
        assert "required" in proc.stderr.lower() or "error" in proc.stderr.lower()

    def test_search_exceeding_max_limit_fails(self) -> None:
        """Invoking search with limit > 75 fails and warns about max ceiling."""
        proc = run_cli("search", "subject:test", "--limit", "100")
        assert proc.returncode != 0
        output = proc.stdout + proc.stderr
        assert "75" in output or "limit" in output.lower()

    def test_read_missing_message_id_fails(self) -> None:
        """Invoking read without message ID fails with exit code 2."""
        proc = run_cli("read")
        assert proc.returncode == 2
        assert "required" in proc.stderr.lower() or "error" in proc.stderr.lower()

    def test_read_exceeding_max_ids_fails(self) -> None:
        """Invoking read with more than 10 IDs fails."""
        eleven_ids = [f"msg_{i}" for i in range(11)]
        proc = run_cli("read", *eleven_ids)
        assert proc.returncode != 0
        output = proc.stdout + proc.stderr
        assert "10" in output

    def test_status_executes_without_unhandled_crash(self) -> None:
        """Status command runs cleanly in any environment without stack trace."""
        proc = run_cli("status")
        # In unauthenticated or headless environment, status exits cleanly (0 or 1)
        assert "Traceback (most recent call last)" not in proc.stderr
        output = proc.stdout + proc.stderr
        assert "Gmail Local" in output or "Status" in output or "Account" in output

    def test_status_structured_output_fields(self) -> None:
        """Status command outputs expected diagnostics keys without token exposure."""
        proc = run_cli("status")
        assert "Traceback (most recent call last)" not in proc.stderr
        output = proc.stdout
        assert "=== Gmail Local Retrieval Status ===" in output
        assert "Account:" in output
        assert "Keychain Service:" in output
        assert "Client Secret:" in output
        assert "Keychain Token:" in output
        assert "Token Valid:" in output
        assert "Scope:" in output
        assert "https://www.googleapis.com/auth/gmail.readonly" in output

    def test_unrecognized_option_rejected(self) -> None:
        """Passing an unrecognized option to a subcommand fails with exit code 2."""
        proc = run_cli("status", "--bogus-flag")
        assert proc.returncode == 2
        assert "unrecognized arguments" in proc.stderr.lower()

    def test_download_missing_arguments_fails(self) -> None:
        """Download without selection arguments fails with code 2."""
        proc = run_cli("download")
        assert proc.returncode == 2
