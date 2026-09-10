"""Tests for AuditLogger."""

import os
from pathlib import Path

from gmail_local.audit import AuditLogger
from gmail_local.models import AuditEntry


def test_audit_logger_creates_file_and_permissions(tmp_path: Path):
    log_file = tmp_path / "test_audit.log"
    logger = AuditLogger(log_path=log_file)

    entry = AuditEntry(
        operation="search",
        purpose="unit_test",
        status="SUCCESS",
        message_id="msg_1",
    )
    logger.record(entry)

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "op=search" in content
    assert "mid=msg_1" in content

    # Verify 0600 file permissions on POSIX
    mode = oct(os.stat(log_file).st_mode & 0o777)
    assert mode == "0o600"
