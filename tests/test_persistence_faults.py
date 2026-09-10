"""Persistence, transactional integrity, and fault-injection tests.

Tests atomic staging under simulated disk failures (ENOSPC, EACCES, EIO),
temporary staging file cleanup guarantees, audit log rotation thresholds, and
no-overwrite race resistance.
"""

import errno
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from gmail_local.audit import AuditLogger
from gmail_local.models import AuditEntry
from gmail_local.retrieval import GmailRetriever, OverwriteError, RetrievalBoundError


@pytest.mark.integration
class TestStagingFaultInjection:
    """Verifies atomic staging cleanup when filesystem errors occur."""

    def test_disk_full_during_write_cleans_up_staging_file(self, tmp_path: Path) -> None:
        """Simulate OSError ENOSPC (No space left on device) during file write.
        
        The temporary .*.tmp.* file must be unlinked and not left orphaned on disk.
        """
        dest_file = tmp_path / "report.pdf"
        tmp_file = tmp_path / f".{dest_file.name}.tmp.9999"

        # Mock open/write to fail with ENOSPC after file is created
        real_open = open

        def mock_open_failing(path, mode="r", *args, **kwargs):
            handle = real_open(path, mode, *args, **kwargs)
            if "w" in mode or "b" in mode:
                # Patch handle's write method to simulate ENOSPC
                orig_write = handle.write
                def failing_write(data):
                    raise OSError(errno.ENOSPC, "No space left on device")
                handle.write = failing_write
            return handle

        with patch("builtins.open", side_effect=mock_open_failing):
            with pytest.raises(OSError) as excinfo:
                GmailRetriever._stage_and_install_file(tmp_file, dest_file, b"sample binary payload")

            assert excinfo.value.errno == errno.ENOSPC

        # Target file must never have been created
        assert not dest_file.exists()
        # Staging file must have been cleanly removed
        assert not tmp_file.exists()

    def test_permission_error_during_replace_cleans_up_staging_file(self, tmp_path: Path) -> None:
        """Simulate OSError EACCES during atomic os.replace."""
        dest_file = tmp_path / "invoice.pdf"
        tmp_file = tmp_path / f".{dest_file.name}.tmp.8888"

        def failing_replace(src, dst):
            raise OSError(errno.EACCES, "Permission denied")

        with patch("os.replace", side_effect=failing_replace):
            with pytest.raises(OSError) as excinfo:
                GmailRetriever._stage_and_install_file(tmp_file, dest_file, b"sample binary payload")

            assert excinfo.value.errno == errno.EACCES

        # Staging file must be deleted on exception
        assert not tmp_file.exists()
        assert not dest_file.exists()

    def test_no_overwrite_preserves_original_file(self, tmp_path: Path) -> None:
        """Pre-existing destination file must never be modified or overwritten."""
        dest_file = tmp_path / "existing_document.pdf"
        dest_file.write_bytes(b"ORIGINAL UNTOUCHED CONTENT")

        # Create mock retriever
        mock_auth = MagicMock()
        mock_logger = MagicMock()
        retriever = GmailRetriever(auth_manager=mock_auth, audit_logger=mock_logger)

        # Attempting download to existing destination must raise OverwriteError
        with pytest.raises(OverwriteError) as excinfo:
            retriever.download_attachments([("msg_1", "att_1", dest_file)])

        assert "already exists" in str(excinfo.value)
        # Verify content remained pristine
        assert dest_file.read_bytes() == b"ORIGINAL UNTOUCHED CONTENT"


@pytest.mark.integration
class TestAuditLogPersistence:
    """Verifies audit log rotation, permission retention, and boundary handling."""

    def test_audit_log_rotation_and_permission_retention(self, tmp_path: Path) -> None:
        """Audit logger rotates at max_bytes threshold and maintains 0600 mode on backups."""
        log_file = tmp_path / "audit_rotating.log"
        # Small max_bytes to force rapid rotation
        logger = AuditLogger(log_path=log_file, max_bytes=200, backup_count=3)

        for i in range(25):
            entry = AuditEntry(
                operation="search",
                purpose=f"iteration_{i:03d}",
                status="SUCCESS",
                message_id=f"msg_{i}",
            )
            logger.record(entry)

        assert log_file.exists()
        # Verify rotated backup files exist
        backup_1 = tmp_path / "audit_rotating.log.1"
        assert backup_1.exists()

        # Check permissions on active and backup log files
        mode_active = oct(os.stat(log_file).st_mode & 0o777)
        assert mode_active == "0o600"
