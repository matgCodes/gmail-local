"""Minimal, append-only, rotating local audit logger."""

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from gmail_local.config import (
    AUDIT_LOG_BACKUP_COUNT,
    AUDIT_LOG_FILE,
    MAX_AUDIT_LOG_BYTES,
)
from gmail_local.models import AuditEntry


class AuditLogger:
    """Manages the local audit log with strict permission isolation and rotation."""

    def __init__(
        self,
        log_path: Optional[Path] = None,
        max_bytes: int = MAX_AUDIT_LOG_BYTES,
        backup_count: int = AUDIT_LOG_BACKUP_COUNT,
    ):
        self.log_path = log_path or AUDIT_LOG_FILE
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        self._logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        # Ensure parent directory exists with 0700 permissions
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.log_path.parent, 0o700)
        except OSError:
            pass

        logger_name = f"gmail_local.audit.{id(self)}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # Clear existing handlers if re-instantiated
        for handler in list(logger.handlers):
            logger.removeHandler(handler)

        handler = RotatingFileHandler(
            filename=str(self.log_path),
            maxBytes=self.max_bytes,
            backupCount=self.backup_count,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)

        # Ensure file permissions are 0600 if file exists
        if self.log_path.exists():
            try:
                os.chmod(self.log_path, 0o600)
            except OSError:
                pass

        return logger

    def record(self, entry: AuditEntry) -> None:
        """Write a sanitized audit entry line to the audit log."""
        self._logger.info(entry.to_log_line())
        # Re-enforce 0600 permissions
        if self.log_path.exists():
            try:
                os.chmod(self.log_path, 0o600)
            except OSError:
                pass
