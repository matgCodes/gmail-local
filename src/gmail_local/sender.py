"""Guarded outbound email sender implementing Manual Send Gate and rate-limited transmission."""

import base64
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

from googleapiclient.discovery import build

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.composer import build_mime_message
from gmail_local.models import (
    AuditEntry,
    FrozenDraft,
    FrozenDraftValidationError,
)
from gmail_local.rate_limiter import RateLimiter


class GmailSender:
    """Outbound transmission agent with tamper-verification and rate-limited execution."""

    def __init__(
        self,
        auth: Optional[AuthManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_logger: Optional[AuditLogger] = None,
        service: Optional[Any] = None,
    ):
        self.auth = auth or AuthManager.for_transmission()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_logger = audit_logger or AuditLogger()
        self.service = service

    def _get_service(self):
        if self.service is None:
            creds = self.auth.get_credentials()
            self.service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return self.service

    def send(self, draft: FrozenDraft, purpose: str = "send_message") -> Dict[str, Any]:
        """Transmits a FrozenDraft via users.drafts.send or users.messages.send after tamper checks."""
        # 1. Structural validation
        draft.validate()

        # 2. TOCTOU & Tamper defense: verify all attachments on disk match digests
        for att in draft.attachments:
            p = Path(att.file_path)
            if not p.exists() or not p.is_file():
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' failed integrity check: file missing at '{att.file_path}'."
                )
            current_bytes = p.read_bytes()
            current_digest = hashlib.sha256(current_bytes).hexdigest()
            if current_digest != att.sha256:
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' failed integrity check: content modified since draft freezing."
                )

        service = self._get_service()
        fp = draft.compute_fingerprint()

        # 3. Transmit via Gmail API
        if draft.draft_id:
            # Send staged draft (cost 100 units)
            def _send_call():
                return service.users().drafts().send(
                    userId="me",
                    body={"id": draft.draft_id},
                ).execute()

            resp = self.rate_limiter.execute_with_retry("users.drafts.send", _send_call)
        else:
            # Send unstaged raw MIME message (cost 100 units)
            mime_msg = build_mime_message(draft)
            raw_bytes = mime_msg.as_bytes()
            b64_raw = base64.urlsafe_b64encode(raw_bytes).decode("utf-8")

            def _send_call():
                return service.users().messages().send(
                    userId="me",
                    body={"raw": b64_raw},
                ).execute()

            resp = self.rate_limiter.execute_with_retry("users.messages.send", _send_call)

        # 4. Structured audit logging
        msg_id = resp.get("id")
        thread_id = resp.get("threadId")
        total_recipients = len(draft.to) + len(draft.cc) + len(draft.bcc)

        self.audit_logger.log_entry(
            AuditEntry(
                operation="send_message",
                purpose=purpose,
                status="SUCCESS",
                draft_id=draft.draft_id,
                message_id=msg_id,
                fingerprint=fp,
                details=f"recipients={total_recipients}",
            )
        )

        return {
            "id": msg_id,
            "threadId": thread_id,
            "draft_id": draft.draft_id,
            "fingerprint": fp,
            "raw_response": resp,
        }
