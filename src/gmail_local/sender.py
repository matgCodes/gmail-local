"""Guarded outbound email sender implementing Manual Send Gate and rate-limited transmission."""

import base64
from email import message_from_bytes
from email.message import EmailMessage
from email.policy import default
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional

from googleapiclient.discovery import build

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.composer import build_mime_message
from gmail_local.mime_utils import decode_rfc2047_header, sanitize_filename
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

    def verify_remote_draft(self, draft: FrozenDraft, purpose: str = "verify_remote_draft") -> Dict[str, Any]:
        """Reads back a staged draft from Gmail as raw MIME and verifies semantic headers and attachments."""
        if not draft.draft_id:
            raise FrozenDraftValidationError("Cannot verify remote draft: draft has no draft_id.")

        service = self._get_service()

        def _get_draft_call():
            return service.users().drafts().get(
                userId="me",
                id=draft.draft_id,
                format="raw",
            ).execute()

        resp = self.rate_limiter.execute_with_retry("users.drafts.get", _get_draft_call)
        raw_b64 = resp.get("message", {}).get("raw", "")
        if not raw_b64:
            raise FrozenDraftValidationError(
                f"Remote draft '{draft.draft_id}' returned no raw RFC message data."
            )

        pad_len = (4 - len(raw_b64) % 4) % 4
        raw_bytes = base64.urlsafe_b64decode(raw_b64 + ("=" * pad_len))
        parsed_msg = message_from_bytes(raw_bytes, policy=default)

        # 1. Verify semantic headers
        remote_subject = decode_rfc2047_header(parsed_msg.get("Subject", "")).strip()
        if remote_subject != draft.subject.strip():
            raise FrozenDraftValidationError(
                f"Remote draft subject mismatch: expected '{draft.subject.strip()}', got '{remote_subject}'."
            )

        to_header = parsed_msg.get("To", "")
        remote_to = [addr.strip().lower() for addr in to_header.split(",") if addr.strip()] if to_header else []
        expected_to = [addr.strip().lower() for addr in draft.to]
        if sorted(remote_to) != sorted(expected_to):
            raise FrozenDraftValidationError(
                f"Remote draft recipient (To) mismatch: expected {expected_to}, got {remote_to}."
            )

        # 2. Walk entire MIME tree to extract attachments
        remote_attachments: List[Dict[str, Any]] = []
        for part in parsed_msg.walk():
            if part.is_multipart():
                continue
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = part.get_content_type()
            if disposition == "attachment" or filename is not None:
                payload = part.get_payload(decode=True)
                if payload is None:
                    raw_content = part.get_content()
                    payload = raw_content.encode("utf-8") if isinstance(raw_content, str) else bytes(raw_content or b"")
                clean_filename = sanitize_filename(filename) if filename else "attachment.bin"
                digest = hashlib.sha256(payload).hexdigest()
                params = dict(part.get_params()[1:]) if part.get_params() else {}
                remote_attachments.append({
                    "filename": clean_filename,
                    "raw_filename": filename,
                    "mime_type": content_type,
                    "params": params,
                    "size_bytes": len(payload),
                    "sha256": digest,
                })

        # 3. Compare attachments against FrozenDraft attachments
        if len(remote_attachments) != len(draft.attachments):
            raise FrozenDraftValidationError(
                f"Remote draft attachment count ({len(remote_attachments)}) does not match "
                f"approved frozen draft count ({len(draft.attachments)})."
            )

        for att in draft.attachments:
            matched = [ra for ra in remote_attachments if ra["filename"] == att.filename or ra.get("raw_filename") == att.filename]
            if not matched:
                raise FrozenDraftValidationError(
                    f"Approved attachment '{att.filename}' missing in remote draft readback."
                )
            remote_att = matched[0]

            expected_temp = EmailMessage()
            expected_temp["Content-Type"] = att.mime_type
            expected_base = f"{expected_temp.get_content_maintype()}/{expected_temp.get_content_subtype()}".lower()
            expected_params = {k.lower(): v for k, v in (expected_temp.get_params()[1:] if expected_temp.get_params() else [])}

            remote_base = remote_att["mime_type"].lower()
            remote_params = {k.lower(): v for k, v in remote_att.get("params", {}).items()}

            if expected_base != remote_base:
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' MIME type mismatch in remote draft: "
                    f"expected '{expected_base}', got '{remote_base}'."
                )

            if "charset" in expected_params:
                if remote_params.get("charset", "").lower() != expected_params["charset"].lower():
                    raise FrozenDraftValidationError(
                        f"Attachment '{att.filename}' charset mismatch in remote draft: "
                        f"expected '{expected_params['charset']}', got '{remote_params.get('charset')}'."
                    )
            if "method" in expected_params:
                if remote_params.get("method", "").upper() != expected_params["method"].upper():
                    raise FrozenDraftValidationError(
                        f"Attachment '{att.filename}' method mismatch in remote draft: "
                        f"expected '{expected_params['method']}', got '{remote_params.get('method')}'."
                    )

            if remote_att["size_bytes"] != att.size_bytes:
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' size mismatch in remote draft: "
                    f"expected {att.size_bytes} bytes, got {remote_att['size_bytes']} bytes."
                )

            if remote_att["sha256"] != att.sha256:
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' SHA-256 digest mismatch: remote draft content differs from frozen draft."
                )

        self.audit_logger.log_entry(
            AuditEntry(
                operation="verify_remote_draft",
                purpose=purpose,
                status="SUCCESS",
                draft_id=draft.draft_id,
                fingerprint=draft.compute_fingerprint(),
                details=f"attachments={len(draft.attachments)}",
            )
        )

        return {
            "verified": True,
            "draft_id": draft.draft_id,
            "fingerprint": draft.compute_fingerprint(),
            "attachment_count": len(remote_attachments),
        }

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

        remote_verified = False
        # 3. If draft is staged, verify remote draft raw MIME before sending
        if draft.draft_id:
            self.verify_remote_draft(draft, purpose=f"{purpose}_remote_verify")
            remote_verified = True

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
            "local_attachment_verified": True,
            "remote_draft_verified": remote_verified,
            "gmail_send_accepted": True,
            "stored_sent_raw_verified": False,
            "recipient_ui_verified": False,
            "raw_response": resp,
        }
