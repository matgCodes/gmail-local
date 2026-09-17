"""Draft composition, MIME packaging, and Gmail API payload serialization."""

import base64
from dataclasses import replace
from email.message import EmailMessage
import hashlib
import json
import mimetypes
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.config import DRAFTS_DIR
from gmail_local.models import (
    AttachmentMode,
    AuditEntry,
    FrozenAttachment,
    FrozenDraft,
    FrozenDraftValidationError,
)
from gmail_local.rate_limiter import RateLimiter


def create_frozen_draft(
    to: List[str],
    subject: str,
    body_text: str,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    body_html: Optional[str] = None,
    thread_id: Optional[str] = None,
    in_reply_to: Optional[str] = None,
    references: Optional[List[str]] = None,
    attachment_paths: Optional[List[Union[Path, str]]] = None,
    attachment_mode: Union[AttachmentMode, str] = AttachmentMode.AUTO,
    attachment_modes: Optional[Dict[str, Union[AttachmentMode, str]]] = None,
) -> FrozenDraft:
    """Constructs, inspects local attachments for, and validates an immutable FrozenDraft."""
    import re
    attachments: List[FrozenAttachment] = []

    if attachment_paths:
        for p_raw in attachment_paths:
            p_str = str(p_raw)
            if "\x00" in p_str:
                raise FrozenDraftValidationError(f"Invalid attachment file path: {repr(p_str)}")
            try:
                p = Path(p_raw).expanduser().resolve()
            except (ValueError, OSError) as e:
                raise FrozenDraftValidationError(f"Invalid attachment file path: {repr(p_str)}") from e

            if not p.exists() or not p.is_file():
                raise FrozenDraftValidationError(f"Attachment file not found: {p_raw}")

            file_bytes = p.read_bytes()
            size = len(file_bytes)
            digest = hashlib.sha256(file_bytes).hexdigest()

            # Resolve effective mode for this attachment
            effective_mode_raw = attachment_mode
            if attachment_modes:
                if p.name in attachment_modes:
                    effective_mode_raw = attachment_modes[p.name]
                elif str(p) in attachment_modes:
                    effective_mode_raw = attachment_modes[str(p)]

            if isinstance(effective_mode_raw, str):
                try:
                    effective_mode = AttachmentMode(effective_mode_raw.lower())
                except ValueError:
                    raise FrozenDraftValidationError(f"Unknown attachment mode: '{effective_mode_raw}'")
            else:
                effective_mode = effective_mode_raw

            if effective_mode == AttachmentMode.COMPATIBILITY:
                mime_type = "application/octet-stream"
            elif effective_mode == AttachmentMode.INVITATION:
                content_str = file_bytes.decode("utf-8", errors="replace")
                method_match = re.search(r"(?m)^METHOD:([A-Za-z0-9_-]+)", content_str, re.IGNORECASE)
                if not method_match:
                    raise FrozenDraftValidationError(
                        f"Calendar invitation mode for '{p.name}' requires matching VCALENDAR METHOD property (e.g. METHOD:REQUEST)."
                    )
                inv_method = method_match.group(1).upper()
                mime_type = f"text/calendar; charset=UTF-8; method={inv_method}"
            elif effective_mode == AttachmentMode.SNAPSHOT or (
                effective_mode == AttachmentMode.AUTO
                and (p.suffix.lower() == ".ics" or mimetypes.guess_type(str(p))[0] == "text/calendar")
            ):
                mime_type = "text/calendar; charset=UTF-8"
            else:
                guessed, _ = mimetypes.guess_type(str(p))
                mime_type = guessed or "application/octet-stream"

            attachments.append(
                FrozenAttachment(
                    filename=p.name,
                    mime_type=mime_type,
                    file_path=str(p),
                    size_bytes=size,
                    sha256=digest,
                )
            )

    draft = FrozenDraft(
        to=list(to),
        subject=subject,
        body_text=body_text,
        cc=list(cc) if cc else [],
        bcc=list(bcc) if bcc else [],
        body_html=body_html,
        thread_id=thread_id,
        in_reply_to=in_reply_to,
        references=list(references) if references else [],
        attachments=attachments,
    )

    draft.validate()
    return draft


def build_mime_message(draft: FrozenDraft) -> EmailMessage:
    """Constructs a standard RFC 5322 EmailMessage from a FrozenDraft."""
    msg = EmailMessage()

    # Core message content
    msg.set_content(draft.body_text)

    # Optional HTML alternative
    if draft.body_html:
        msg.add_alternative(draft.body_html, subtype="html")

    # Attachments
    for att in draft.attachments:
        data = Path(att.file_path).read_bytes()
        temp_msg = EmailMessage()
        temp_msg["Content-Type"] = att.mime_type
        maintype = temp_msg.get_content_maintype()
        subtype = temp_msg.get_content_subtype()
        raw_params = temp_msg.get_params()[1:] if temp_msg.get_params() else []
        params = dict(raw_params) if raw_params else None

        msg.add_attachment(
            data,
            maintype=maintype,
            subtype=subtype,
            filename=att.filename,
            params=params,
        )

    # RFC 5322 Headers
    msg["To"] = ", ".join(draft.to)
    if draft.cc:
        msg["Cc"] = ", ".join(draft.cc)
    if draft.bcc:
        msg["Bcc"] = ", ".join(draft.bcc)
    msg["Subject"] = draft.subject

    if draft.in_reply_to:
        msg["In-Reply-To"] = draft.in_reply_to
    if draft.references:
        msg["References"] = " ".join(draft.references)

    return msg


def build_draft_payload(draft: FrozenDraft) -> Dict[str, Any]:
    """Serializes a FrozenDraft into a base64url-encoded Gmail API Draft resource dictionary."""
    mime_msg = build_mime_message(draft)
    raw_bytes = mime_msg.as_bytes()
    raw_base64url = base64.urlsafe_b64encode(raw_bytes).decode("utf-8")
    message_payload = {"raw": raw_base64url}
    if draft.thread_id:
        message_payload["threadId"] = draft.thread_id
    return {"message": message_payload}


class GmailDraftManager:
    """Manages composing, staging, and inspecting Gmail drafts under Transmission Grant bounds."""

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
        self._service = service

    def _get_service(self) -> Any:
        if self._service is None:
            from googleapiclient.discovery import build

            creds = self.auth.get_credentials()
            self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return self._service

    def save_draft(self, draft: FrozenDraft, purpose: str = "create_draft") -> FrozenDraft:
        """Uploads a FrozenDraft to the user's Gmail Drafts folder (users.drafts.create)."""
        draft.validate()
        payload = build_draft_payload(draft)
        service = self._get_service()

        def _create_call():
            return service.users().drafts().create(userId="me", body=payload).execute()

        resp = self.rate_limiter.execute_with_retry("users.drafts.create", _create_call)
        draft_id = resp.get("id")

        updated_draft = replace(draft, draft_id=draft_id)

        self.audit_logger.record(
            AuditEntry(
                operation="draft_create",
                purpose=purpose,
                status="SUCCESS",
                draft_id=draft_id,
                fingerprint=draft.compute_fingerprint(),
                details=f"recipients={len(draft.to)+len(draft.cc)+len(draft.bcc)}",
            )
        )
        return updated_draft

    def list_drafts(self, max_results: int = 10, purpose: str = "list_drafts") -> List[Dict[str, Any]]:
        """Lists drafts in the Gmail mailbox (users.drafts.list)."""
        if max_results < 1 or max_results > 75:
            raise ValueError("max_results must be between 1 and 75.")
        service = self._get_service()

        def _list_call():
            return service.users().drafts().list(userId="me", maxResults=max_results).execute()

        resp = self.rate_limiter.execute_with_retry("users.drafts.list", _list_call)
        return resp.get("drafts", [])

    def get_draft(self, draft_id: str, purpose: str = "get_draft") -> Dict[str, Any]:
        """Retrieves draft metadata from Gmail (users.drafts.get)."""
        service = self._get_service()

        def _get_call():
            return service.users().drafts().get(userId="me", id=draft_id, format="full").execute()

        return self.rate_limiter.execute_with_retry("users.drafts.get", _get_call)


def save_draft_locally(draft: FrozenDraft, drafts_dir: Optional[Path] = None) -> Path:
    """Persists a FrozenDraft to the local state directory named by its SHA-256 fingerprint."""
    target_dir = drafts_dir or DRAFTS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    fp = draft.compute_fingerprint()
    file_path = target_dir / f"{fp}.json"
    data = draft.to_dict()
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return file_path


def load_draft_locally(identifier: str, drafts_dir: Optional[Path] = None) -> FrozenDraft:
    """Loads a FrozenDraft by file path, full fingerprint, fingerprint prefix, or draft ID."""
    target_dir = drafts_dir or DRAFTS_DIR

    # 1. Check exact path on disk
    p = Path(identifier).expanduser()
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return FrozenDraft.from_dict(data)
        except Exception as e:
            raise FrozenDraftValidationError(f"Invalid draft file format: {e}") from e

    # 2. Check within target_dir
    if target_dir.exists():
        direct_file = target_dir / f"{identifier}.json"
        if direct_file.is_file():
            data = json.loads(direct_file.read_text(encoding="utf-8"))
            return FrozenDraft.from_dict(data)

        # Search for prefix match or draft_id match
        for candidate in target_dir.glob("*.json"):
            if candidate.stem.startswith(identifier):
                data = json.loads(candidate.read_text(encoding="utf-8"))
                return FrozenDraft.from_dict(data)
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if data.get("draft_id") == identifier:
                    return FrozenDraft.from_dict(data)
            except Exception:
                continue

    raise FileNotFoundError(f"No local draft found matching '{identifier}'")
