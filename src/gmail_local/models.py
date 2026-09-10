"""Domain models for bounded Gmail retrieval."""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class CandidateMessage:
    """Header-only bounded discovery result. Body is not retrieved."""
    id: str
    thread_id: str
    date: str
    sender: str
    recipient: str
    subject: str
    preview: Optional[str] = None  # Populated only if Message Preview explicitly requested


@dataclass(frozen=True)
class AttachmentDescriptor:
    """Metadata describing an attachment without downloading binary data."""
    message_id: str
    attachment_id: str
    filename: str
    mime_type: str
    size_bytes: int
    is_inline: bool = False


@dataclass(frozen=True)
class SelectedMessage:
    """A fully retrieved message governed by the Read Bound."""
    id: str
    thread_id: str
    date: str
    sender: str
    recipient: str
    subject: str
    body_text: str
    body_bytes: int
    attachments: List[AttachmentDescriptor] = field(default_factory=list)


@dataclass(frozen=True)
class AuditEntry:
    """Minimal audit log record. Never includes message bodies, headers, or tokens."""
    operation: str
    purpose: str
    status: str
    message_id: Optional[str] = None
    draft_id: Optional[str] = None
    fingerprint: Optional[str] = None
    filename: Optional[str] = None
    destination: Optional[str] = None
    details: Optional[str] = None
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_log_line(self) -> str:
        fields = [
            f"ts={self.timestamp}",
            f"op={self.operation}",
            f"purpose={self.purpose.replace(' ', '_')}",
            f"status={self.status}",
        ]
        if self.message_id:
            fields.append(f"mid={self.message_id}")
        if self.draft_id:
            fields.append(f"did={self.draft_id}")
        if self.fingerprint:
            fields.append(f"fp={self.fingerprint}")
        if self.filename:
            fields.append(f"file={self.filename}")
        if self.destination:
            fields.append(f"dest={self.destination}")
        if self.details:
            fields.append(f"details={self.details.replace(' ', '_')}")
        return " ".join(fields)


@dataclass(frozen=True)
class HistoryDelta:
    """Lightweight incremental synchronization record from users.history.list (2 quota units)."""
    history_id: str
    messages_added: List[str] = field(default_factory=list)
    messages_deleted: List[str] = field(default_factory=list)
    is_expired: bool = False  # True when historyId is too old (HTTP 404), requiring full sync


@dataclass(frozen=True)
class ThreadSummary:
    """Bounded conversation thread summary mapping constituent messages."""
    thread_id: str
    message_count: int
    subject: str
    participants: List[str] = field(default_factory=list)
    message_ids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class LabelInfo:
    """Metadata describing a Gmail label."""
    id: str
    name: str
    type: str  # 'system' or 'user'
    messages_total: Optional[int] = None
    messages_unread: Optional[int] = None


class FrozenDraftValidationError(ValueError):
    """Raised when a FrozenDraft violates security bounds or formatting constraints."""


@dataclass(frozen=True)
class FrozenAttachment:
    """Metadata and local digest for an outbound attachment."""
    filename: str
    mime_type: str
    file_path: str
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class FrozenDraft:
    """Immutable outbound message package bound to a deterministic cryptographic fingerprint."""
    to: List[str]
    subject: str
    body_text: str
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    body_html: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: List[str] = field(default_factory=list)
    attachments: List[FrozenAttachment] = field(default_factory=list)
    draft_id: Optional[str] = None  # Populated when saved to Gmail Drafts
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        """Validates safety bounds and CRLF header injection protections."""
        from gmail_local.config import (
            MAX_RECIPIENTS,
            MAX_TRANSMISSION_BODY_BYTES,
            MAX_TRANSMISSION_ATTACHMENT_BYTES_PER_FILE,
            MAX_TRANSMISSION_ATTACHMENT_BYTES_AGGREGATE,
        )

        # 1. Recipient presence and bounds
        total_recipients = len(self.to) + len(self.cc) + len(self.bcc)
        if total_recipients == 0:
            raise FrozenDraftValidationError("At least one recipient (to, cc, bcc) is required.")
        if total_recipients > MAX_RECIPIENTS:
            raise FrozenDraftValidationError(
                f"Total recipient count ({total_recipients}) exceeds maximum bound of {MAX_RECIPIENTS}."
            )

        # 2. Header injection (CRLF, null bytes, recipient delimiter evasion) prevention
        for field_name, addr_list in [("to", self.to), ("cc", self.cc), ("bcc", self.bcc)]:
            for addr in addr_list:
                if "\x00" in addr:
                    raise FrozenDraftValidationError(
                        f"Null byte detected in {field_name} address: {repr(addr)}"
                    )
                if "\r" in addr or "\n" in addr:
                    raise FrozenDraftValidationError(
                        f"CRLF characters detected in {field_name} address: {repr(addr)}"
                    )
                if "," in addr or ";" in addr:
                    raise FrozenDraftValidationError(
                        f"Delimiter character (',' or ';') detected in {field_name} address: {repr(addr)}"
                    )
                if not addr.strip():
                    raise FrozenDraftValidationError(f"Empty email address in {field_name}.")

        if "\x00" in self.subject:
            raise FrozenDraftValidationError("Null byte detected in subject.")
        if "\r" in self.subject or "\n" in self.subject:
            raise FrozenDraftValidationError("CRLF characters detected in subject.")
        if not self.subject.strip():
            raise FrozenDraftValidationError("Subject must not be empty.")

        # 3. Payload size bounds
        body_bytes = len(self.body_text.encode("utf-8"))
        if self.body_html:
            body_bytes += len(self.body_html.encode("utf-8"))
        if body_bytes > MAX_TRANSMISSION_BODY_BYTES:
            raise FrozenDraftValidationError(
                f"Aggregate message body ({body_bytes} bytes) exceeds maximum bound of {MAX_TRANSMISSION_BODY_BYTES} bytes."
            )

        # 4. Attachment bounds
        agg_att_bytes = 0
        for att in self.attachments:
            if "\x00" in att.filename:
                raise FrozenDraftValidationError(
                    f"Null byte detected in attachment filename: {repr(att.filename)}"
                )
            if "\r" in att.filename or "\n" in att.filename:
                raise FrozenDraftValidationError(
                    f"CRLF characters detected in attachment filename: {repr(att.filename)}"
                )
            if att.size_bytes > MAX_TRANSMISSION_ATTACHMENT_BYTES_PER_FILE:
                raise FrozenDraftValidationError(
                    f"Attachment '{att.filename}' size ({att.size_bytes} bytes) exceeds per-file bound of {MAX_TRANSMISSION_ATTACHMENT_BYTES_PER_FILE} bytes."
                )
            agg_att_bytes += att.size_bytes

        if agg_att_bytes > MAX_TRANSMISSION_ATTACHMENT_BYTES_AGGREGATE:
            raise FrozenDraftValidationError(
                f"Aggregate attachment size ({agg_att_bytes} bytes) exceeds aggregate bound of {MAX_TRANSMISSION_ATTACHMENT_BYTES_AGGREGATE} bytes."
            )

    def canonical_dict(self) -> Dict[str, Any]:
        """Returns ordered, normalized representation for deterministic hashing."""
        return {
            "to": sorted([addr.strip().lower() for addr in self.to]),
            "cc": sorted([addr.strip().lower() for addr in self.cc]),
            "bcc": sorted([addr.strip().lower() for addr in self.bcc]),
            "subject": self.subject.strip(),
            "body_text": self.body_text,
            "body_html": self.body_html,
            "in_reply_to": self.in_reply_to,
            "references": sorted(self.references),
            "attachments": [
                {
                    "filename": att.filename,
                    "mime_type": att.mime_type,
                    "size_bytes": att.size_bytes,
                    "sha256": att.sha256,
                }
                for att in sorted(self.attachments, key=lambda a: a.filename)
            ],
        }

    def compute_fingerprint(self) -> str:
        """Generates SHA-256 fingerprint of the canonical JSON representation."""
        serialized = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Returns standard dictionary representation for persistence and IPC."""
        return {
            "to": list(self.to),
            "subject": self.subject,
            "body_text": self.body_text,
            "cc": list(self.cc),
            "bcc": list(self.bcc),
            "body_html": self.body_html,
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
            "attachments": [
                {
                    "filename": a.filename,
                    "mime_type": a.mime_type,
                    "file_path": a.file_path,
                    "size_bytes": a.size_bytes,
                    "sha256": a.sha256,
                }
                for a in self.attachments
            ],
            "draft_id": self.draft_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FrozenDraft":
        """Reconstructs a FrozenDraft instance from a dictionary representation."""
        attachments = [
            FrozenAttachment(
                filename=a["filename"],
                mime_type=a["mime_type"],
                file_path=a.get("file_path", ""),
                size_bytes=a["size_bytes"],
                sha256=a["sha256"],
            )
            for a in data.get("attachments", [])
        ]
        return cls(
            to=list(data["to"]),
            subject=data["subject"],
            body_text=data["body_text"],
            cc=list(data.get("cc", [])),
            bcc=list(data.get("bcc", [])),
            body_html=data.get("body_html"),
            in_reply_to=data.get("in_reply_to"),
            references=list(data.get("references", [])),
            attachments=attachments,
            draft_id=data.get("draft_id"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )

