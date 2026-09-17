"""Domain models for bounded Gmail retrieval."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


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
    labels: Tuple[str, ...] = ()


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
class ReplyMetadata:
    """Header-only context required to bind a draft to an existing Gmail thread."""
    gmail_message_id: str
    thread_id: str
    rfc_message_id: str
    references: Tuple[str, ...]
    subject: str


@dataclass(frozen=True)
class AuditEntry:
    """Minimal audit log record. Never includes message bodies, headers, or tokens."""
    operation: str
    purpose: str
    status: str
    message_id: Optional[str] = None
    draft_id: Optional[str] = None
    event_id: Optional[str] = None
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
        if self.event_id:
            fields.append(f"eid={self.event_id}")
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


class AttachmentMode(str, Enum):
    """Supported attachment presentation and compatibility modes."""
    AUTO = "auto"
    SNAPSHOT = "snapshot"
    COMPATIBILITY = "compatibility"
    INVITATION = "invitation"


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
    thread_id: Optional[str] = None
    in_reply_to: Optional[str] = None
    references: List[str] = field(default_factory=list)
    attachments: List[FrozenAttachment] = field(default_factory=list)
    draft_id: Optional[str] = None  # Populated when saved to Gmail Drafts
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        """Validates safety bounds and CRLF header injection protections."""
        from email.message import EmailMessage
        from pathlib import Path
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

        # 3. Thread-binding values are fingerprinted and must be safe RFC headers.
        message_id_pattern = re.compile(r"^<[^<>\s]+>$")
        if self.thread_id is not None:
            if not self.thread_id.strip():
                raise FrozenDraftValidationError("Thread ID must not be empty.")
            if any(char in self.thread_id for char in ("\x00", "\r", "\n")):
                raise FrozenDraftValidationError("Invalid control character in thread ID.")
            if not self.in_reply_to or not self.references:
                raise FrozenDraftValidationError(
                    "A thread-bound draft requires In-Reply-To and References headers."
                )

        if self.in_reply_to is not None and not message_id_pattern.fullmatch(self.in_reply_to):
            raise FrozenDraftValidationError("In-Reply-To must be one RFC Message-ID value.")
        for reference in self.references:
            if not message_id_pattern.fullmatch(reference):
                raise FrozenDraftValidationError(
                    "Each References entry must be one RFC Message-ID value."
                )

        # 4. Payload size bounds
        body_bytes = len(self.body_text.encode("utf-8"))
        if self.body_html:
            body_bytes += len(self.body_html.encode("utf-8"))
        if body_bytes > MAX_TRANSMISSION_BODY_BYTES:
            raise FrozenDraftValidationError(
                f"Aggregate message body ({body_bytes} bytes) exceeds maximum bound of {MAX_TRANSMISSION_BODY_BYTES} bytes."
            )

        # 5. Attachment bounds
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

            # Validate calendar media-type parameters per RFC 5545 §3.1.4 and RFC 6047 §2.4
            temp_msg = EmailMessage()
            temp_msg["Content-Type"] = att.mime_type
            maintype = temp_msg.get_content_maintype()
            subtype = temp_msg.get_content_subtype()
            params = dict(temp_msg.get_params()[1:]) if temp_msg.get_params() else {}
            params_lower = {k.lower(): v for k, v in params.items()}

            if f"{maintype}/{subtype}".lower() == "text/calendar":
                if "charset" not in params_lower or not params_lower["charset"]:
                    raise FrozenDraftValidationError(
                        f"Calendar attachment '{att.filename}' with Content-Type 'text/calendar' "
                        "must specify charset (e.g. 'text/calendar; charset=UTF-8') per RFC 5545 §3.1.4."
                    )
                if "method" in params_lower and params_lower["method"]:
                    method_param = params_lower["method"].strip().upper()
                    if att.file_path and Path(att.file_path).exists():
                        try:
                            content_str = Path(att.file_path).read_text(encoding="utf-8", errors="replace")
                            method_match = re.search(r"(?m)^METHOD:([A-Za-z0-9_-]+)", content_str, re.IGNORECASE)
                            if not method_match or method_match.group(1).upper() != method_param:
                                found_method = method_match.group(1).upper() if method_match else "NONE"
                                raise FrozenDraftValidationError(
                                    f"Calendar invitation attachment '{att.filename}' has MIME method='{method_param}', "
                                    f"which does not match VCALENDAR METHOD property ('{found_method}')."
                                )
                        except OSError:
                            pass

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
            "thread_id": self.thread_id,
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

    @property
    def fingerprint(self) -> str:
        """Returns the computed cryptographic SHA-256 fingerprint."""
        return self.compute_fingerprint()

    def to_dict(self) -> Dict[str, Any]:
        """Returns standard dictionary representation for persistence and IPC."""
        return {
            "to": list(self.to),
            "subject": self.subject,
            "body_text": self.body_text,
            "cc": list(self.cc),
            "bcc": list(self.bcc),
            "body_html": self.body_html,
            "thread_id": self.thread_id,
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
            thread_id=data.get("thread_id"),
            in_reply_to=data.get("in_reply_to"),
            references=list(data.get("references", [])),
            attachments=attachments,
            draft_id=data.get("draft_id"),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )


class CleanupAction(str, Enum):
    TRASH = "trash"
    ARCHIVE = "archive"
    MARK_READ = "mark_read"
    ADD_LABEL = "add_label"
    REMOVE_LABEL = "remove_label"


class CleanupPlanValidationError(ValueError):
    """Raised when a CleanupPlan violates safety bounds or operational constraints."""


@dataclass(frozen=True)
class CleanupTarget:
    """Individual message targeted for mutation."""
    message_id: str
    thread_id: str
    sender: str
    subject: str
    date: str
    action: CleanupAction
    add_labels: List[str] = field(default_factory=list)
    remove_labels: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class CleanupPlan:
    """Immutable mailbox modification plan bound to a deterministic cryptographic fingerprint."""
    query: str
    action_type: CleanupAction
    targets: List[CleanupTarget]
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate(self) -> None:
        """Validates batch ceilings and target constraints."""
        from gmail_local.config import MAX_CLEANUP_BATCH_SIZE

        if not self.targets:
            raise CleanupPlanValidationError("Cleanup plan must contain at least one target message.")

        if len(self.targets) > MAX_CLEANUP_BATCH_SIZE:
            raise CleanupPlanValidationError(
                f"Target message count ({len(self.targets)}) exceeds maximum batch bound of {MAX_CLEANUP_BATCH_SIZE}."
            )

        for target in self.targets:
            if not target.message_id:
                raise CleanupPlanValidationError("Invalid empty message_id in cleanup target.")
            if "\x00" in target.message_id:
                raise CleanupPlanValidationError("Null byte character detected in target message_id.")
            if "\r" in target.message_id or "\n" in target.message_id:
                raise CleanupPlanValidationError("CRLF characters detected in target message_id.")
            if not target.message_id.strip():
                raise CleanupPlanValidationError("Invalid empty message_id in cleanup target.")
            for lbl in target.add_labels + target.remove_labels:
                if "\x00" in lbl:
                    raise CleanupPlanValidationError("Null byte character detected in label name.")
                if "\r" in lbl or "\n" in lbl:
                    raise CleanupPlanValidationError(f"CRLF characters detected in label name: {repr(lbl)}")

    def canonical_dict(self) -> Dict[str, Any]:
        """Returns ordered, normalized representation for deterministic hashing."""
        action_val = self.action_type.value if isinstance(self.action_type, CleanupAction) else str(self.action_type)
        return {
            "query": self.query.strip(),
            "action_type": action_val,
            "targets": [
                {
                    "message_id": t.message_id.strip(),
                    "action": t.action.value if isinstance(t.action, CleanupAction) else str(t.action),
                    "add_labels": sorted(t.add_labels),
                    "remove_labels": sorted(t.remove_labels),
                }
                for t in sorted(self.targets, key=lambda x: x.message_id)
            ],
        }

    def compute_fingerprint(self) -> str:
        """Generates SHA-256 fingerprint of the canonical JSON representation."""
        serialized = json.dumps(self.canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @property
    def fingerprint(self) -> str:
        """Returns the computed cryptographic SHA-256 fingerprint."""
        return self.compute_fingerprint()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes CleanupPlan to a dictionary."""
        action_val = self.action_type.value if isinstance(self.action_type, CleanupAction) else str(self.action_type)
        return {
            "query": self.query,
            "action_type": action_val,
            "fingerprint": self.compute_fingerprint(),
            "created_at": self.created_at,
            "targets": [
                {
                    "message_id": t.message_id,
                    "thread_id": t.thread_id,
                    "sender": t.sender,
                    "subject": t.subject,
                    "date": t.date,
                    "action": t.action.value if isinstance(t.action, CleanupAction) else str(t.action),
                    "add_labels": list(t.add_labels),
                    "remove_labels": list(t.remove_labels),
                }
                for t in self.targets
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CleanupPlan":
        """Reconstructs a CleanupPlan instance from dictionary representation."""
        action_type = CleanupAction(data["action_type"])
        targets = [
            CleanupTarget(
                message_id=t["message_id"],
                thread_id=t.get("thread_id", ""),
                sender=t.get("sender", ""),
                subject=t.get("subject", ""),
                date=t.get("date", ""),
                action=CleanupAction(t["action"]),
                add_labels=list(t.get("add_labels", [])),
                remove_labels=list(t.get("remove_labels", [])),
            )
            for t in data.get("targets", [])
        ]
        return cls(
            query=data["query"],
            action_type=action_type,
            targets=targets,
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
        )

    def to_handoff_summary(self) -> str:
        """Emits standardized Cleanup Handoff block."""
        fp = self.compute_fingerprint()
        lines = [
            "============================ CLEANUP HANDOFF ============================",
            f"Plan Fingerprint:   {fp}",
            f"Action Type:        {self.action_type.value.upper()}",
            f"Target Count:       {len(self.targets)} messages (within 50-message batch bound)",
            f"Search Query:       {self.query}",
            "",
            "Summary of Targets:",
        ]
        for t in self.targets[:5]:
            lines.append(f"  - [{t.message_id}] {t.date} | {t.subject}")
        if len(self.targets) > 5:
            lines.append(f"  ... ({len(self.targets) - 5} more messages)")

        lines.extend([
            "",
            f"Plan Staging:       ~/.local/state/gmail-local/plans/{fp}.json",
            "",
            "To review full target details:",
            f"  gmail-local cleanup preview {fp}",
            "",
            "To authorize execution, the Operator must independently run:",
            f"  gmail-local cleanup apply --plan {fp} --confirm",
            "========================================================================",
        ])
        return "\n".join(lines)


@dataclass(frozen=True)
class Attendee:
    """Attendee for a Calendar event."""
    email: str
    response_status: str = "needsAction"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "responseStatus": self.response_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Attendee":
        return cls(
            email=data["email"],
            response_status=data.get("responseStatus", data.get("response_status", "needsAction")),
        )


@dataclass(frozen=True)
class ConferenceData:
    """Google Meet conference entry details."""
    uri: str
    conference_id: str
    entry_point_type: str = "video"
    status: str = "success"
    label: Optional[str] = None
    phone_uri: Optional[str] = None
    phone_pin: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "uri": self.uri,
            "conference_id": self.conference_id,
            "entry_point_type": self.entry_point_type,
            "status": self.status,
        }
        if self.label is not None:
            d["label"] = self.label
        if self.phone_uri is not None:
            d["phone_uri"] = self.phone_uri
        if self.phone_pin is not None:
            d["phone_pin"] = self.phone_pin
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConferenceData":
        return cls(
            uri=data["uri"],
            conference_id=data["conference_id"],
            entry_point_type=data.get("entry_point_type", "video"),
            status=data.get("status", "success"),
            label=data.get("label"),
            phone_uri=data.get("phone_uri"),
            phone_pin=data.get("phone_pin"),
        )


@dataclass(frozen=True)
class CalendarEvent:
    """Domain model for a Google Calendar event."""
    id: str
    summary: str
    start: str
    end: str
    timezone: str
    description: Optional[str] = None
    attendees: List[Attendee] = field(default_factory=list)
    has_meet: bool = True
    html_link: Optional[str] = None
    conference: Optional[ConferenceData] = None
    fingerprint: Optional[str] = None

    def compute_fingerprint(self) -> str:
        """Deterministic SHA-256 fingerprint from canonical attributes."""
        canonical_obj = {
            "summary": self.summary.strip(),
            "start": self.start.strip(),
            "end": self.end.strip(),
            "timezone": self.timezone.strip(),
            "attendees": sorted(a.email.strip().lower() for a in self.attendees),
            "has_meet": self.has_meet,
        }
        raw_json = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "summary": self.summary,
            "start": self.start,
            "end": self.end,
            "timezone": self.timezone,
            "has_meet": self.has_meet,
            "attendees": [a.to_dict() for a in self.attendees],
        }
        if self.description is not None:
            d["description"] = self.description
        if self.html_link is not None:
            d["html_link"] = self.html_link
        if self.conference is not None:
            d["conference"] = self.conference.to_dict()
        if self.fingerprint is not None:
            d["fingerprint"] = self.fingerprint
        else:
            d["fingerprint"] = self.compute_fingerprint()
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CalendarEvent":
        attendees = [Attendee.from_dict(a) for a in data.get("attendees", [])]
        conf_data = data.get("conference")
        conf = ConferenceData.from_dict(conf_data) if conf_data else None
        return cls(
            id=data["id"],
            summary=data["summary"],
            start=data["start"],
            end=data["end"],
            timezone=data["timezone"],
            description=data.get("description"),
            attendees=attendees,
            has_meet=data.get("has_meet", True),
            html_link=data.get("html_link"),
            conference=conf,
            fingerprint=data.get("fingerprint"),
        )


@dataclass(frozen=True)
class CalendarPreview:
    """Staged dry-run preview and handoff artifact for a calendar event."""
    event: CalendarEvent
    send_updates: str = "none"
    handoff_markdown: str = ""
