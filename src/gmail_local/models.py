"""Domain models for bounded Gmail retrieval."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


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
