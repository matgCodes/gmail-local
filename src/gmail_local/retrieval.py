"""Bounded Gmail retrieval operations enforcing all privacy and content bounds."""

import base64
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from googleapiclient.discovery import Resource, build
from googleapiclient.errors import HttpError

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.config import (
    DEFAULT_SEARCH_BOUND,
    MAX_ATTACHMENT_BYTES_AGGREGATE,
    MAX_ATTACHMENT_BYTES_PER_FILE,
    MAX_DECODED_BODY_BYTES,
    MAX_READ_MESSAGES,
    MAX_SEARCH_BOUND,
)
from gmail_local.mime_utils import (
    decode_rfc2047_header,
    extract_header_map,
    html_to_plain_text,
    sanitize_filename,
)
from gmail_local.models import (
    AttachmentDescriptor,
    AuditEntry,
    CandidateMessage,
    HistoryDelta,
    LabelInfo,
    SelectedMessage,
    ThreadSummary,
)
from gmail_local.rate_limiter import RateLimiter


class RetrievalBoundError(Exception):
    """Raised when an operation violates search, read, or attachment bounds."""


class OverwriteError(RetrievalBoundError):
    """Raised when a download attempts to overwrite an existing file."""


class PathTraversalError(RetrievalBoundError):
    """Raised when a download path contains unsafe directory traversal."""


class GmailRetriever:
    """Implements bounded read-only Gmail access with strict privacy enforcement."""

    def __init__(
        self,
        auth_manager: Optional[AuthManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_logger: Optional[AuditLogger] = None,
        service: Optional[Resource] = None,
    ):
        self.auth = auth_manager or AuthManager()
        self.limiter = rate_limiter or RateLimiter()
        self.audit = audit_logger or AuditLogger()
        self._service = service

    def _get_service(self) -> Resource:
        """Lazily initialize Google API service."""
        if self._service is None:
            creds = self.auth.get_credentials()
            self._service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return self._service

    def search_messages(
        self,
        query: str,
        max_results: int = DEFAULT_SEARCH_BOUND,
        purpose: str = "search",
    ) -> List[CandidateMessage]:
        """Search Gmail messages and return header-only CandidateMessage records."""
        if max_results < 1 or max_results > MAX_SEARCH_BOUND:
            raise RetrievalBoundError(
                f"max_results must be between 1 and {MAX_SEARCH_BOUND} (got {max_results})."
            )

        service = self._get_service()

        # Step 1: messages.list (5 quota units)
        def _list_call():
            return (
                service.users()
                .messages()
                .list(userId="me", q=query, maxResults=max_results)
                .execute()
            )

        list_resp = self.limiter.execute_with_retry("users.messages.list", _list_call)
        msg_items = list_resp.get("messages", [])[:max_results]

        candidates: List[CandidateMessage] = []

        # Step 2: messages.get(format=METADATA) for Date, From, To, Subject (20 quota units each)
        for item in msg_items:
            msg_id = item["id"]

            def _get_meta():
                return (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=msg_id,
                        format="metadata",
                        metadataHeaders=["Date", "From", "To", "Subject"],
                    )
                    .execute()
                )

            meta_resp = self.limiter.execute_with_retry("users.messages.get", _get_meta)

            headers = extract_header_map(meta_resp.get("payload"))

            candidate = CandidateMessage(
                id=msg_id,
                thread_id=meta_resp.get("threadId", ""),
                date=decode_rfc2047_header(headers.get("date", "")),
                sender=decode_rfc2047_header(headers.get("from", "")),
                recipient=decode_rfc2047_header(headers.get("to", "")),
                subject=decode_rfc2047_header(headers.get("subject", "(No Subject)")),
                preview=None,
            )
            candidates.append(candidate)

        self.audit.record(
            AuditEntry(
                operation="search_messages",
                purpose=purpose,
                status="SUCCESS",
                details=f"query='{query}' count={len(candidates)}",
            )
        )
        return candidates

    def preview_candidates(
        self,
        candidate_ids: List[str],
        purpose: str = "preview",
    ) -> List[CandidateMessage]:
        """Fetch short body snippets for an explicitly specified set of candidate message IDs."""
        if len(candidate_ids) > MAX_SEARCH_BOUND:
            raise RetrievalBoundError(
                f"Cannot preview more than {MAX_SEARCH_BOUND} candidates at once."
            )

        service = self._get_service()
        results: List[CandidateMessage] = []

        for cid in candidate_ids:
            def _get_meta():
                return (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=cid,
                        format="metadata",
                        metadataHeaders=["Date", "From", "To", "Subject"],
                    )
                    .execute()
                )

            meta_resp = self.limiter.execute_with_retry("users.messages.get", _get_meta)
            headers = extract_header_map(meta_resp.get("payload"))
            snippet = meta_resp.get("snippet", "")

            results.append(
                CandidateMessage(
                    id=cid,
                    thread_id=meta_resp.get("threadId", ""),
                    date=decode_rfc2047_header(headers.get("date", "")),
                    sender=decode_rfc2047_header(headers.get("from", "")),
                    recipient=decode_rfc2047_header(headers.get("to", "")),
                    subject=decode_rfc2047_header(headers.get("subject", "(No Subject)")),
                    preview=snippet,
                )
            )

        self.audit.record(
            AuditEntry(
                operation="preview_candidates",
                purpose=purpose,
                status="SUCCESS",
                details=f"count={len(results)}",
            )
        )
        return results

    @staticmethod
    def _extract_attachment_desc(
        part: Dict[str, Any], message_id: str
    ) -> Optional[AttachmentDescriptor]:
        """Extracts an AttachmentDescriptor if the part contains a file attachment."""
        raw_filename = part.get("filename", "")
        body = part.get("body", {})
        attachment_id = body.get("attachmentId")
        if raw_filename and (attachment_id or "data" in body):
            return AttachmentDescriptor(
                message_id=message_id,
                attachment_id=attachment_id or "inline",
                filename=sanitize_filename(raw_filename),
                mime_type=part.get("mimeType", ""),
                size_bytes=body.get("size", 0),
                is_inline=bool("data" in body and not attachment_id),
            )
        return None

    @staticmethod
    def _extract_text_content(
        part: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[str]]:
        """Extracts (plain_text, html_text) from a text MIME part if present."""
        mime_type = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        if not data:
            return None, None

        if mime_type == "text/plain":
            try:
                decoded = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
                return decoded, None
            except Exception:
                return None, None

        if mime_type == "text/html":
            try:
                html_content = base64.urlsafe_b64decode(data).decode("utf-8", errors="replace")
                return None, html_to_plain_text(html_content)
            except Exception:
                return None, None

        return None, None

    @staticmethod
    def _parse_single_mime_part(
        part: Dict[str, Any], message_id: str
    ) -> Tuple[Optional[str], Optional[str], Optional[AttachmentDescriptor]]:
        """Parses a single MIME part returning (plain_text, html_text, attachment_descriptor)."""
        att = GmailRetriever._extract_attachment_desc(part, message_id)
        if att:
            return None, None, att
        plain, html_text = GmailRetriever._extract_text_content(part)
        return plain, html_text, None

    def _extract_mime_parts(
        self, payload: Dict[str, Any], message_id: str
    ) -> Tuple[str, List[AttachmentDescriptor]]:
        """Recursively extracts text body and attachment descriptors from a MIME payload."""
        body_text_parts: List[str] = []
        html_fallback_parts: List[str] = []
        attachments: List[AttachmentDescriptor] = []

        def _walk(part: Dict[str, Any]):
            plain, html_text, att = self._parse_single_mime_part(part, message_id)
            if plain:
                body_text_parts.append(plain)
            if html_text:
                html_fallback_parts.append(html_text)
            if att:
                attachments.append(att)

            for subpart in part.get("parts", []):
                _walk(subpart)

        _walk(payload)
        chosen_parts = body_text_parts if body_text_parts else html_fallback_parts
        full_text = "\n\n".join(p for p in chosen_parts if p.strip())
        return full_text, attachments

    def get_messages(
        self,
        message_ids: List[str],
        purpose: str = "read",
    ) -> List[SelectedMessage]:
        """Retrieve full messages enforcing the 10-message and 1 MiB aggregate body limits."""
        if len(message_ids) > MAX_READ_MESSAGES:
            raise RetrievalBoundError(
                f"Read Bound violation: requested {len(message_ids)} messages, "
                f"maximum allowed per read is {MAX_READ_MESSAGES}."
            )

        service = self._get_service()
        selected: List[SelectedMessage] = []
        aggregate_bytes = 0

        for mid in message_ids:
            def _get_full():
                return (
                    service.users()
                    .messages()
                    .get(userId="me", id=mid, format="full")
                    .execute()
                )

            full_resp = self.limiter.execute_with_retry("users.messages.get", _get_full)
            payload = full_resp.get("payload", {})
            headers = extract_header_map(payload)

            body_text, attachments = self._extract_mime_parts(payload, mid)
            body_bytes = len(body_text.encode("utf-8"))

            # Read Bound: 1 MiB aggregate decoded body limit
            if aggregate_bytes + body_bytes > MAX_DECODED_BODY_BYTES:
                # Per ADR 0007 / WAYFINDER: discard held body immediately, emit no partial body,
                # stop read immediately, and do not process later selections.
                self.audit.record(
                    AuditEntry(
                        operation="get_messages",
                        purpose=purpose,
                        status="HELD_OVERFLOW",
                        message_id=mid,
                        details=(
                            f"Body size {body_bytes}B would exceed 1MiB limit "
                            f"(current aggregate {aggregate_bytes}B). Read terminated."
                        ),
                    )
                )
                break

            aggregate_bytes += body_bytes
            msg = SelectedMessage(
                id=mid,
                thread_id=full_resp.get("threadId", ""),
                date=decode_rfc2047_header(headers.get("date", "")),
                sender=decode_rfc2047_header(headers.get("from", "")),
                recipient=decode_rfc2047_header(headers.get("to", "")),
                subject=decode_rfc2047_header(headers.get("subject", "(No Subject)")),
                body_text=body_text,
                body_bytes=body_bytes,
                attachments=attachments,
            )
            selected.append(msg)
            self.audit.record(
                AuditEntry(
                    operation="get_messages",
                    purpose=purpose,
                    status="SUCCESS",
                    message_id=mid,
                    details=f"bytes={body_bytes} attachments={len(attachments)}",
                )
            )

        return selected

    def list_attachments(
        self,
        message_id: str,
        purpose: str = "list_attachments",
    ) -> List[AttachmentDescriptor]:
        """Lists attachment descriptors for a message without downloading binary content."""
        service = self._get_service()

        def _get_full():
            return (
                service.users()
                .messages()
                .get(userId="me", id=message_id, format="full")
                .execute()
            )

        resp = self.limiter.execute_with_retry("users.messages.get", _get_full)
        _, attachments = self._extract_mime_parts(resp.get("payload", {}), message_id)

        self.audit.record(
            AuditEntry(
                operation="list_attachments",
                purpose=purpose,
                status="SUCCESS",
                message_id=message_id,
                details=f"count={len(attachments)}",
            )
        )
        return attachments

    def _resolve_download_path(
        self,
        mid: str,
        att_id: str,
        target_path: Path,
        purpose: str,
    ) -> Path:
        """Resolves target download path, supporting directory auto-naming and safety checks."""
        target_path = target_path.resolve()
        if target_path.is_dir():
            att_list = self.list_attachments(mid, purpose=purpose)
            matched = [a for a in att_list if a.attachment_id == att_id]
            if not matched and len(att_list) == 1:
                matched = att_list
            fallback = f"attachment_{att_id[:12]}"
            orig_name = matched[0].filename if matched else f"{fallback}.bin"
            safe_name = sanitize_filename(orig_name, fallback_prefix=fallback)
            target_path = target_path / safe_name

        parent_dir = target_path.parent
        if not parent_dir.exists():
            parent_dir.mkdir(parents=True, exist_ok=True)

        if target_path.exists():
            self.audit.record(
                AuditEntry(
                    operation="download_attachments",
                    purpose=purpose,
                    status="REJECTED_OVERWRITE",
                    message_id=mid,
                    filename=target_path.name,
                    destination=str(target_path),
                )
            )
            raise OverwriteError(f"Target file already exists: {target_path}")

        return target_path

    def _fetch_attachment_bytes(self, mid: str, att_id: str) -> bytes:
        """Fetches and decodes base64 attachment data from Gmail API."""
        service = self._get_service()

        def _get_att():
            return (
                service.users()
                .messages()
                .attachments()
                .get(userId="me", messageId=mid, id=att_id)
                .execute()
            )

        att_resp = self.limiter.execute_with_retry(
            "users.messages.attachments.get", _get_att
        )
        raw_b64 = att_resp.get("data", "")
        return base64.urlsafe_b64decode(raw_b64)

    @staticmethod
    def _stage_and_install_file(tmp_path: Path, target_path: Path, data: bytes) -> None:
        """Writes binary data to restricted staging file and replaces atomically."""
        try:
            with open(tmp_path, "wb") as f:
                os.chmod(tmp_path, 0o600)
                f.write(data)
            os.replace(tmp_path, target_path)
        except Exception:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
            raise

    def download_attachments(
        self,
        selections: List[Tuple[str, str, Path]],  # (message_id, attachment_id, target_file)
        purpose: str = "download",
    ) -> List[Path]:
        """Download selected attachments enforcing atomic staging, no-overwrite, and size limits."""
        installed_paths: List[Path] = []
        aggregate_bytes = 0

        for mid, att_id, raw_target_path in selections:
            target_path = self._resolve_download_path(mid, att_id, raw_target_path, purpose)
            tmp_path = target_path.parent / f".{target_path.name}.tmp.{os.getpid()}"

            decoded_bytes = self._fetch_attachment_bytes(mid, att_id)
            file_size = len(decoded_bytes)

            if file_size > MAX_ATTACHMENT_BYTES_PER_FILE:
                raise RetrievalBoundError(
                    f"Attachment '{target_path.name}' size ({file_size} bytes) exceeds "
                    f"25 MiB single-file limit ({MAX_ATTACHMENT_BYTES_PER_FILE} bytes)."
                )

            if aggregate_bytes + file_size > MAX_ATTACHMENT_BYTES_AGGREGATE:
                raise RetrievalBoundError(
                    f"Downloading '{target_path.name}' would exceed 50 MiB aggregate limit "
                    f"({aggregate_bytes + file_size}/{MAX_ATTACHMENT_BYTES_AGGREGATE} bytes)."
                )

            self._stage_and_install_file(tmp_path, target_path, decoded_bytes)
            aggregate_bytes += file_size
            installed_paths.append(target_path)

            self.audit.record(
                AuditEntry(
                    operation="download_attachments",
                    purpose=purpose,
                    status="SUCCESS",
                    message_id=mid,
                    filename=target_path.name,
                    destination=str(target_path),
                    details=f"bytes={file_size}",
                )
            )

        return installed_paths

    def get_history(
        self,
        start_history_id: str,
        purpose: str = "sync",
    ) -> HistoryDelta:
        """Lightweight incremental synchronization using users.history.list (2 quota units)."""
        service = self._get_service()

        def _history_call():
            return (
                service.users()
                .history()
                .list(userId="me", startHistoryId=start_history_id)
                .execute()
            )

        try:
            resp = self.limiter.execute_with_retry("users.history.list", _history_call)
        except HttpError as err:
            if err.resp.status == 404:
                # Expired or invalid startHistoryId requires full sync
                self.audit.record(
                    AuditEntry(
                        operation="get_history",
                        purpose=purpose,
                        status="EXPIRED_HISTORY_ID",
                        details=f"startHistoryId={start_history_id}",
                    )
                )
                return HistoryDelta(history_id=start_history_id, is_expired=True)
            raise

        added: List[str] = []
        deleted: List[str] = []
        for h_record in resp.get("history", []):
            for m_add in h_record.get("messagesAdded", []):
                m = m_add.get("message", {})
                if m.get("id"):
                    added.append(m["id"])
            for m_del in h_record.get("messagesDeleted", []):
                m = m_del.get("message", {})
                if m.get("id"):
                    deleted.append(m["id"])

        delta = HistoryDelta(
            history_id=resp.get("historyId", start_history_id),
            messages_added=list(dict.fromkeys(added)),  # preserve order, unique
            messages_deleted=list(dict.fromkeys(deleted)),
            is_expired=False,
        )

        self.audit.record(
            AuditEntry(
                operation="get_history",
                purpose=purpose,
                status="SUCCESS",
                details=f"added={len(delta.messages_added)} deleted={len(delta.messages_deleted)}",
            )
        )
        return delta

    def get_thread(
        self,
        thread_id: str,
        purpose: str = "thread",
    ) -> ThreadSummary:
        """Inspect a conversation thread summary mapping constituent messages."""
        service = self._get_service()

        def _thread_call():
            return (
                service.users()
                .threads()
                .get(
                    userId="me",
                    id=thread_id,
                    format="metadata",
                    metadataHeaders=["From", "Subject"],
                )
                .execute()
            )

        resp = self.limiter.execute_with_retry("users.threads.get", _thread_call)
        messages = resp.get("messages", [])

        participants = set()
        subject = "(No Subject)"
        mids: List[str] = []

        for m in messages:
            mids.append(m["id"])
            headers = extract_header_map(m.get("payload"))
            if headers.get("from"):
                participants.add(decode_rfc2047_header(headers["from"]))
            if headers.get("subject") and subject == "(No Subject)":
                subject = decode_rfc2047_header(headers["subject"])

        summary = ThreadSummary(
            thread_id=thread_id,
            message_count=len(messages),
            subject=subject,
            participants=sorted(participants),
            message_ids=mids,
        )

        self.audit.record(
            AuditEntry(
                operation="get_thread",
                purpose=purpose,
                status="SUCCESS",
                details=f"count={len(mids)} participants={len(participants)}",
            )
        )
        return summary

    def list_labels(
        self,
        purpose: str = "list_labels",
    ) -> List[LabelInfo]:
        """List all Gmail labels (system and user) with IDs and names. Cost: 1 quota unit."""
        service = self._get_service()

        def _call():
            return service.users().labels().list(userId="me").execute()

        resp = self.limiter.execute_with_retry("users.labels.list", _call)
        labels: List[LabelInfo] = []
        for l in resp.get("labels", []):
            labels.append(
                LabelInfo(
                    id=l.get("id", ""),
                    name=l.get("name", ""),
                    type=l.get("type", "user"),
                    messages_total=l.get("messagesTotal"),
                    messages_unread=l.get("messagesUnread"),
                )
            )

        # Sort system labels first, then user labels alphabetically
        labels.sort(key=lambda x: (0 if x.type == "system" else 1, x.name.lower()))

        self.audit.record(
            AuditEntry(
                operation="list_labels",
                purpose=purpose,
                status="SUCCESS",
                details=f"count={len(labels)}",
            )
        )
        return labels
