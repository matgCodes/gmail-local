"""Mailbox modification, staged cleanup plans, and Manual Modify Gate enforcement."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from googleapiclient.discovery import build

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.config import (
    DEFAULT_SEARCH_BOUND,
    MAX_CLEANUP_BATCH_SIZE,
    PLANS_DIR,
)
from gmail_local.models import (
    AuditEntry,
    CleanupAction,
    CleanupPlan,
    CleanupPlanValidationError,
    CleanupTarget,
)
from gmail_local.rate_limiter import RateLimiter


class ManualModifyGateViolationError(PermissionError):
    """Raised when modification is attempted without explicit operator authorization."""


class SecurityViolationError(PermissionError):
    """Raised when an operation violates core security invariants (e.g. permanent delete)."""


def save_plan_locally(plan: CleanupPlan, plans_dir: Optional[Path] = None) -> Path:
    """Persists a CleanupPlan to disk named by its SHA-256 fingerprint."""
    target_dir = plans_dir or PLANS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    try:
        target_dir.chmod(0o700)
    except OSError:
        pass

    fp = plan.compute_fingerprint()
    file_path = target_dir / f"{fp}.json"
    data = plan.to_dict()
    file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    try:
        file_path.chmod(0o600)
    except OSError:
        pass
    return file_path


def load_plan_locally(identifier: str, plans_dir: Optional[Path] = None) -> CleanupPlan:
    """Loads a CleanupPlan by file path, full fingerprint, or fingerprint prefix."""
    target_dir = plans_dir or PLANS_DIR

    # 1. Direct file path check
    p = Path(identifier).expanduser()
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            return CleanupPlan.from_dict(data)
        except Exception as e:
            raise CleanupPlanValidationError(f"Invalid plan file format: {e}") from e

    # 2. Check within target_dir
    if target_dir.exists():
        direct_file = target_dir / f"{identifier}.json"
        if direct_file.is_file():
            data = json.loads(direct_file.read_text(encoding="utf-8"))
            return CleanupPlan.from_dict(data)

        # Prefix search
        matches = list(target_dir.glob(f"{identifier}*.json"))
        if len(matches) == 1:
            data = json.loads(matches[0].read_text(encoding="utf-8"))
            return CleanupPlan.from_dict(data)
        elif len(matches) > 1:
            raise ValueError(f"Ambiguous plan fingerprint prefix '{identifier}' matches multiple plans.")

    raise FileNotFoundError(f"No local cleanup plan found matching '{identifier}'")


class GmailModifier:
    """Manages staged cleanup planning and guarded mailbox modification behind the Manual Modify Gate."""

    def __init__(
        self,
        auth: Optional[AuthManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_logger: Optional[AuditLogger] = None,
        service: Optional[Any] = None,
        plans_dir: Optional[Path] = None,
    ):
        self.auth = auth or AuthManager.for_modification()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_logger = audit_logger or AuditLogger()
        self.service = service
        self.plans_dir = plans_dir or PLANS_DIR

    def _get_service(self):
        if self.service is None:
            creds = self.auth.get_credentials()
            self.service = build("gmail", "v1", credentials=creds, cache_discovery=False)
        return self.service

    def build_plan(
        self,
        query: str,
        action: CleanupAction,
        add_labels: Optional[List[str]] = None,
        remove_labels: Optional[List[str]] = None,
        limit: int = DEFAULT_SEARCH_BOUND,
        purpose: str = "cleanup_plan",
    ) -> CleanupPlan:
        """Executes candidate discovery and builds an immutable, fingerprinted CleanupPlan."""
        if not query or not query.strip():
            raise CleanupPlanValidationError("Search query must not be empty.")

        effective_limit = min(max(1, limit), MAX_CLEANUP_BATCH_SIZE)
        service = self._get_service()

        def _list_call():
            return (
                service.users()
                .messages()
                .list(userId="me", q=query, maxResults=effective_limit)
                .execute()
            )

        resp = self.rate_limiter.execute_with_retry("users.messages.list", _list_call)
        messages_meta = resp.get("messages", [])

        targets: List[CleanupTarget] = []
        for item in messages_meta:
            m_id = item["id"]

            def _get_call(msg_id=m_id):
                return (
                    service.users()
                    .messages()
                    .get(
                        userId="me",
                        id=msg_id,
                        format="metadata",
                        metadataHeaders=["Subject", "From", "Date"],
                    )
                    .execute()
                )

            detail = self.rate_limiter.execute_with_retry("users.messages.get", _get_call)
            headers = {
                h["name"].lower(): h["value"]
                for h in detail.get("payload", {}).get("headers", [])
            }

            sub = headers.get("subject", "(No Subject)")
            sender = headers.get("from", "(Unknown Sender)")
            date_val = headers.get("date", "")

            # Set label mutations based on action
            target_add = list(add_labels) if add_labels else []
            target_remove = list(remove_labels) if remove_labels else []

            if action == CleanupAction.ARCHIVE and "INBOX" not in target_remove:
                target_remove.append("INBOX")
            elif action == CleanupAction.MARK_READ and "UNREAD" not in target_remove:
                target_remove.append("UNREAD")

            target = CleanupTarget(
                message_id=m_id,
                thread_id=item.get("threadId", detail.get("threadId", "")),
                sender=sender,
                subject=sub,
                date=date_val,
                action=action,
                add_labels=target_add,
                remove_labels=target_remove,
            )
            targets.append(target)

        plan = CleanupPlan(
            query=query,
            action_type=action,
            targets=targets,
        )
        plan.validate()

        # Stage plan locally
        save_plan_locally(plan, plans_dir=self.plans_dir)

        # Audit log
        fp = plan.compute_fingerprint()
        self.audit_logger.record(
            AuditEntry(
                operation="cleanup_plan",
                purpose=purpose,
                status="SUCCESS",
                fingerprint=fp,
                details=f"targets={len(targets)}_action={action.value}",
            )
        )
        return plan

    def apply_plan(
        self,
        plan_or_id: Union[CleanupPlan, str],
        confirm: bool = False,
        interactive: bool = False,
        purpose: str = "cleanup_apply",
    ) -> Dict[str, Any]:
        """Applies a staged CleanupPlan behind the Manual Modify Gate."""
        if isinstance(plan_or_id, str):
            plan = load_plan_locally(plan_or_id, plans_dir=self.plans_dir)
        else:
            plan = plan_or_id

        plan.validate()
        fp = plan.compute_fingerprint()

        # Enforce Manual Modify Gate
        if not confirm and not interactive:
            raise ManualModifyGateViolationError(
                "Manual Modify Gate violation: Mailbox modification in non-interactive environment requires explicit --confirm flag."
            )

        service = self._get_service()
        processed_count = 0

        for target in plan.targets:
            if target.action == CleanupAction.TRASH:
                def _trash_call(msg_id=target.message_id):
                    return service.users().messages().trash(userId="me", id=msg_id).execute()

                self.rate_limiter.execute_with_retry("users.messages.trash", _trash_call)
                self.audit_logger.record(
                    AuditEntry(
                        operation="trash",
                        purpose=purpose,
                        status="SUCCESS",
                        message_id=target.message_id,
                        fingerprint=fp,
                    )
                )

            elif target.action in (
                CleanupAction.ARCHIVE,
                CleanupAction.MARK_READ,
                CleanupAction.ADD_LABEL,
                CleanupAction.REMOVE_LABEL,
            ):
                body: Dict[str, Any] = {}
                if target.add_labels:
                    body["addLabelIds"] = target.add_labels
                if target.remove_labels:
                    body["removeLabelIds"] = target.remove_labels

                def _modify_call(msg_id=target.message_id, b=body):
                    return service.users().messages().modify(userId="me", id=msg_id, body=b).execute()

                self.rate_limiter.execute_with_retry("users.messages.modify", _modify_call)
                op_name = target.action.value
                self.audit_logger.record(
                    AuditEntry(
                        operation=op_name,
                        purpose=purpose,
                        status="SUCCESS",
                        message_id=target.message_id,
                        fingerprint=fp,
                    )
                )
            else:
                raise ValueError(f"Unsupported cleanup action: {target.action}")

            processed_count += 1

        return {
            "status": "SUCCESS",
            "fingerprint": fp,
            "processed": processed_count,
            "action": plan.action_type.value,
        }

    def untrash(self, message_id: str, purpose: str = "cleanup_untrash") -> Dict[str, Any]:
        """Restores a message from Gmail Trash back to the mailbox (users.messages.untrash)."""
        clean_id = message_id.strip()
        if not clean_id or "\r" in clean_id or "\n" in clean_id:
            raise ValueError(f"Invalid message ID: {repr(message_id)}")

        service = self._get_service()

        def _untrash_call():
            return service.users().messages().untrash(userId="me", id=clean_id).execute()

        self.rate_limiter.execute_with_retry("users.messages.untrash", _untrash_call)
        self.audit_logger.record(
            AuditEntry(
                operation="untrash",
                purpose=purpose,
                status="SUCCESS",
                message_id=clean_id,
            )
        )
        return {"status": "SUCCESS", "message_id": clean_id}

    def delete_message_permanently(self, message_id: str) -> None:
        """Strictly forbidden under ADR 0010 and WAYFINDER_GMAIL_API_MODIFY_ACCESS.md."""
        raise SecurityViolationError(
            "Permanent deletion (users.messages.delete) is strictly forbidden under ADR 0010. "
            "Use reversible soft-delete (users.messages.trash) instead."
        )
