# Wayfinder Ticket: Establish Guarded Gmail API Mailbox Modification & Cleanup Access

**Status:** Completed and verified 2026-09-10  
**Type:** `wayfinder:task`  
**Created:** 2026-09-10  
**Workspace:** `/Users/mag_station/Dev_Tools/Gmail-API`  
**Account:** `[REDACTED_USER_EMAIL]`  
**Governing ADRs:** [ADR 0001](docs/adr/0001-user-executed-send-gate.md), [ADR 0002](docs/adr/0002-authorize-retrieval-before-transmission.md), [ADR 0003](docs/adr/0003-separate-retrieval-and-transmission-credentials.md), [ADR 0004](docs/adr/0004-one-oauth-project-two-desktop-clients.md), [ADR 0007](docs/adr/0007-separate-service-throttling-from-content-disclosure.md), [ADR 0008](docs/adr/0008-attachment-staging-and-audit-log-retention.md), [ADR 0009](docs/adr/0009-frozen-draft-fingerprint-and-manual-send-gate.md), [ADR 0010](docs/adr/0010-staged-cleanup-plan-and-manual-modify-gate.md), and [CONTEXT.md](CONTEXT.md).  
**Predecessor Tickets:** [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md) (Completed and verified 2026-09-10), [WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md](WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md) (Transmission Milestone).

---

## 1. Question

How should the Operator establish durable, least-privilege API mailbox modification and cleanup access to the personal Gmail account so an AI assistant can safely identify, categorize, archive, and soft-delete (trash) unwanted emails behind a cryptographically fingerprinted `CleanupPlan` and interactive Manual Modify Gate, strictly enforcing separate Keychain credentials (`gmail-local-modify`), batch ceilings (max 50 messages), reversible soft-delete (`messages.trash`) over permanent deletion, and append-only audit logging?

---

## 2. Destination

A locally operated, auditable Gmail mailbox cleanup and triage capability that:

1. **Maintains Strict Credential Separation ([ADR 0003](docs/adr/0003-separate-retrieval-and-transmission-credentials.md), [ADR 0004](docs/adr/0004-one-oauth-project-two-desktop-clients.md))**:
   - Uses a dedicated Desktop OAuth Client configuration file (`~/.config/gmail-local/client_secret_modify.json`), distinct from the retrieval (`client_secret.json`) and transmission (`client_secret_transmission.json`) client secrets.
   - Stores the modification refresh token in macOS Keychain under service name `gmail-local-modify` (`KEYCHAIN_SERVICE_MODIFY`), completely separate from `gmail-local-retrieval` and `gmail-local-transmission`.
   - Never upgrades or mutates the existing `gmail-local-retrieval` or `gmail-local-transmission` credentials.
   - Can be disconnected or revoked independently without disrupting read or transmission capabilities.

2. **Requests Least-Privilege Modification OAuth Scope**:
   - Requests `https://www.googleapis.com/auth/gmail.modify`.
   - **Permitted Operations:**
     - Archiving: removing the `INBOX` system label (`users.messages.modify`).
     - Marking Read: removing the `UNREAD` system label.
     - Custom Labeling: applying or removing user categorization labels.
     - Soft-deletion: moving messages to the user's Gmail Trash bin (`users.messages.trash`).
     - Untrashing: restoring accidentally trashed messages (`users.messages.untrash`).
   - **Excluded Operations:** Permanent, unrecoverable deletion (`users.messages.delete`), which requires the unrestricted `https://mail.google.com/` scope and is strictly out of scope.

3. **Implements the Staged Cleanup Plan Contract ([ADR 0010](docs/adr/0010-staged-cleanup-plan-and-manual-modify-gate.md))**:
   - Two-phase execution model:
     - **Phase 1 (Dry-Run / Plan):** Inspects candidate messages matching a search query or rule set, generates a deterministic `CleanupPlan` binding message IDs, subjects, senders, dates, current labels, and proposed mutations.
     - Computes a deterministic SHA-256 fingerprint over the canonical JSON representation. Any alteration invalidates the fingerprint.
   - Staging format: Plans can be saved locally as JSON artifacts (`~/.local/state/gmail-local/plans/<fingerprint>.json`) for review.

4. **Enforces the Manual Modify Gate ([ADR 0010](docs/adr/0010-staged-cleanup-plan-and-manual-modify-gate.md))**:
   - AI agents (Codex, Antigravity, Claude Code) may search for candidates, propose categorization, and generate a **Cleanup Handoff**, but **CANNOT** execute mailbox modifications autonomously.
   - The Cleanup CLI (`gmail-local cleanup apply`) requires direct Operator execution with an explicit `--confirm` flag or interactive TTY confirmation prompt matching the plan's exact fingerprint.
   - Non-interactive invocations lacking `--confirm` fail immediately with a hard security violation error.

5. **Applies Strict Operational & Blast-Radius Boundaries**:
   - **Batch Ceiling:** At most 50 messages per cleanup plan execution to prevent catastrophic bulk inbox wipes from hallucinated queries.
   - **Soft-Delete Safety Net:** All deletion requests use `users.messages.trash`, keeping items recoverable in the Gmail 30-day Trash folder.
   - **Reversible Untrash Command:** A dedicated `gmail-local cleanup untrash <message-id>` CLI command to quickly restore mistakenly trashed items.

6. **Records Append-Only Audit Logging ([ADR 0008](docs/adr/0008-attachment-staging-and-audit-log-retention.md))**:
   - Logs `op=trash`, `op=untrash`, `op=archive`, `op=mark_read`, and `op=modify_labels` events to `~/.local/state/gmail-local/audit.log` with timestamp, message ID, plan fingerprint, and label delta (`+LABEL`, `-LABEL`).
   - Never logs full message bodies or sensitive subject PII.

---

## 3. Staged Cleanup Plan Specification & Data Model

### 3.1 Dataclass Definitions

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import hashlib
import json
from datetime import datetime, timezone


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
            if not target.message_id or not target.message_id.strip():
                raise CleanupPlanValidationError("Invalid empty message_id in cleanup target.")

    def canonical_dict(self) -> Dict[str, Any]:
        """Returns ordered, normalized representation for deterministic hashing."""
        return {
            "query": self.query.strip(),
            "action_type": self.action_type.value,
            "targets": [
                {
                    "message_id": t.message_id.strip(),
                    "action": t.action.value,
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
```

### 3.2 Cleanup Handoff Format

When an agent identifies messages for cleanup, it halts and produces a standardized **Cleanup Handoff**:

```markdown
============================ CLEANUP HANDOFF ============================
Plan Fingerprint:   9d4e1a7b3c2e8f1a...
Action Type:        TRASH (Soft Delete) / ARCHIVE
Target Count:       18 messages (within 50-message batch bound)
Search Query:       from:promotions@newsletter.com older_than:30d

Summary of Targets:
  - [msg_id_1] 2026-08-01 | Weekly Deals #42
  - [msg_id_2] 2026-08-08 | Weekly Deals #43
  - [msg_id_3] 2026-08-15 | Special Promo Alert
  ... (15 more messages)

Plan Staging:       ~/.local/state/gmail-local/plans/9d4e1a7b3c2e8f1a.json

To review full target details:
  gmail-local cleanup preview 9d4e1a7b3c2e8f1a

To authorize execution, the Operator must independently run:
  gmail-local cleanup apply --plan 9d4e1a7b3c2e8f1a --confirm
========================================================================
```

---

## 4. Architectural Boundaries & Quota Management

### 4.1 Tripartite Credential Separation

| Item | Retrieval Grant | Transmission Grant | Modification Grant (This Ticket) |
| :--- | :--- | :--- | :--- |
| **OAuth Scope** | `.../auth/gmail.readonly` | `.../auth/gmail.compose` | `.../auth/gmail.modify` |
| **Client Secret Config** | `~/.config/gmail-local/client_secret.json` | `~/.config/gmail-local/client_secret_transmission.json` | `~/.config/gmail-local/client_secret_modify.json` |
| **macOS Keychain Service** | `gmail-local-retrieval` | `gmail-local-transmission` | `gmail-local-modify` |
| **Default Account Key** | User email (`user@example.com`) | User email (`user@example.com`) | User email (`user@example.com`) |
| **Module Isolation** | `src/gmail_local/retrieval.py` | `src/gmail_local/composer.py`, `sender.py` | `src/gmail_local/modifier.py` |

### 4.2 Google API Quota Costs
Method quota costs (charged against the 3,000 units / 60s application rate limiter):
- `users.messages.modify`: **5 units**
- `users.messages.trash`: **5 units**
- `users.messages.untrash`: **5 units**
- `users.threads.modify`: **10 units**
- `users.messages.batchModify`: **50 units**
- `users.labels.list`: **1 unit**
- `users.labels.create`: **5 units**

### 4.3 Quota & Concurrency Enforcement
- Cleanup actions integrate into the shared [`RateLimiter`](src/gmail_local/rate_limiter.py).
- Batch operations use single calls (`batchModify`) or throttled iterative calls with max 4 concurrent requests.
- Transient errors (`HTTP 429`, `HTTP 503`) follow exponential backoff with jitter up to a 60s deadline.
- Terminal errors (`HTTP 400 Bad Request`, `HTTP 404 Not Found`) fail immediately without retrying.

---

## 5. Proposed CLI Surface

```bash
# 1. Modification Authentication & Token Management
gmail-local modify-login [--client-secret <path>]   # Authorize desktop client for gmail.modify
gmail-local modify-status                          # Verify modify token validity and expiration
gmail-local modify-revoke                          # Revoke modify token from Keychain & Google

# 2. Staged Plan Generation (Dry-Run / Non-Destructive)
gmail-local cleanup plan \
  --query "from:noreply@updates.com older_than:60d" \
  --action trash \
  [--limit 50]                                     # Hard ceiling: 50

gmail-local cleanup plan \
  --query "label:unread category:promotions" \
  --action archive \
  [--limit 50]

# 3. Plan Inspection
gmail-local cleanup preview <fingerprint_or_plan_path>

# 4. Manual Modify Gate (Execution)
gmail-local cleanup apply \
  --plan <fingerprint_or_plan_path> \
  --confirm                                        # Required in scripts; interactive prompt otherwise

# 5. Recovery & Safety Rollback
gmail-local cleanup untrash <message-id>           # Restore message from Gmail Trash back to Inbox
```

---

## 6. Safety Checklist & Verification Boundaries

Before marking the Modification Milestone complete, all items must be verified:

- [x] Distinct OAuth Client secret (`client_secret_modify.json`) and Keychain service (`gmail-local-modify`) configured.
- [x] Retrieval token (`gmail-local-retrieval`) and Transmission token (`gmail-local-transmission`) confirmed untouched.
- [x] OAuth scope is strictly `https://www.googleapis.com/auth/gmail.modify` (no `https://mail.google.com/`).
- [x] Permanent deletion (`users.messages.delete`) is strictly excluded and rejected in code.
- [x] Batch ceiling enforced: reject any cleanup plan targeting > 50 messages.
- [x] Cryptographic fingerprinting implemented for `CleanupPlan` canonical JSON.
- [x] Manual Modify Gate enforced: `cleanup apply` fails in non-interactive mode without `--confirm`.
- [x] Interactive confirmation prompt displays candidate count, action type, sample subject lines, and fingerprint.
- [x] `users.messages.trash` and `users.messages.untrash` tested with mock responses and offline unit tests.
- [x] `users.messages.modify` tested for archive (`-INBOX`) and read status (`-UNREAD`).
- [x] Audit log appends structured lines for `op=trash`, `op=untrash`, and `op=modify_labels` without logging email bodies.
- [x] Disconnection and token revocation tested via `modify-revoke`.
- [x] Comprehensive unit test suite and SwarmForge adversarial evals expanded with >= 20 new tests for modifier boundaries (27 new tests added, 192 total unit tests & 22 evals passing).

---

## 7. Out of Scope

- Permanent, unrecoverable message deletion (`users.messages.delete`).
- Mailbox-wide administration or forwarding configuration changes.
- Automated background cron jobs or continuous background daemon inbox scrubbing without interactive gates.
- Merging modification, transmission, and retrieval into a monolithic OAuth grant.
- Mailbox-wide export or bulk downloading beyond established retrieval disclosure ceilings.
