# Wayfinder Ticket: Establish Guarded Gmail API Write and Transmission Access

**Status:** Active (Transmission Milestone Specification & Scaffolding)  
**Type:** `wayfinder:task`  
**Created:** 2026-09-10  
**Workspace:** `/Users/mag_station/Dev_Tools/Gmail-API`  
**Account:** `[REDACTED_USER_EMAIL]`  
**Governing ADRs:** [ADR 0001](docs/adr/0001-user-executed-send-gate.md), [ADR 0002](docs/adr/0002-authorize-retrieval-before-transmission.md), [ADR 0003](docs/adr/0003-separate-retrieval-and-transmission-credentials.md), [ADR 0004](docs/adr/0004-one-oauth-project-two-desktop-clients.md), [ADR 0007](docs/adr/0007-separate-service-throttling-from-content-disclosure.md), [ADR 0008](docs/adr/0008-attachment-staging-and-audit-log-retention.md), and [CONTEXT.md](CONTEXT.md).  
**Predecessor Ticket:** [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md) (Completed and verified 2026-09-10).

---

## 1. Question

How should the Operator establish durable, least-privilege API write and transmission access to the personal Gmail account so an AI drafting agent can construct immutable Frozen Drafts, stage them to Gmail's "Drafts" folder (`gmail.compose`), and permit the Operator to independently execute guarded message transmission (`gmail.send` / `users.messages.send`) through a stable Sender CLI behind an interactive Manual Send Gate, strictly enforcing recipient bounds, payload caps, separate Keychain credentials, and append-only audit logging?

---

## 2. Destination

A locally operated, auditable Gmail outbound capability that:

1. **Maintains Strict Credential Separation ([ADR 0003](docs/adr/0003-separate-retrieval-and-transmission-credentials.md), [ADR 0004](docs/adr/0004-one-oauth-project-two-desktop-clients.md))**:
   - Uses a dedicated Desktop OAuth Client configuration file (`~/.config/gmail-local/client_secret_transmission.json`), distinct from the retrieval client secret.
   - Stores the transmission refresh token in macOS Keychain under service name `gmail-local-transmission` (`KEYCHAIN_SERVICE_TRANSMISSION`), completely separate from `gmail-local-retrieval`.
   - Never upgrades or mutates the existing `gmail-local-retrieval` credential.
   - Can be disconnected or revoked independently without disrupting the read-only retrieval setup.

2. **Requests Least-Privilege Outbound OAuth Scope**:
   - Requests `https://www.googleapis.com/auth/gmail.compose`.
   - Rationale: `gmail.compose` permits creating and managing drafts (`users.drafts.*`) as well as user-initiated sending (`users.messages.send`), without granting broad mailbox modification (`gmail.modify`) or deletion privileges.

3. **Implements the Frozen Draft Contract ([ADR 0001](docs/adr/0001-user-executed-send-gate.md), [CONTEXT.md](CONTEXT.md))**:
   - An immutable data container binding recipient headers (`To`, `Cc`, `Bcc`), single-line subject, plain-text and optional HTML body, in-reply-to threading headers, and local attachment descriptors.
   - Computes a deterministic SHA-256 fingerprint across normalized fields. Any alteration to body, recipient, or attachment invalidates the fingerprint.
   - Supports saving drafts locally as JSON or uploading directly to the Gmail user's "Drafts" folder via `users.drafts.create`.

4. **Enforces the Manual Send Gate ([ADR 0001](docs/adr/0001-user-executed-send-gate.md))**:
   - AI agents (Codex, Antigravity, Claude Code) may construct Frozen Drafts and generate a **Send Handoff**, but **CANNOT** transmit emails autonomously.
   - The Sender CLI (`gmail-local send`) requires direct Operator execution with an explicit `--confirm` flag or interactive TTY confirmation prompt matching the exact draft fingerprint.
   - Non-interactive invocations lacking `--confirm` fail immediately with a hard security violation error.

5. **Applies Strict Payload & Safety Boundaries**:
   - **Recipient Bound:** At most 10 recipients total across `To`, `Cc`, and `Bcc`.
   - **Message Body Bound:** At most 1 MiB (1,048,576 bytes) of aggregate message text/HTML.
   - **Attachment Bounds:** At most 25 MiB per attached file and 50 MiB in aggregate, verified before MIME base64 encoding.
   - **Header Injection Defense:** Hard rejection of carriage return (`\r`) and newline (`\n`) characters in email addresses, subject line, and attachment filenames.

6. **Records Append-Only Audit Logging ([ADR 0008](docs/adr/0008-attachment-staging-and-audit-log-retention.md))**:
   - Logs `op=draft_create` and `op=message_send` events to `~/.local/state/gmail-local/audit.log` with timestamp, draft ID / message ID, fingerprint, recipient count, and byte size.
   - Never logs message bodies, subject lines with PII, attachment binary contents, or credentials.

---

## 3. Frozen Draft Specification & Data Model

### 3.1 Dataclass Definitions

```python
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import hashlib
import json

@dataclass(frozen=True)
class FrozenAttachment:
    """Metadata and local hash verification for an outbound attachment."""
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
    draft_id: Optional[str] = None  # Gmail Draft ID (r-...) when staged to Gmail
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

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
            "references": self.references,
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
```

### 3.2 Send Handoff Format

When an agent finishes preparing a draft, it must halt and output the standardized **Send Handoff**:

```markdown
============================= SEND HANDOFF =============================
Draft Fingerprint: 3f8b1a9c4e2d7f0b...
Recipients (To):  recipient@example.com
Subject:          Quarterly Review Notes
Attachments:      report.pdf (142 KB, sha256: 9e2a...)
Payload Size:     148,204 bytes (within 1 MiB bound)
Gmail Staging:    Staged to Gmail Drafts (Draft ID: r-7291048102)

To inspect this draft in Gmail:
  Open https://mail.google.com/#drafts

To authorize transmission, the Operator must independently run:
  gmail-local send --draft 3f8b1a9c4e2d7f0b --confirm
========================================================================
```

---

## 4. Architectural Boundaries & Quota Management

### 4.1 Credential & Configuration Separation

| Item | Retrieval Grant (Existing) | Transmission Grant (This Ticket) |
| :--- | :--- | :--- |
| **OAuth Scope** | `https://www.googleapis.com/auth/gmail.readonly` | `https://www.googleapis.com/auth/gmail.compose` |
| **Client Secret Config** | `~/.config/gmail-local/client_secret.json` | `~/.config/gmail-local/client_secret_transmission.json` |
| **macOS Keychain Service** | `gmail-local-retrieval` | `gmail-local-transmission` |
| **Default Account Key** | User email (`user@example.com`) | User email (`user@example.com`) |
| **Module Isolation** | `src/gmail_local/retrieval.py` | `src/gmail_local/composer.py`, `src/gmail_local/sender.py` |

### 4.2 Google API Quota Costs
Method quota costs (charged against the 3,000 units / 60s application rate limiter):
- `users.drafts.create`: **10 units**
- `users.drafts.get`: **10 units**
- `users.drafts.list`: **10 units**
- `users.drafts.send`: **100 units**
- `users.messages.send`: **100 units**

### 4.3 Quota & Concurrency Enforcement
- Draft and send operations integrate into the shared [`RateLimiter`](src/gmail_local/rate_limiter.py).
- Transient errors (`HTTP 429`, `HTTP 503`, rate-limit `HTTP 403`) follow exponential backoff with jitter up to 60s deadline.
- Terminal errors (`HTTP 400 Bad Request`, invalid email address, RFC 5322 syntax error) fail immediately without retrying.

---

## 5. Proposed CLI Surface

```bash
# 1. Transmission Authentication & Token Management
gmail-local compose-login [--client-secret <path>]   # Authorize desktop client for gmail.compose
gmail-local compose-status                          # Verify token validity and expiration
gmail-local compose-revoke                          # Revoke transmission token from Keychain & Google

# 2. Draft Creation & Staging
gmail-local draft \
  --to <email> [--to <email2>] \
  [--cc <email>] [--bcc <email>] \
  --subject "<subject_line>" \
  (--body "<text>" | --body-file <path>) \
  [--html "<html_text>" | --html-file <path>] \
  [--attach <filepath>] \
  [--reply-to-id <message_id>] \
  [--local-only | --push]                           # Default: --push saves to Gmail Drafts

# 3. Draft Inspection
gmail-local drafts list [--limit 10]                # List pending Gmail drafts
gmail-local drafts get <draft_id>                   # Inspect draft headers and fingerprint

# 4. Manual Send Gate (Transmission)
gmail-local send \
  --draft <fingerprint_or_draft_id_or_path> \
  --confirm                                         # Required in automated scripts; interactive prompt otherwise
```

---

## 6. Safety Checklist & Verification Boundaries

Before marking the Transmission Milestone complete, all items must be verified:

- [x] Distinct OAuth Client secret (`client_secret_transmission.json`) and Keychain service (`gmail-local-transmission`) implemented.
- [x] Retrieval token in `gmail-local-retrieval` is confirmed untouched and never upgraded.
- [x] OAuth scope is strictly `https://www.googleapis.com/auth/gmail.compose`.
- [x] Header injection defense tested: reject `\r`, `\n`, `\0`, and recipient delimiter injection in subject, recipients, and filenames.
- [x] Recipient bound enforced: reject any draft exceeding 10 recipients total.
- [x] Message size bounds enforced: reject body > 1 MiB or aggregate attachment > 50 MiB.
- [x] Frozen Draft fingerprinting implemented with deterministic canonical JSON hashing.
- [x] Manual Send Gate enforced: `send` command fails in non-interactive mode without `--confirm`.
- [x] Interactive confirmation prompt displays recipient list, subject, attachment names, and fingerprint.
- [x] `users.drafts.create` tested and verified (draft appears in Gmail web interface, verified with draft r6067898827920447571 and r794035402801703386).
- [x] `users.messages.send` and `users.drafts.send` tested under Manual Send Gate with live email dispatch receipt (Message ID: 1a08ac516f94803a).
- [x] Audit log appends structured lines for draft creation and message transmission without logging email bodies.
- [x] Disconnection and token revocation tested via `compose-revoke` and isolated mock revocation tests.
- [x] Automated unit test suite and SwarmForge adversarial evals expanded to >= 150 passing tests (165 passed: 147 unit + 18 evals).

---

## 7. Out of Scope

- Merging retrieval and transmission scopes into a single OAuth token.
- Autonomous sending without explicit human CLI execution (Manual Send Gate bypass).
- Mass email campaigns, mail merges, or marketing automation (> 10 recipients).
- Deletion or modification of already-sent messages (`gmail.modify` / permanent delete).
- Automatic background email processing or daemonized outbound queues.
