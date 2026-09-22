# Gmail Local Integration (`gmail-local`)

A locally operated Gmail and Calendar capability providing least-privilege search, message reading, attachment downloads, guarded outbound drafting, staged mailbox cleanup, autonomous inbox triage, and Calendar/Meet event creation for personal accounts.

Governed by [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md), [WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md](WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md), [WAYFINDER_GMAIL_API_MODIFY_ACCESS.md](WAYFINDER_GMAIL_API_MODIFY_ACCESS.md), [WAYFINDER_INBOX_TRIAGE_PIPELINE.md](WAYFINDER_INBOX_TRIAGE_PIPELINE.md), [ADR 0014](docs/adr/0014-calendar-and-meet-integration-architecture.md), and [AGENTS.md](AGENTS.md).

---

## Security Boundaries & Guarantees

1. **Strict Read-Only Retrieval Scope:** Retrieval requests only `https://www.googleapis.com/auth/gmail.readonly`. That credential exposes no send, modify, label, trash, delete, settings, or administration operations; every write capability lives behind a separate grant and gate (see 2).
2. **Strict Credential Separation (ADR 0003, 0004, 0010 & 0014):** Each capability uses an isolated OAuth grant with its own desktop client secret and macOS Keychain service. The retrieval credential is never upgraded.

   | Grant | Scope | Client secret | Keychain service |
   | --- | --- | --- | --- |
   | Retrieval | `gmail.readonly` | `client_secret.json` | `gmail-local-retrieval` |
   | Transmission | `gmail.compose` | `client_secret_transmission.json` | `gmail-local-transmission` |
   | Modification | `gmail.modify` | `client_secret_modify.json` | `gmail-local-modify` |
   | Calendar | `calendar.events.owned` | `client_secret_calendar.json` | `gmail-local-calendar` |
3. **Cryptographic Frozen Drafts (ADR 0009):** Outbound emails are packaged into immutable `FrozenDraft` containers with deterministic canonical JSON hashing and SHA-256 fingerprinting. Any change to headers, body, or attachment digests invalidates the fingerprint.
4. **Manual Write Gates:** AI agents cannot autonomously perform any write. Every mutating command requires explicit human operator authorization, either an interactive confirmation prompt or an explicit `--confirm` flag in scripted environments. Non-interactive invocations without `--confirm` fail immediately with exit code 1.
   * **Manual Send Gate** (ADR 0001, 0009) guards `gmail-local send`.
   * **Manual Modify Gate** (ADR 0010) guards `gmail-local cleanup apply`.
   * **Manual Action Gate** (ADR 0014) guards `gmail-local calendar-event create`.
5. **TOCTOU Tamper Protection:** Attachments are re-verified on disk against their recorded SHA-256 digests immediately before dispatch to prevent Time-of-Check to Time-of-Use file tampering.
6. **Disclosure & Transmission Ceilings:**
   * **Search Bound:** Header-only results (Date, From, To, Subject, ID); default 10, hard ceiling of 75.
   * **Read Bound:** Maximum 10 messages and 1 MiB (1,048,576 bytes) aggregate decoded body text per read.
   * **Attachment Download Bound:** Maximum 25 MiB per file, 50 MiB aggregate. Explicit destination required, overwrite forbidden.
   * **Transmission Bound:** Maximum 10 total recipients (`To`, `Cc`, `Bcc`), maximum 1 MiB body text, maximum 25 MiB per attachment, 50 MiB aggregate. CRLF characters (`\r`, `\n`), null bytes (`\0`), and recipient delimiter injections (`,`, `;`) are strictly rejected.
   * **Cleanup Batch Bound:** Maximum 75 targets per `CleanupPlan` (ADR 0013); larger triage runs are partitioned into multiple fingerprinted plans.
   * **Calendar Bound:** Maximum 10 attendees per event. Attendee notifications default to `--send-updates none`, so no invitation email leaves the account unless the Operator asks for one.
7. **Service Protection:** Rolling budget of 3,000 quota units / 60s (50% of Google's per-user rate limit), max 4 concurrent requests in flight, truncated exponential backoff with jitter.
8. **Local Rotating Audit Log:** Append-only log at `~/.local/state/gmail-local/audit.log` (mode `0600`) rotated at 5 MiB. Logs timestamps, operations, message IDs, draft IDs, and fingerprints; never logs message bodies or credentials.

---

## Installation & Testing

```bash
# Virtual environment setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run test suite (100% offline mock execution, no network calls)
pytest -v
```

---

## Google Cloud Console Setup (One-Time)

To connect to your personal Gmail account:

1. **Create/Select Project:** Go to [Google Cloud Console](https://console.cloud.google.com/) and create a project (e.g., `gmail-local-tools`).
2. **Enable APIs:** Go to **APIs & Services > Library** and enable both the **Gmail API** and the **Google Calendar API**. Google Meet links are created through Calendar `events.insert` with `conferenceDataVersion=1`, so the Meet REST API does not need to be enabled (ADR 0014).
3. **Configure OAuth Consent Screen:**
   * Go to **APIs & Services > OAuth consent screen**.
   * User Type: **External**.
   * App name: `Gmail Local Tools`.
   * User support email & Developer contact: `your-email@gmail.com`.
   * Scopes: Add `https://www.googleapis.com/auth/gmail.readonly` (Retrieval), `https://www.googleapis.com/auth/gmail.compose` (Transmission), `https://www.googleapis.com/auth/gmail.modify` (Modification), and `https://www.googleapis.com/auth/calendar.events.owned` (Calendar).
   * Test Users: Add `your-email@gmail.com`.
4. **Create OAuth Client IDs (Desktop app):**
   Create one Desktop client per grant so each credential can be revoked independently (ADR 0003, 0004):
   * Retrieval Client: `Gmail Local Desktop Client` -> download to `~/.config/gmail-local/client_secret.json`
   * Transmission Client: `Gmail Local Transmission Desktop Client` -> download to `~/.config/gmail-local/client_secret_transmission.json`
   * Modification Client: `Gmail Local Modify Desktop Client` -> download to `~/.config/gmail-local/client_secret_modify.json`
   * Calendar Client: `Gmail Local Calendar Desktop Client` -> download to `~/.config/gmail-local/client_secret_calendar.json` (a `client_secret_meet.json` at the same path is accepted as a fallback)
5. **Secure Local Secrets:**
   ```bash
   chmod 600 ~/.config/gmail-local/client_secret*.json
   ```

---

## CLI Usage

### Retrieval Operations (`gmail.readonly`)

```bash
# 1. Check retrieval connection status
gmail-local status

# 2. Authenticate retrieval (launches system browser with PKCE flow)
gmail-local login

# 3. Search messages (headers only)
gmail-local search "from:court is:unread" --limit 10

# 4. Preview short snippets for candidate IDs
gmail-local preview <message-id-1> <message-id-2>

# 5. Read full messages (max 10 msgs, max 1 MiB aggregate body)
gmail-local read <message-id-1>

# 6. List attachments
gmail-local attachments <message-id-1>

# 7. Download attachment safely (pass directory to preserve original filename)
gmail-local download <message-id-1> <attachment-id> --dest ~/Downloads/

# 8. List mailbox labels (system and user folders)
gmail-local labels

# 9. Inspect conversation thread
gmail-local thread <thread-id>

# 10. Check incremental history changes
gmail-local history <start-history-id>

# 11. Revoke retrieval token and clear Keychain
gmail-local revoke
```

### Transmission Operations (`gmail.compose`)

```bash
# 1. Check transmission connection status
gmail-local compose-status

# 2. Authenticate transmission (system browser with PKCE flow)
gmail-local compose-login

# 3. Compose a FrozenDraft and stage to Gmail Drafts
gmail-local draft \
  --to recipient@example.com \
  --subject "Quarterly Status Update" \
  --body "All deliverables complete and verified." \
  --attach ~/Documents/report.pdf

# 4. Inspect drafts
gmail-local drafts list --limit 5
gmail-local drafts get <draft-id>

# 5. Guarded transmission via Manual Send Gate
# Interactive execution (prompts operator for confirmation):
gmail-local send --draft <fingerprint_or_draft_id>

# Scripted execution (requires explicit confirmation flag):
gmail-local send --draft <fingerprint_or_draft_id> --confirm

# 6. Revoke transmission token and clear Keychain
gmail-local compose-revoke
```

### Modification & Cleanup Operations (`gmail.modify`)

```bash
# 1. Check modification connection status
gmail-local modify-status

# 2. Authenticate modification (system browser with PKCE flow)
gmail-local modify-login

# 3. Generate a staged cleanup plan (Dry-Run, non-destructive)
# Trash (soft delete) newsletters older than 30 days
gmail-local cleanup plan --query "category:promotions older_than:30d" --action trash --limit 50

# Archive notifications
gmail-local cleanup plan --query "from:noreply@app.com is:unread" --action archive --limit 20

# 4. Preview targets and verify plan fingerprint
gmail-local cleanup preview <plan-fingerprint>

# 5. Apply plan under Manual Modify Gate
# Interactive execution (prompts operator for confirmation):
gmail-local cleanup apply --plan <plan-fingerprint>

# Scripted execution (requires explicit confirmation flag):
gmail-local cleanup apply --plan <plan-fingerprint> --confirm

# 6. Reversible rollback: restore message from Trash back to mailbox
gmail-local cleanup untrash <message-id>

# 7. Revoke modification token and clear Keychain
gmail-local modify-revoke
```

### Autonomous AFK Inbox Triage (`triage`)

Designed for large mailboxes (>100k messages). Analyzes message headers, enforces zero false-positive protection for sensitive messages (financial, receipts, 2FA, travel, personal), and partitions candidate mutations into fingerprinted `CleanupPlan` bundles (<= 75 items/bundle, per ADR 0013):

```bash
# 1. Non-destructive scan: evaluate candidate messages and view category breakdown
gmail-local triage scan --query "in:inbox" --limit 50

# 2. Generate partitioned staged plans for trash candidates
gmail-local triage plan --query "in:inbox" --limit 50 --action trash

# 3. Generate partitioned staged plans for archive candidates
gmail-local triage plan --query "in:inbox" --limit 50 --action archive

# 4. Preview and confirm execution via Manual Modify Gate
gmail-local cleanup preview <plan-fingerprint>
gmail-local cleanup apply --plan <plan-fingerprint> --confirm
```

### Calendar & Meet Operations (`calendar.events.owned`)

Creates events on the operator's primary calendar, optionally provisioning a Google Meet
conference through Calendar `events.insert` with `conferenceDataVersion=1`. Conference
creation is asynchronous, so a `pending` conference is polled with bounded backoff before
the Meet link is reported (ADR 0014).

```bash
# 1. Check calendar connection status
gmail-local calendar-status

# 2. Authenticate calendar (system browser with PKCE flow)
gmail-local calendar-login

# 3. Preview an event (dry-run handoff, nothing is created)
gmail-local calendar-event preview \
  --summary "Design Review" \
  --start 2026-09-22T10:00:00-07:00 \
  --end 2026-09-22T10:35:00-07:00 \
  --timezone America/Los_Angeles

# 4. Create the event under the Manual Action Gate
# --attendee is repeatable, max 10 total; --meet provisions a Google Meet link
gmail-local calendar-event create \
  --summary "Design Review" \
  --start 2026-09-22T10:00:00-07:00 \
  --end 2026-09-22T10:35:00-07:00 \
  --timezone America/Los_Angeles \
  --description "Walk through the v2 architecture." \
  --attendee alice@example.com \
  --attendee bob@example.com \
  --meet \
  --confirm

# Attendees are NOT emailed unless you opt in explicitly:
#   --send-updates none (default) | externalOnly | all

# 5. Revoke calendar token and clear Keychain
gmail-local calendar-revoke
```

---

## Hardening & Security Evaluations

Run the comprehensive unit test suite and security evaluation benchmarks:

```bash
# Run the full suite (unit, property, security, and triage policy evals)
.venv/bin/pytest

# Run dedicated evaluation benchmark runner
.venv/bin/python evals/run_evals.py
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
