# Gmail Local Integration (`gmail-local`)

A locally operated, read-only Gmail capability providing least-privilege search, message reading, and attachment downloads for personal Gmail accounts.

Governed by [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md), [WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md](WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md), and [AGENTS.md](AGENTS.md).

---

## Security Boundaries & Guarantees

1. **Strict Read-Only Retrieval Scope:** Requests only `https://www.googleapis.com/auth/gmail.readonly` for retrieval tasks. It exposes no send, modify, label, trash, delete, settings, or administration operations.
2. **Strict Credential Separation (ADR 0003 & 0004):** Outbound transmission uses an isolated OAuth grant with `https://www.googleapis.com/auth/gmail.compose`, a separate desktop client secret (`client_secret_transmission.json`), and a separate macOS Keychain service (`service="gmail-local-transmission"`). The retrieval credential is never upgraded.
3. **Cryptographic Frozen Drafts (ADR 0009):** Outbound emails are packaged into immutable `FrozenDraft` containers with deterministic canonical JSON hashing and SHA-256 fingerprinting. Any change to headers, body, or attachment digests invalidates the fingerprint.
4. **Manual Send Gate:** AI agents cannot autonomously transmit messages. Outbound transmission via `gmail-local send` requires explicit human operator authorization via an interactive confirmation prompt or the explicit `--confirm` flag in scripted environments. Non-interactive invocations without `--confirm` fail immediately with exit code 1.
5. **TOCTOU Tamper Protection:** Attachments are re-verified on disk against their recorded SHA-256 digests immediately before dispatch to prevent Time-of-Check to Time-of-Use file tampering.
6. **Disclosure & Transmission Ceilings:**
   * **Search Bound:** Header-only results (Date, From, To, Subject, ID); default 10, hard ceiling of 75.
   * **Read Bound:** Maximum 10 messages and 1 MiB (1,048,576 bytes) aggregate decoded body text per read.
   * **Attachment Download Bound:** Maximum 25 MiB per file, 50 MiB aggregate. Explicit destination required, overwrite forbidden.
   * **Transmission Bound:** Maximum 10 total recipients (`To`, `Cc`, `Bcc`), maximum 1 MiB body text, maximum 25 MiB per attachment, 50 MiB aggregate. CRLF characters (`\r`, `\n`), null bytes (`\0`), and recipient delimiter injections (`,`, `;`) are strictly rejected.
7. **Service Protection:** Rolling budget of 3,000 quota units / 60s (50% of Google's per-user rate limit), max 4 concurrent requests in flight, truncated exponential backoff with jitter.
8. **Local Rotating Audit Log:** Append-only log at `~/.local/state/gmail-local/audit.log` (mode `0600`) rotated at 5 MiB. Logs timestamps, operations, message IDs, draft IDs, and fingerprints; never logs message bodies or credentials.

---

## Installation & Testing

```bash
# Virtual environment setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run test suite (165 tests, 100% offline mock execution)
pytest -v
```

---

## Google Cloud Console Setup (One-Time)

To connect to your personal Gmail account:

1. **Create/Select Project:** Go to [Google Cloud Console](https://console.cloud.google.com/) and create a project (e.g., `gmail-local-tools`).
2. **Enable Gmail API:** Go to **APIs & Services > Library**, search for **Gmail API**, and click **Enable**.
3. **Configure OAuth Consent Screen:**
   * Go to **APIs & Services > OAuth consent screen**.
   * User Type: **External**.
   * App name: `Gmail Local Tools`.
   * User support email & Developer contact: `your-email@gmail.com`.
   * Scopes: Add `https://www.googleapis.com/auth/gmail.readonly` (Retrieval) and `https://www.googleapis.com/auth/gmail.compose` (Transmission).
   * Test Users: Add `your-email@gmail.com`.
4. **Create OAuth Client IDs (Desktop app):**
   * Retrieval Client: `Gmail Local Desktop Client` -> download to `~/.config/gmail-local/client_secret.json`
   * Transmission Client: `Gmail Local Transmission Desktop Client` -> download to `~/.config/gmail-local/client_secret_transmission.json`
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

---

## Hardening & Security Evaluations

Run the comprehensive unit test suite and security evaluation benchmarks:

```bash
# Run all 165 tests (147 unit + 18 security evals)
.venv/bin/pytest

# Run dedicated evaluation benchmark runner
.venv/bin/python evals/run_evals.py
```

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
