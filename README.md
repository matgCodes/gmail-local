# Gmail Local Integration (`gmail-local`)

A locally operated, read-only Gmail capability providing least-privilege search, message reading, and attachment downloads for personal Gmail accounts.

Governed by [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md) and [AGENTS.md](AGENTS.md).

---

## Security Boundaries & Guarantees

1. **Strict Read-Only Scope:** Requests only `https://www.googleapis.com/auth/gmail.readonly`. It exposes no send, modify, label, trash, delete, settings, or administration operations.
2. **Credential Isolation:** Refresh tokens are stored directly in **macOS Keychain** (`service="gmail-local-retrieval"`), never in plain text, environment variables, logs, or source control.
3. **Disclosure Ceilings:**
   * **Search Bound:** Header-only results (Date, From, To, Subject, ID); default 10, hard ceiling of 75.
   * **Read Bound:** Maximum 10 messages and 1 MiB (1,048,576 bytes) aggregate decoded body text per read. Overflows are discarded immediately with no partial leakage.
   * **Attachment Bound:** Maximum 25 MiB per file, 50 MiB aggregate. Explicit destination required, overwrite strictly forbidden, atomic writes with immediate cleanup on failure.
4. **Service Protection:** Rolling budget of 3,000 quota units / 60s (50% of Google's per-user rate limit), max 4 concurrent requests in flight, truncated exponential backoff with jitter.
5. **Local Rotating Audit Log:** Append-only log at `~/.local/state/gmail-local/audit.log` (mode `0600`) rotated at 5 MiB. Logs timestamps, operations, message IDs, and filenames; never logs message bodies or credentials.

---

## Installation & Testing

```bash
# Virtual environment setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run test suite (18 tests, 100% offline mock execution)
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
   * App name: `Gmail Local Reader`.
   * User support email & Developer contact: `your-email@gmail.com`.
   * Scopes: Add `https://www.googleapis.com/auth/gmail.readonly`.
   * Test Users: Add `your-email@gmail.com`.
4. **Create OAuth Client ID:**
   * Go to **APIs & Services > Credentials > Create Credentials > OAuth client ID**.
   * Application type: **Desktop app**.
   * Name: `Gmail Local Desktop Client`.
   * Download the JSON credentials.
5. **Install Secrets Locally:**
   ```bash
   mkdir -p ~/.config/gmail-local
   mv ~/Downloads/client_secret_*.json ~/.config/gmail-local/client_secret.json
   chmod 600 ~/.config/gmail-local/client_secret.json
   ```

---

## CLI Usage

```bash
# 1. Check connection status
gmail-local status

# 2. Authenticate (launches system browser with PKCE flow)
gmail-local login

# 3. Search messages (headers only)
gmail-local search "from:court is:unread" --limit 10

# 4. Preview short snippets for candidate IDs
gmail-local preview <message-id-1> <message-id-2>

# 5. Read full messages (max 10 msgs, max 1 MiB aggregate body)
gmail-local read <message-id-1>

# 6. List attachments
gmail-local attachments <message-id-1>

# 7. Download attachment safely (pass a directory to preserve original filename & extension)
gmail-local download <message-id-1> <attachment-id> --dest ~/Downloads/
# Or specify an explicit target filepath:
gmail-local download <message-id-1> <attachment-id> --dest ~/Downloads/custom_name.png

# 8. List mailbox labels (system and user folders)
gmail-local labels

# 9. Inspect conversation thread
gmail-local thread <thread-id>

# 10. Check incremental history changes
gmail-local history <start-history-id>

# 11. Revoke token and clear Keychain
gmail-local revoke
```

---

## Hardening & Security Evaluations

Run the comprehensive unit test suite and security evaluation benchmarks:

```bash
# Run all 68 unit tests & security evals
.venv/bin/pytest tests evals

# Run dedicated benchmark runner
.venv/bin/python evals/run_evals.py
```
