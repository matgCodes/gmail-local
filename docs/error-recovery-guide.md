# Gmail Local Error Recovery Guide

This guide provides troubleshooting paths and root-cause explanations for every common error state in `gmail-local`.

---

## 1. Authentication & OAuth Errors

### `MissingClientSecretError`
* **Symptoms:** CLI outputs `OAuth client configuration not found at ~/.config/gmail-local/client_secret.json`.
* **Root Cause:** The Google Cloud Desktop OAuth JSON credentials file has not been copied into place.
* **Resolution:**
  ```bash
  mkdir -p ~/.config/gmail-local
  cp ~/Downloads/client_secret_*.json ~/.config/gmail-local/client_secret.json
  chmod 600 ~/.config/gmail-local/client_secret.json
  ```

### `MissingTokenError`
* **Symptoms:** CLI outputs `No refresh token found in Keychain for service 'gmail-local-retrieval'`.
* **Root Cause:** The tool has not yet completed the one-time interactive browser login flow.
* **Resolution:** Run `.venv/bin/gmail-local login` and complete Google OAuth consent in your browser.

### `Error 403: access_denied (App has not completed Google verification process)`
* **Symptoms:** During browser login, Google shows an orange warning and blocks login with `Error 403: access_denied`.
* **Root Cause:** The Google Cloud project is in **Testing** mode, and your account email was not added to the **Test Users** allowlist.
* **Resolution:**
  1. Open [Google Cloud OAuth Consent Screen](https://console.cloud.google.com/apis/credentials/consent).
  2. Scroll down to **Test users** $\rightarrow$ click **+ ADD USERS**.
  3. Enter `your-account@gmail.com` $\rightarrow$ click **Save**.
  4. Rerun `.venv/bin/gmail-local login`.

### `invalid_grant` / Token Revoked
* **Symptoms:** API calls fail with `invalid_grant` or `Token has been expired or revoked`.
* **Root Cause:** User changed Google account password, revoked permissions in Google Account Security, or the 7-day testing token expired.
* **Resolution:** Run `.venv/bin/gmail-local login` to obtain a fresh refresh token.

---

## 2. API & Quota Errors

### `HttpError 403: accessNotConfigured (Gmail API has not been used in project ...)`
* **Symptoms:** API call fails with message stating Gmail API is disabled.
* **Root Cause:** The Gmail API service is not enabled in the active Google Cloud project.
* **Resolution:** Click the direct link provided in the error message (or search "Gmail API" in Google Cloud Library) and click **ENABLE**.

### `RateLimitExceededError: Rolling 60s budget exceeded`
* **Symptoms:** CLI raises `Rolling 60s budget exceeded: requested 20 units, currently at 3000/3000 units`.
* **Root Cause:** The application-level rate limiter prevents consuming more than 3,000 quota units in any rolling 60-second window (50% of Google's 6,000 unit/min user quota).
* **Resolution:** Wait 15–30 seconds for earlier requests to roll off the window and re-dispatch. Avoid running repeated `--limit 75` searches back-to-back.

### `RequestDeadlineExceededError: Retry deadline of 60s exceeded`
* **Symptoms:** Multiple HTTP 429 or 503 transient errors exhausted the 60-second retry deadline.
* **Root Cause:** Google servers are under heavy load or rate-limiting concurrent requests across all clients for this user.
* **Resolution:** Pause execution for 60 seconds before retrying the query.

---

## 3. Retrieval & File Handling Errors

### `OverwriteError: Target file already exists`
* **Symptoms:** `gmail-local download` fails with `Target file already exists: /path/to/file`.
* **Root Cause:** Strict security policy prevents silently overwriting existing local files.
* **Resolution:** Specify a new target filename or move/archive the existing local file first.

### `RetrievalBoundError: Body size ...B would exceed 1MiB limit`
* **Symptoms:** `get_messages` stops retrieving and audit log shows status `HELD_OVERFLOW`.
* **Root Cause:** Aggregate decoded message bodies reached the 1 MiB (1,048,576 bytes) privacy ceiling. The held message was discarded immediately to prevent partial leakage.
* **Resolution:** Split large batch reads into single-message reads:
  ```bash
  # Instead of reading 10 messages at once:
  .venv/bin/gmail-local read <id1>
  .venv/bin/gmail-local read <id2>
  ```

### `RetrievalBoundError: Attachment size exceeds 25 MiB limit`
* **Symptoms:** Download rejected because attachment size exceeds 25 MiB single-file limit.
* **Root Cause:** The attachment exceeds the standard Attachment Download Bound.
* **Resolution:** A one-time exception requires explicit Operator agreement detailing the file and destination before modifying bounds.

### `HTTP 404: History ID Expired`
* **Symptoms:** CLI outputs `History ID '...' has expired (HTTP 404). A full mailbox sync is required.`
* **Root Cause:** Gmail retains history records for approximately 30 days. Queries with `startHistoryId` older than this window cannot provide incremental changes.
* **Resolution:** Establish a fresh synchronization baseline by executing a bounded search query (e.g., `gmail-local search "newer_than:14d"`), recording the current latest history checkpoint, and resuming incremental sync from there.

### `HTTP 404: Requested entity was not found`
* **Symptoms:** Message read or thread inspection fails with HTTP 404.
* **Root Cause:** The requested message or thread ID was permanently purged from Trash/Spam, or the ID was mistyped.
* **Resolution:** Verify the ID using `gmail-local search` or check if the message was moved to Trash (`in:trash`).
