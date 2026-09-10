# Wayfinder Ticket: Establish Read-Only Gmail API Access

**Status:** Completed (Retrieval Milestone Verified)  
**Type:** `wayfinder:task` with implementation and live verification complete  
**Created:** 2026-07-28  
**Verified:** 2026-09-10  
**Workspace:** `/path/to/Gmail-API`  
**Account:** `[REDACTED_USER_EMAIL]`  
**Credential status:** Verified. Google Cloud project configured; OAuth client type
Desktop app; refresh token stored in macOS Keychain (`gmail-local-retrieval`).
Live search, read, and attachment download tested and passed.

## Question

How should the Operator establish durable, least-privilege API access to the personal
Gmail account so an explicitly authorized local workflow can search messages,
read selected messages, and download selected attachments without send, modify,
delete, or mailbox-administration authority?

## Destination

A locally operated, auditable Gmail integration that:

- uses the Gmail API and the account owner's OAuth consent;
- requests only `https://www.googleapis.com/auth/gmail.readonly`;
- can search for a filing notice or other user-named message;
- can show a bounded result list and read only the selected result;
- can download only the selected attachment to a user-approved destination;
- stores refresh credentials in macOS Keychain or an equivalent OS credential
  store, never in the Documents tree or source control;
- exposes no send, modify, label, trash, delete, settings-change, or account-
  administration operation; and
- can be disconnected by revoking consent and deleting the local token.

Reaching this destination means the authorization and read-only retrieval path
has been implemented and tested. It does not mean background mailbox monitoring
or unrestricted agent access has been authorized.

## Relationship to the later Transmission Milestone

This ticket controls only the read-only Retrieval Milestone. The planned
Transmission Milestone remains separately authorized and must use its own
`gmail.send` client profile, refresh token, and Keychain entry; it must never
expand the Retrieval Grant. See `CONTEXT.md` and `docs/adr/` for the resolved
cross-milestone terminology and architecture decisions.

## Why this ticket exists

Chrome browser automation is currently prohibited from opening or inspecting
`mail.google.com` by an active browser privacy preference. The Operator separately asked
to investigate API read access to the Gmail account.

This API lane requires its own explicit OAuth consent and operating policy. It
must not be described or implemented as a browser-policy bypass. The browser
restriction remains in force for browser automation unless the Operator changes it in the
controlling product setting.

## Recommended route

Use a **local installed application** with three-legged OAuth:

1. Create or select a Google Cloud project dedicated to the personal Gmail
   reader.
2. Enable the Gmail API.
3. Configure Google Auth Platform with an **External** audience because the
   target is a consumer `@gmail.com` account.
4. Create an OAuth client of type **Desktop app**.
5. Request only `gmail.readonly` because message bodies and attachments are
   required. `gmail.metadata` is insufficient because it cannot retrieve
   message bodies and does not support the Gmail `q` search parameter.
6. Use the installed-application authorization-code flow in the system browser,
   with a loopback redirect, PKCE `S256`, and `state` validation.
7. Store the refresh token in macOS Keychain. Keep the downloaded client
   configuration and all token material outside Documents, repositories, logs,
   prompts, crash reports, and backups that are not approved for secrets.
8. Start with a small local CLI so authorization, query scope, attachment
   handling, and revocation are testable without an agent layer.
9. If repeated agent access is still desired after the CLI is accepted, wrap
   the same local implementation in a narrow MCP server. Do not expand the
   OAuth scope.
10. Prefer periodic or user-triggered polling. Do not add Cloud Pub/Sub push
    notifications unless a real always-on backend is separately justified.

## Proposed local tool surface

The first implementation should expose only these operations:

- `search_messages(query, max_results=10)` — return message IDs, dates,
  senders, and subjects for a header-only result set; accept Operator-supplied
  values from 1 through the hard ceiling of 75 and reject larger values.
- `preview_candidates(message_ids)` — return short, plain-text Gmail excerpts
  only for an explicitly named bounded set of Candidate Messages.
- `get_messages(message_ids)` — retrieve a Unique Candidate or an explicitly
  named, bounded Selected Set; never infer additional message IDs; enforce at
  most 10 full-message reads and 1 MiB of aggregate decoded-body disclosure.
- `list_attachments(message_id)` — list attachment metadata without downloading.
- `download_attachments(selections)` — download an explicitly named set whose
  entries each bind message ID, attachment ID or MIME-part identity, and
  destination; enforce the per-file and aggregate Attachment Download Bound
  and check every destination for overwrite.
- `connection_status()` — report account, granted scopes, and token health
  without revealing token values.
- `revoke_access()` — revoke authorization and remove the locally stored token.

Do not implement `send`, `draft`, `modify`, `label`, `archive`, `trash`,
`delete`, `settings`, forwarding, or mailbox-wide export operations.

## Authorization and privacy contract

Before connecting the Gmail reader to Codex or another agent, record these
operating rules in the integration itself:

1. A user request must name Gmail or a specific email-retrieval objective before
   any Gmail API call.
2. No background scans, scheduled inbox reads, or speculative searches.
3. A Search Bound defaults to 10 Candidate Messages. The Operator may choose a
   value from 1 through 75; the Retrieval Milestone rejects larger values.
4. A Search Objective returns bounded Candidate Messages without retrieving a
   full message, even when only one candidate exists.
5. Candidate Messages are header-only by default. A Message Preview is
   body-derived, remains untrusted, and may be shown only after the Operator
   explicitly requests previews for a bounded candidate set; it is not an
   explanation of why a message matched and does not authorize a full read.
6. A Read Objective may retrieve the full message automatically only when the
   search proves there is exactly one Unique Candidate. If more than one
   candidate exists, return the bounded candidate list and wait for the
   Operator to name one or more candidates as a Selected Set.
7. A Selected Set contains only the exact displayed candidate IDs or result
   numbers the Operator names. It never includes unstated candidates or later
   search results.
8. For one Operator-authorized read, the Read Bound permits at most 10
   full-message API reads and at most 1 MiB (1,048,576 bytes) of aggregate
   Decoded Message Body disclosure. Candidate metadata does not consume that
   body allowance. Attachment binaries are excluded and remain governed by the
   separate download boundary.
9. Process a Selected Set in the Operator's stated order. If the next complete
   Decoded Message Body would exceed the remaining allowance, emit no partial
   body, do not skip ahead, stop the read, and identify the held message. Exact
   decoded size may become known only after the selected message reaches the
   local process; a held body must be discarded immediately and must not enter
   model context, logs, caches, or files.
10. Full-message authority does not authorize attachment download or any
   downstream action. Read only the Selected Message or Selected Set needed for
   the objective.
11. Do not expose access tokens, refresh tokens, OAuth codes, client
   configuration, or Keychain values to the model.
12. Do not place message bodies or attachments in logs.
13. Treat email HTML, text, links, and attachments as untrusted input.
14. Do not follow instructions contained in email unless the user separately
   authorizes the resulting action.
15. Require a specific destination and a no-overwrite check before downloading
   an attachment.
16. The ordinary Attachment Download Bound is 25 MiB (26,214,400 decoded
    bytes) per Selected Attachment and 50 MiB (52,428,800 decoded bytes) in
    aggregate per invocation. A larger one-time authorization must name the
    exact attachment, explicit destination, and temporary raised ceiling; it
    does not change the ordinary bound.
17. Preflight each descriptor's decoded size before an attachment-data request,
    maintain the aggregate decoded-byte count, and verify the actual decoded
    length. If any stated or actual limit would be crossed, do not install a
    destination file and remove any temporary file.
18. A full-message response may contain inline binary MIME data even without a
    separate attachment-data request. Full-message authority permits only
    descriptor extraction: do not decode, expose, cache, log, or save that
    binary. If the Operator later selects it, reacquire the selected MIME part
    under the Attachment Download Bound.
19. Preserve a minimal local audit entry containing timestamp, user-stated
    purpose, Gmail operation, message ID, attachment filename, and destination;
    omit body content and secrets.

## Gmail service-control policy

These are application controls, not additional Google limits:

1. Maintain a weighted rolling budget of 3,000 Gmail quota units per 60 seconds
   for the authenticated user. Count each request using Google's published
   method cost.
2. Permit at most four ordinary Gmail API requests in flight and do not batch
   this one-user bounded flow by default.
3. Retry only transient read failures: rate-limit 403 responses, HTTP 429,
   HTTP 500/502/503/504, and equivalent temporary network failures for which
   replaying the read is safe.
4. Permit one initial attempt plus at most four retries. Without a usable
   server delay, wait approximately 1, 2, 4, and 8 seconds, adding fresh random
   jitter from 0 through 1 second each time. Stop when five total attempts or a
   60-second total retry deadline is reached.
5. Honor a Google-provided retry delay only when it fits inside the remaining
   60-second deadline; otherwise stop and return a resumable error rather than
   sleeping indefinitely. Pause new requests for that user during backoff.
6. After exhaustion, report the failed operation, affected selected item,
   completed earlier items, absence of further retrieval, and exact rerun
   command. Repeated concurrency-related 429 responses lower the four-request
   cap rather than increasing retries.
7. Do not use backoff for malformed requests, missing scope, nonexistent
   messages, or revoked authorization. A 401 permits one normal token-refresh
   path and then requires reauthorization if refresh fails.
8. These read-retry rules do not authorize later transmission retries. An
   ambiguous send requires reconciliation before another send attempt.

## Implementation work packets

### 1. Bind the implementation home — resolved

- The implementation home is `/path/to/Gmail-API`.
- The directory exists and currently contains this Wayfinder ticket.
- Do not build the implementation at the Documents root.
- Add the local repository's own `AGENTS.md`, secret-handling rules, and tests.
- Python is the chosen runtime for both the Retrieval Milestone and the later
  Transmission Milestone. This resolves the runtime decision only; it does not
  authorize scaffolding, implementation, OAuth, Gmail access, or transmission.

### 2. Configure Google Cloud and OAuth

- Create/select the project and enable Gmail API.
- Configure Branding, support email, developer contact, and External audience.
- During development, add the Gmail account as a test user.
- Create the Desktop app OAuth client and download its configuration directly
  into the approved secret/configuration location.
- Never commit that file.

### 3. Decide Testing versus In production

- **Testing** is acceptable for the initial prototype, but Google states that
  authorizations and refresh tokens expire after seven days when non-identity
  scopes such as Gmail scopes are requested.
- For durable personal use, evaluate moving the External app to **In
  production**. Google states that personal-use apps with fewer than 100 users
  may qualify for a verification exception, but the user may still receive an
  unverified-app warning and unverified apps retain a 100-new-user cap.
- Treat “External + In production + unverified for durable personal use” as a
  reasoned configuration inference from Google's rules, not as a separately
  named Google deployment tier. Confirm the live console behavior before
  depending on it.

### 4. Implement authorization and secure token storage

- Use a maintained Google auth/client library.
- Use system-browser authorization, a random loopback port, PKCE `S256`, and
  `state` validation.
- Request offline access so the code exchange returns a refresh token.
- Store the refresh token in macOS Keychain; access tokens remain short-lived.
- Handle revocation, `invalid_grant`, six months of non-use, password changes,
  token-count limits, and other refresh-token invalidation by returning to
  interactive authorization.
- Never print or serialize tokens into ordinary application logs.

### 5. Implement bounded mail retrieval

- Use `users.messages.list(userId="me", q=...)` for a bounded Gmail search.
- Page results deliberately; do not default to mailbox-wide enumeration.
- Use `users.messages.get` only for selected message IDs, with no more than 10
  full-message calls in one Operator-authorized read.
- Decode selected messages locally in the stated order and disclose no more
  than 1 MiB of aggregate Decoded Message Body. Emit no partial body and do not
  skip a held message to process later selections.
- Enforce the weighted quota budget, concurrency cap, retry count, retry
  deadline, jitter, and error classification defined above.
- Recursively inspect MIME parts and call
  `users.messages.attachments.get` only for a selected attachment.
- For inline attachment data already present in a full-message response, retain
  only the Attachment Descriptor until the Operator selects that MIME part;
  reacquire it under attachment-download authority rather than carrying the
  binary across the selection boundary.
- Preflight 25 MiB per-file and 50 MiB aggregate decoded-size limits. A one-time
  override binds the exact attachment, destination, and temporary raised
  ceiling and never alters defaults.
- Base64url-decode safely into a restricted temporary file; verify actual
  decoded length, sanitize filenames, reject path traversal, and atomically
  install only after all checks pass. Never overwrite an existing file and
  remove temporary output on every failure.
- Use `users.history.list` for later incremental polling if needed. An expired
  history ID requires a new bounded/full synchronization decision.

### 6. Test and review

- Unit-test MIME traversal, base64url decoding, safe filenames, no-overwrite
  behavior, token redaction, and query/result bounds without live credentials.
- Unit-test 25 MiB per-file and 50 MiB aggregate attachment boundaries,
  descriptor preflight, actual-size mismatch, exact one-time override binding,
  inline-binary nondisclosure and reacquisition, atomic installation, and
  temporary-file cleanup.
- Unit-test the 10-message limit, exact 1 MiB aggregate disclosure boundary,
  whole-body/no-skip behavior, and immediate disposal of a held body.
- With a fake clock and fake Gmail responses, test the 3,000-unit rolling
  budget, four-request concurrency cap, retryable error classes, 1/2/4/8-second
  jittered schedule, five-total-attempt limit, 60-second deadline, and
  non-retryable paths.
- Run one owner-controlled OAuth smoke test.
- Confirm the consent screen shows only `gmail.readonly`.
- Confirm the tool cannot send, modify, label, trash, delete, or change settings.
- Search for a user-named message, retrieve one result, and download one
  selected attachment into a temporary approved directory.
- Revoke access and confirm the local token is removed.
- Reauthorize and confirm the invalid/revoked-token path is understandable.

## Retrieval Milestone acceptance criteria

- [x] The implementation has a verified home at
      `/path/to/Gmail-API` outside Documents root.
- [x] The Google Cloud project and Gmail API enablement are recorded without
      placing secrets in the ticket.
- [x] OAuth audience is External and client type is Desktop app.
- [x] The only granted Gmail scope is `gmail.readonly`.
- [x] Authorization uses system browser, loopback redirect, PKCE `S256`, and
      state validation.
- [x] The refresh token is stored in macOS Keychain or equivalent secure storage.
- [x] No credential or token exists in Documents, source control, logs, prompts,
      or ordinary configuration files.
- [x] Search results are bounded and header-only by default; Message Previews
      require an explicit request, and full content is retrieved only after a
      specific Read Objective or selection.
- [x] The Search Bound defaults to 10, accepts Operator-supplied values from 1
      through 75, and rejects larger values.
- [x] Every Selected Set is constrained to at most 10 full-message reads and
      1 MiB of aggregate Decoded Message Body disclosure, with no partial body
      or skip-ahead when the next complete body does not fit.
- [x] Gmail calls remain within a 3,000-unit rolling 60-second application
      budget and four-request concurrency cap; retryable reads stop after five
      total attempts or 60 seconds.
- [x] Attachment downloads require an explicit destination, cannot overwrite
      an existing file, and remain within 25 MiB per file and 50 MiB aggregate
      unless a one-time authorization names the exact attachment, destination,
      and raised ceiling.
- [x] Inline attachment binaries returned during full-message retrieval are not
      disclosed, cached, logged, or saved without separate attachment selection.
- [x] The integration exposes no write-capable Gmail operation.
- [x] Email content is treated as untrusted and cannot authorize downstream
      actions by itself.
- [x] Revocation and reauthorization paths have been tested.
- [x] The operating policy for agent-triggered reads is documented and enforced.
- [x] A live test retrieves one authorized message and one selected attachment
      without reading unrelated messages (Verified 2026-09-10: read message
      1a089c4c56718b8b and downloaded attachment from message 1a086f77b8e7609e).

## Open decisions

1. Is a local CLI sufficient, or is a read-only MCP wrapper required after the
   CLI proves the authorization and privacy model?
2. Should the app remain in Testing with seven-day reauthorization during the
   prototype, then move to In production for durable personal use?
3. Attachment staging and audit log retention: Resolved in ADR 0008
   (atomic installation, no overwrite, ~/.local/state/gmail-local/audit.log).

## Out of scope

- Changing or bypassing the Chrome/Gmail browser privacy preference.
- Reading Gmail before the OAuth setup and privacy contract are approved.
- Service-account access to consumer Gmail. Service-account impersonation
  requires Google Workspace domain-wide delegation by a Workspace administrator
  and does not directly unlock a personal `@gmail.com` mailbox.
- Sending email or changing mailbox state during the Retrieval Milestone. The
  later Transmission Milestone remains separately gated and unauthorized by
  this ticket.
- Organization-wide or multi-user deployment.
- Cloud-hosted storage or processing of restricted Gmail data.
- Pub/Sub push infrastructure or continuous monitoring.
- Saving credentials, tokens, or message bodies in this ticket.

## Official Google sources

- [Gmail API Python quickstart](https://developers.google.com/workspace/gmail/api/quickstart/python)
- [Gmail OAuth scope catalog](https://developers.google.com/workspace/gmail/api/auth/scopes)
- [OAuth for desktop and installed applications](https://developers.google.com/identity/protocols/oauth2/native-app)
- [OAuth 2.0 policies](https://developers.google.com/identity/protocols/oauth2/policies)
- [OAuth security best practices](https://developers.google.com/identity/protocols/oauth2/resources/best-practices)
- [OAuth token expiration and refresh-token lifecycle](https://developers.google.com/identity/protocols/oauth2#expiration)
- [Manage Google Auth Platform audience and publishing status](https://support.google.com/cloud/answer/15549945)
- [When OAuth verification is not required](https://support.google.com/cloud/answer/13464323)
- [Restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification)
- [Google Workspace API user-data policy](https://developers.google.com/workspace/workspace-api-user-data-developer-policy)
- [Service-account OAuth and domain-wide delegation](https://developers.google.com/identity/protocols/oauth2/service-account)
- [`users.messages.list`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/list)
- [Search and filter Gmail messages](https://developers.google.com/workspace/gmail/api/guides/filtering)
- [`users.messages.get`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages/get)
- [`users.messages.attachments.get`](https://developers.google.com/workspace/gmail/api/reference/rest/v1/users.messages.attachments/get)
- [Synchronize Gmail clients](https://developers.google.com/workspace/gmail/api/guides/sync)
- [Gmail push notifications](https://developers.google.com/workspace/gmail/api/guides/push)
- [Gmail API usage limits](https://developers.google.com/workspace/gmail/api/reference/quota)

## Current resolution state

Official-source research and architecture grilling are complete (ADRs 0001–0008).
The implementation home is `/path/to/Gmail-API`.
Python is the chosen runtime. The Operator authorized scaffolding and
test-driven implementation. Live OAuth consent, Google Cloud project creation,
and live credential access have been completed and verified against the user's
personal mailbox (`[REDACTED_USER_EMAIL]`).

The Retrieval Milestone is fully completed and verified:
1. Core CLI (`gmail-local`) provides `status`, `login`, `search`, `preview`, `read`, `attachments`, `download`, `labels`, `history`, and `thread`.
2. All hard security and privacy boundaries (75 search ceiling, 10 read ceiling, 1 MiB aggregate body discard, 25 MiB single / 50 MiB aggregate attachment download, no-overwrite, 3,000 units/60s rolling rate limit, 4 concurrency) are strictly enforced.
3. Automated test suite and security evaluation benchmarks (`evals/run_evals.py`) feature 68 automated unit tests and adversary evals, verifying zero-secret leakage, prompt injection isolation, directory traversal sanitization, and quota protection.
