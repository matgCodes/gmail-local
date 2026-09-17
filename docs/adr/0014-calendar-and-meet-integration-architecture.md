# ADR 0014: Google Calendar Event Creation, Meet Provisioning, and Manual Action Gate Architecture

## Context & Problem Statement
Users and AI agents need the ability to schedule calendar events and generate Google Meet video conference links locally without exposing credentials, leaking confidential attendee/agenda details into logs, or creating duplicate calendar events upon network retries.

## Decision Drivers
1. **Least Privilege & Credential Isolation:** Never bundle calendar write permissions with Gmail retrieval, transmission, or mailbox modification grants (ADRs 0003, 0004, 0010).
2. **Standardized Meet Provisioning:** Leverage Google Calendar API v3's atomic conference provisioning (`conferenceData.createRequest`) rather than introducing the Google Meet REST API (`meet.googleapis.com`), which is reserved for active meeting space management and moderation.
3. **Network Idempotency & Deduplication:** Guard against double-booking and orphan meeting rooms caused by network retries.
4. **Manual Action Gate:** Prevent autonomous, unconfirmed calendar mutations and external attendee invitations by agents.
5. **Zero-Leak Privacy:** Ensure event descriptions, attendee email addresses, join links, and OAuth tokens never leak into local audit logs.

## Architectural Decisions

1. **Dedicated Least-Privilege Scope & Keychain Isolation:**
   - Scope: `https://www.googleapis.com/auth/calendar.events.owned` (restricts access strictly to events on calendars owned by the authenticated user).
   - macOS Keychain Service: `gmail-local-calendar`.
   - Client Secrets: Primary `~/.config/gmail-local/client_secret_calendar.json` with fallback to `~/.config/gmail-local/client_secret_meet.json` (`0600` permissions).
   - Under no circumstances may calendar scopes be combined with Gmail retrieval (`gmail-local-retrieval`), transmission (`gmail-local-transmission`), or modification (`gmail-local-modify`) tokens.

2. **Google Calendar API v3 as Meet Space Provisioner:**
   - Invokes `calendar.events.insert` with query parameter `conferenceDataVersion=1`.
   - Event creation payload populates `conferenceData.createRequest` with `conferenceSolutionKey.type: "hangoutsMeet"` and a unique client-generated `requestId` (`req-<uuid>`).
   - If Google's conference generation returns `statusCode: "pending"`, the client enters a bounded exponential backoff polling loop querying `events.get(calendarId="primary", eventId=..., conferenceDataVersion=1)` (schedule: `[0.5, 1.0, 2.0, 4.0]` seconds, max ~7.5s) before surfacing any failure.

3. **Deterministic Base32hex Idempotency Engine:**
   - Event IDs are client-generated using RFC 4648 Base32hex encoding (`[a-v0-9]{5,64}`) derived from a canonical SHA-256 fingerprint of normalized event fields (`summary`, `start`, `end`, `timezone`, sorted attendee emails, `has_meet`).
   - Network retries that result in `HTTP 409 Conflict` trigger an automatic `events.get` retrieval, resolving the existing event resource and Meet URL without creating duplicates.

4. **Interactive Manual Action Gate:**
   - External event creation has immediate side effects and may notify third-party attendees (`sendUpdates: none | externalOnly | all`).
   - Non-interactive invocations require the explicit `--confirm` flag. In interactive terminal environments, the user is presented with the complete event preview handoff block and prompted for explicit confirmation (`yes`).

5. **Zero-Leak Append-Only Audit Logging:**
   - Operations log sanitized `AuditEntry` records containing `timestamp`, `operation="calendar_event_create"`, `event_id`, `fingerprint`, and metadata counters (`start`, `end`, `timezone`, `attendee_count`, `has_meet`).
   - Strictly redacts and excludes event descriptions, attendee email addresses, Google Meet URLs, and OAuth tokens.
