# ADR 0016: Read-Only Availability Grant for freeBusy

## Context & Problem Statement
The book-a-meeting skill (`docs/book-meeting-skill-design.md`, issue #9) needs to read the Operator's free/busy availability without a manual gate, so it can suggest open windows next to the booking-page links. No shipped grant can do that safely:

- `freebusy.query` accepts only `calendar.readonly`, `calendar`, `calendar.events.freebusy`, or `calendar.freebusy`. The Calendar Grant's `calendar.events.owned` (ADR 0014) is not on that list.
- An unattended availability lookup must never load a write-capable token.

## Decision Drivers
1. **Least Privilege:** the credential used without a gate carries no write scope and sees no event content.
2. **Credential Isolation:** follow the one-client-per-grant pattern of ADR 0003, 0004, 0010, and 0014.
3. **Independent Revocation:** revoking availability must not revoke calendar writes, and the reverse.
4. **Verifiable Scope:** a token that carries more than was requested is never stored.

## Architectural Decisions

1. **Separate Availability Grant (design option L1):**
   - Scope: `https://www.googleapis.com/auth/calendar.freebusy` only ("View your availability in your calendars").
   - macOS Keychain Service: `gmail-local-availability`.
   - Client Secret: `~/.config/gmail-local/client_secret_availability.json` (`0600` permissions), from its own Desktop OAuth client. There is no fallback to another grant's client secret, unlike the Calendar Grant's `client_secret_meet.json` fallback.
   - Commands: `gmail-local availability-login`, `availability-status`, `availability-revoke`, mirroring the `calendar-*` commands.
   - The grant is read-only and has no manual gate. It is never combined with the Retrieval, Transmission, Modification, or Calendar grants.

2. **Adding `calendar.freebusy` to the Calendar Grant (option L2) is rejected:**
   - Every unattended availability lookup would load a token that can create events and Meet links.
   - Revoking one capability would revoke both.
   - It would amend ADR 0014 decision 1 and force a re-consent. This ADR leaves ADR 0014's text unchanged; the Availability Grant is additive.

3. **Reusing the Calendar client's secret is rejected:** it saves one setup step but breaks the one-client-per-grant pattern and would make the granted-scope check depend on Google's token behavior for a client that already holds a write grant.

4. **Granted-Scope Check after login:**
   - After the OAuth flow returns, the granted scopes must equal the requested scopes exactly. Any difference (an extra scope, a missing scope, or no scope reported) discards the token, stores nothing in the Keychain, and fails the login with `ScopeMismatchError` and a non-zero exit.
   - The check has two paths. By default `oauthlib` already aborts the token exchange when the returned scope differs from the request, but it raises a bare `Warning` that escaped the CLI as a raw traceback. That is now converted into the governed error. When `OAUTHLIB_RELAX_TOKEN_SCOPE` is set, `oauthlib` lets the token through, so the credentials' `granted_scopes` are compared explicitly; that comparison cannot be disabled by the environment.
   - The discarded token is not revoked remotely. The over-scoped grant stays visible on the Operator's Google Account permissions page as evidence for finding the cause.
   - The check is scoped to this grant. Applying it to the shared login path would change the failure behavior of `compose-login`, and the Transmission lane is out of scope for this decision.

5. **Project Boundary:** the Availability Grant's Desktop client is a fifth client in the shared Google Cloud project and joins the open project-boundary question in issue #5 (ADR 0015, pending). If #5 moves calendar-family clients to their own project, this client moves with the Calendar Grant.

6. **Keychain Naming:** `gmail-local-availability` follows the existing service names. Per issue #4, service names are not renamed, because renaming orphans stored tokens.

## Exit Condition
Any availability token observed to carry a write scope ends this decision until the cause is found.

## Consequences
- One more Desktop client, client secret, consent, and Keychain entry for the Operator to maintain.
- The availability read path (`availability windows`, issue #11) can run without a gate because the only token it loads cannot write.
- A live check that `freebusy.query` succeeds and `events.insert` fails with 403 needs separate authorization (design section 13, gate C).
