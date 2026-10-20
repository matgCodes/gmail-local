# ADR 0017: Explicit Account Selection and Login Identity Check

## Context & Problem Statement
The Operator is adding a second Google account (issue #18). Before this decision:

- The active account was only a Keychain label, resolved once at import from `GMAIL_ACCOUNT`, then `~/.config/gmail-local/account.txt`.
- Nothing compared that label with the Google account chosen on the consent screen. Picking the wrong account in the browser stored that account's token under the other label, and every later command for that label ran against the wrong mailbox without any warning.
- `status` reported the label, not the mailbox the token opened.
- Drafts, cleanup plans, triage reports, and the audit log shared one state directory and recorded no account.

## Decision Drivers
1. **No Hidden State:** which account a command acts as must be visible on the command and in its output.
2. **Fail Loudly:** a token for the wrong mailbox is never stored.
3. **No Change for One-Account Installs:** without `--account`, behavior matches the previous release.
4. **Writes Stay Safe During Rollout:** no write lane may act as a newly selected account until its artifacts record their account.

## Architectural Decisions

1. **Explicit `--account <address>`:**
   - Accepted before or after the subcommand. Giving it twice with different values is an error (exit 2).
   - Precedence: `--account`, then `GMAIL_ACCOUNT`, then `account.txt`. The existing default stays the default, and other accounts are always named explicitly.
   - When the flag names the default account in a different letter case, the default's original spelling is used, so the Keychain lookup still matches.

2. **A persistent switch (`gmail-local account use X`) is rejected:** a switch made earlier and then forgotten is the most likely way to send or modify as the wrong account.

3. **Aliases are deferred:** the full address is unambiguous, and an alias registry would add a second name for the same thing.

4. **Every command states its account:** `account: <address>` is printed to stderr before dispatch, so stdout stays parseable.

5. **Login Identity Check (Retrieval Grant):**
   - `login_hint=<address>` pre-selects the account on the consent screen. It is skipped for the `user@example.com` placeholder.
   - After consent, `users.getProfile` returns the mailbox address. It reads no message content. The address must match the label, compared case-insensitively.
   - On a mismatch, the new token is revoked and nothing is stored, and any token already stored for that label is left untouched. The login fails with `IdentityMismatchError` and names both addresses. If the revoke fails, the error tells the Operator to remove the app at Google Account permissions.
   - If the identity lookup itself fails, the token is revoked and not stored, and the login fails.
   - Unlike ADR 0016's scope check, which keeps an over-scoped grant visible as evidence, a mismatched token is revoked: it is a valid credential for a mailbox the Operator did not intend to connect.
   - `status` shows the verified mailbox for the Retrieval Grant and exits non-zero on a mismatch.

6. **Audit lines record the account:** each `AuditLogger` stamps `acct=<address>` at the end of every entry it writes. The log is local and `0600`.

7. **Phase 1 Guard:** until phase 2 of issue #18, only the read-only retrieval commands (`status`, `login`, `revoke`, `search`, `preview`, `read`, `attachments`, `download`, `history`, `thread`, `labels`) accept a non-default `--account`. Every other command refuses one (exit 2) instead of silently acting as the default account.

8. **Unchanged:** scopes, Keychain service names, client secret files, and the state directory layout. Tokens for different accounts already coexist, because the Keychain keys them by service and account label.

## Deferred to Phase 2 (issue #18)
- Recording the account in `FrozenDraft`, `CleanupPlan`, triage reports, and staged calendar events, and refusing to send or execute when it doesn't match.
- Identity checks for the Transmission and Modification grants.
- The Calendar and Availability grants have no identity endpoint within their scopes, and ADR 0016 forbids adding one to Availability.
- Removing the phase 1 guard.

## Consequences
- **Good:** a token can't be stored for the wrong mailbox through the retrieval login. The account in use is visible on every command and in the audit log.
- **Neutral:** `GMAIL_ACCOUNT` still selects an account for every lane, as before this decision. Phase 2 must land before any write-grant login on a second account.
- **Cost:** `login` and `status` make one extra `users.getProfile` call.
