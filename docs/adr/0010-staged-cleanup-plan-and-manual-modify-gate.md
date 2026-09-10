# Staged Cleanup Plan fingerprinting, soft-delete safety, and Manual Modify Gate enforcement

The Mailbox Modification & Cleanup Milestone enforces strict blast-radius controls, reversibility, and human verification before any mailbox mutation or deletion:

1. **Cryptographic Cleanup Plan Fingerprinting:** Mailbox modification and inbox cleanup operations produce an immutable `CleanupPlan` structure. A deterministic SHA-256 fingerprint is computed across canonically sorted and normalized target messages (message IDs, actions, label deltas). Any subsequent alteration to candidate IDs or target actions invalidates the fingerprint.

2. **Reversible Soft-Delete Over Permanent Deletion:** Unrecoverable permanent deletion (`users.messages.delete` under `https://mail.google.com/`) is strictly prohibited. All deletion actions must use `users.messages.trash` under `https://www.googleapis.com/auth/gmail.modify`. This guarantees that all trashed messages are retained in the user's Gmail Trash for 30 days and can be restored via the Gmail web interface or the `gmail-local cleanup untrash <message-id>` command.

3. **Non-Interactive Manual Modify Gate:** An AI assistant may execute read-only queries, suggest categorization rules, assemble cleanup candidates, and stage a `CleanupPlan`, but is strictly forbidden from executing mutations autonomously. Mailbox modification via the CLI (`gmail-local cleanup apply`) requires Operator intervention:
   - In an interactive terminal, the CLI presents the plan summary, candidate count, sample subject lines, action type, and fingerprint, requiring explicit terminal confirmation (`yes`).
   - In non-interactive or scripted environments, execution requires the explicit `--confirm` flag bound to the plan fingerprint. Non-interactive invocations without `--confirm` terminate with an immediate security exit.

4. **Hard Batch Bounds:** To eliminate the risk of bulk inbox wiping caused by malformed queries or AI hallucination, a hard ceiling of 50 messages per cleanup operation is strictly enforced by the data model and API client.

5. **Tripartite Credential Separation:** In accordance with ADR 0003 and ADR 0004, modification authorization uses a distinct Desktop OAuth client secret (`client_secret_modify.json`) and macOS Keychain entry (`gmail-local-modify`) scoped exclusively to `https://www.googleapis.com/auth/gmail.modify`. The retrieval (`gmail-local-retrieval`) and transmission (`gmail-local-transmission`) credentials are never modified or granted modify access.
