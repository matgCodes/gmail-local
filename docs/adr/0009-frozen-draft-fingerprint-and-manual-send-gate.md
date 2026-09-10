# Cryptographic Frozen Draft fingerprinting and Manual Send Gate enforcement

The Transmission Milestone enforces strict immutability, tamper resistance, and human verification before message dispatch:

1. **Cryptographic Frozen Draft Fingerprinting:** Outbound email construction produces a `FrozenDraft` structure. A deterministic SHA-256 fingerprint is computed across the canonically sorted and normalized fields (recipients `To`, `Cc`, `Bcc`, subject, body text, HTML, and attachment hashes). Any subsequent modification to headers, body, or attachments invalidates the fingerprint.

2. **Non-Interactive Manual Send Gate:** The Drafting Agent (AI) can compose drafts, compute fingerprints, and optionally stage drafts to the Gmail user's Drafts folder (`users.drafts.create`), but is strictly forbidden from executing transmission. Transmission via the Sender (`gmail-local send`) requires Operator intervention:
   - In an interactive terminal, the Sender presents the full draft summary, recipient list, subject, and fingerprint, requiring explicit terminal confirmation (`yes`).
   - In non-interactive or scripted environments, transmission requires the explicit `--confirm` flag bound to the draft fingerprint. Non-interactive invocations without `--confirm` terminate with an immediate security exit.

3. **Transmission Credential Separation:** In accordance with ADR 0003 and ADR 0004, transmission authorization uses a distinct Desktop OAuth client secret (`client_secret_transmission.json`) and Keychain entry (`gmail-local-transmission`) scoped exclusively to `https://www.googleapis.com/auth/gmail.compose`. The retrieval credential (`gmail-local-retrieval`) is never modified or granted write access.
