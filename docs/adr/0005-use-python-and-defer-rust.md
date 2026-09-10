# Use Python for both milestones and defer Rust

Use Python for both the Retrieval Milestone and Transmission Milestone because Google's maintained Gmail and OAuth libraries, current command-line examples, and Python's standard email support reduce custom security-sensitive integration work. Rust remains a deliberate future option if the project later requires a signed Sender, binary-specific Keychain restrictions, mechanically enforced user presence, or long-lived single-binary distribution.

## Considered Options

- An all-Rust implementation is feasible and would strengthen compile-time capability boundaries, immutable draft modeling, error handling, and binary distribution, but Google does not provide an official Rust Gmail client or quickstart.
- The generated [`google-gmail1`](https://docs.rs/google-gmail1/latest/google_gmail1/) client was not selected because its [`google-apis-rs`](https://github.com/Byron/google-apis-rs) generator is in maintenance mode and seeking a new maintainer.
- A mixed Python/Rust first version was rejected because two toolchains and a cross-language Frozen Draft contract add complexity without making the current Manual Send Gate mechanically enforceable.

## Rust Revisit Guidance

If Rust is reconsidered, prefer an all-Rust workspace with separately compiled reader, draft, and sender binaries over an FFI add-on. Evaluate a narrow typed Gmail REST adapter, the maintained [`oauth2`](https://docs.rs/oauth2/latest/oauth2/) crate with an explicitly verified PKCE `S256`, state, system-browser, and random-loopback flow, [`keyring-rs`](https://github.com/open-source-cooperative/keyring-rs), and maintained MIME parsing and building crates; do not assume Rust alone solves recipient authorization, prompt injection, ambiguous sends, token scope, retention, or human presence.

## Consequences

The Python implementation must use explicit data models, type checking, an isolated environment, locked dependencies, and comprehensive tests. Google's quickstart-style plaintext token files are prohibited; the two refresh credentials remain in separate macOS Keychain entries.
