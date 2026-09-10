# Keep retrieval and transmission credentials separate

The Retrieval Grant and Transmission Grant use distinct OAuth client profiles, refresh tokens, and macOS Keychain entries. The retrieval credential is never upgraded with Gmail send authority; the additional authorization setup preserves a narrow credential boundary between untrusted inbound processing and outbound transmission.
