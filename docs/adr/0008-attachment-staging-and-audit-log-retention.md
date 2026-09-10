# Attachment staging, atomic installation, and audit log retention

The Retrieval Milestone enforces strict disk isolation for downloaded attachments and runtime activity:

1. **Attachment Staging and Atomic Installation:** Every attachment download requires an explicit destination path (or an Operator-configured destination directory). The download stream writes to a temporary file in the target directory (`.<filename>.tmp.<pid>`) with permissions `0600`. The file is verified against the preflight decoded byte count and the 25 MiB single-file / 50 MiB aggregate Attachment Download Bound. The destination file is checked to ensure no overwrite occurs. Upon successful validation, the file is atomically renamed to the target filename. On any failure, cancellation, or limit violation, the temporary file is purged immediately.

2. **Audit Log Policy:** A local append-only audit log is maintained at `~/.local/state/gmail-local/audit.log` (mode `0600`), rotated when reaching 5 MiB, retaining at most 3 backups. The audit log records only: ISO-8601 timestamp, operator-stated purpose, Gmail operation, message ID, attachment filename, destination path, and completion status. It never logs message bodies, headers, HTML, tokens, or credentials.
