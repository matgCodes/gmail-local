# Gmail Local Integration

A locally operated Gmail capability that lets one human operator retrieve selected mail and prepare outbound mail while retaining sole authority to transmit it.

## Actors

**Operator**:
The human who chooses the Gmail objective, selects messages and files, and alone authorizes transmission by independently running the sender.
_Avoid_: User, approver

**Drafting Agent**:
An AI agent that may refine operator-originated content and prepare a Frozen Draft but cannot authorize or perform transmission.
_Avoid_: Sender, approver

## Retrieval

**Search Objective**:
An Operator request limited to discovering Candidate Messages without authorizing full-content retrieval.
_Avoid_: Read request, Gmail lookup

**Search Bound**:
The Operator-chosen maximum number of header-level Candidate Messages a search may return; it defaults to 10 and has a Retrieval Milestone hard ceiling of 75.
_Avoid_: Read Bound, unlimited results

**Read Objective**:
An Operator request whose requested outcome requires full content from the intended message.
_Avoid_: Search request, blanket read

**Candidate Message**:
A bounded, header-level search result that has not yet become a Selected Message.
_Avoid_: Email result, selected email

**Message Preview**:
An explicitly requested, short body-derived excerpt for a Candidate Message; it is untrusted content rather than an explanation of why the message matched.
_Avoid_: Snippet, match explanation

**Unique Candidate**:
The sole Candidate Message matching an objective after the search establishes that no additional candidate exists.
_Avoid_: First result, single returned result

**Selected Message**:
A Candidate Message authorized for full-content retrieval either by explicit Operator selection or by being the Unique Candidate for a Read Objective.
_Avoid_: Open email, current email

**Selected Set**:
One or more explicitly named Candidate Messages authorized together for full-content retrieval under one Read Objective and one bounded read.
_Avoid_: All results, bulk mailbox read

**Read Bound**:
For one Operator-authorized read, no more than ten Selected Messages may be fully retrieved and no more than 1 MiB (1,048,576 bytes) of aggregate Decoded Message Body may be disclosed. Candidate metadata and attachment binaries are excluded, and attachment binaries remain separately gated.
_Avoid_: Result count, unlimited batch

**Decoded Message Body**:
The complete non-attachment textual content chosen for disclosure after MIME decoding, using one canonical representation rather than duplicating MIME alternatives; quoted reply text remains part of the content.
_Avoid_: Raw message, attachment data, HTML source

**Attachment Descriptor**:
Untrusted metadata identifying a file associated with a Selected Message without downloading the file.
_Avoid_: Attachment, downloaded file

**Selected Attachment**:
An attachment the Operator has chosen for download to an explicit destination under the Attachment Download Bound.
_Avoid_: Associated file, email file

**Attachment Download Bound**:
The ordinary per-read authority to download no Selected Attachment larger than 25 MiB and no Selected Attachment set larger than 50 MiB in aggregate. A separately authorized larger download names the exact attachment, destination, and temporary raised ceiling without changing the ordinary bound.
_Avoid_: Read Bound, Gmail limit, unlimited download

## Delivery

**Retrieval Milestone**:
The first authorized delivery stage, limited to proving bounded search, selected-message retrieval, selected-attachment download, and disconnection without transmission authority.
_Avoid_: Phase one, read-only prototype

**Transmission Milestone**:
The separately authorized delivery stage that adds Frozen Draft preparation and Operator-executed transmission only after the Retrieval Milestone is accepted.
_Avoid_: Phase two, send feature

## Authorization

**Retrieval Grant**:
The Operator's Gmail authorization limited to retrieval authority and never expanded to permit transmission.
_Avoid_: Read token, combined credential

**Transmission Grant**:
The Operator's separate Gmail authorization limited to transmitting Frozen Drafts after the Manual Send Gate.
_Avoid_: Send token, upgraded credential

## Transmission

**Frozen Draft**:
An immutable outbound message package whose recipients, subject, body, reply context, and attachment identities are bound to one fingerprint.
_Avoid_: Draft, final draft

**Send Handoff**:
The complete presentation of a Frozen Draft, its fingerprint, the stable sender's location and behavior, and the exact command the Operator may run.
_Avoid_: Approval request, send prompt

**Manual Send Gate**:
The boundary at which transmission becomes authorized only when the Operator independently executes the sender for a specific Frozen Draft.
_Avoid_: Confirmation, auto-send

**Sender**:
The stable local program that verifies and transmits one Frozen Draft after the Manual Send Gate.
_Avoid_: Generated script, Drafting Agent
