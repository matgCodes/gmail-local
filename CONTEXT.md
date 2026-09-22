# Gmail Local Integration

A locally operated Gmail and Calendar capability that lets one human operator retrieve selected mail, prepare outbound mail, triage and clean a large mailbox, and schedule events, while retaining sole authority over every write.

## Actors

**Operator**:
The human who chooses the objective, selects messages and files, and alone authorizes every write by independently executing the gated command.
_Avoid_: User, approver

**Drafting Agent**:
An AI agent that may refine Operator-originated content and stage work behind a gate, but cannot authorize or perform any write.
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

## Modification & Cleanup

**Modification Milestone**:
The separately authorized delivery stage that adds staged cleanup planning, label modification, and guarded soft-deletion after explicit Operator execution.
_Avoid_: Phase three, delete feature

**Modification Grant**:
The Operator's separate Gmail authorization limited to `gmail.modify` and never merged with retrieval or transmission credentials.
_Avoid_: Modify token, combined credential

**Cleanup Plan**:
An immutable mailbox mutation package whose query, target message IDs, and specific actions (trash, archive, label) are bound to one deterministic fingerprint.
_Avoid_: Bulk deletion script, cleanup queue

**Cleanup Target**:
One message named in a Cleanup Plan together with the action to be taken on it. A message in a Protected Category never becomes one.
_Avoid_: Victim, doomed message, deletion candidate

**Cleanup Handoff**:
The complete presentation of a Cleanup Plan, its fingerprint, affected message count and sample subjects, and the exact CLI command the Operator may run.
_Avoid_: Auto-clean trigger, deletion prompt

**Manual Modify Gate**:
The boundary at which mailbox mutations become authorized only when the Operator independently executes the cleanup command for a specific Cleanup Plan.
_Avoid_: Confirmation bypass, auto-scrub

**Soft Delete**:
Moving a targeted message to Gmail's Trash (`users.messages.trash`) where it is retained for 30 days and remains fully recoverable, as opposed to unrecoverable permanent deletion.
_Avoid_: Hard delete, purge, wipe

## Triage

**Triage Decision**:
The classification outcome for one Candidate Message: the category it falls in and the action that follows from it.
_Avoid_: Verdict, ruling, label

**Triage Category**:
The classification a Candidate Message is assigned from evidence in its headers alone.
_Avoid_: Label, folder, Gmail category

**Protected Category**:
A Triage Category whose messages can never become a Cleanup Target, covering financial, transaction, security, travel, personal, and legal or government correspondence.
_Avoid_: Important, starred, priority

**Sender Cluster**:
A group of Candidate Messages sharing one sending domain, treated as a unit when judging volume and intent.
_Avoid_: Sender group, conversation, thread

**Operator Override**:
An Operator-stated whitelist or blacklist entry for a sender that takes precedence over the inferred Triage Category.
_Avoid_: Rule, filter, exception

**Triage Manifest**:
The durable record of one triage run and the decisions it produced.
_Avoid_: Report, log, summary

## Calendar & Meet

**Calendar Milestone**:
The separately authorized delivery stage that adds event creation and Meet provisioning after the Modification Milestone.
_Avoid_: Phase four, scheduling feature

**Calendar Grant**:
The Operator's separate Google authorization limited to events on calendars the Operator owns, never merged with any Gmail credential.
_Avoid_: Calendar token, Google token, combined credential

**Calendar Event**:
A proposed or created entry on the Operator's own calendar, bound to one start, end, and timezone.
_Avoid_: Meeting, appointment, invite

**Attendee**:
A person named on a Calendar Event. Distinct from a transmission Recipient, who receives a Frozen Draft.
_Avoid_: Recipient, guest, participant

**Calendar Preview**:
The complete presentation of a proposed Calendar Event before the Manual Action Gate, which creates nothing.
_Avoid_: Draft event, tentative event, hold

**Manual Action Gate**:
The boundary at which event creation becomes authorized only when the Operator independently confirms a specific Calendar Preview.
_Avoid_: Confirmation, auto-create, auto-schedule

**Meet Conference**:
The Google Meet space bound to a Calendar Event. Its provisioning resolves after the event exists, so an event may be created without one.
_Avoid_: Meet link, hangout, video call
