# Gmail Local Integration Architecture

Each capability runs on its own OAuth grant, its own client secret, and its own
Keychain entry, and every write is held behind a manual gate the Operator must
execute. See `docs/adr/` for the governing decisions.

```mermaid
flowchart TD
    %% 1. Auth & Credentials
    subgraph Auth ["1. Auth & Credential Isolation (ADR 0003, 0004)"]
        GCP["Google Cloud Project (External)"] --> ClientRead["Client A: Retrieval (gmail.readonly)"]
        GCP --> ClientSend["Client B: Transmission (gmail.compose)"]
        GCP --> ClientMod["Client C: Modification (gmail.modify)"]
        GCP --> ClientCal["Client D: Calendar (calendar.events.owned)"]
        ClientRead --> PKCE["Loopback + PKCE S256"]
        ClientSend --> PKCE
        ClientMod --> PKCE
        ClientCal --> PKCE
        PKCE --> KeyRead[("Keychain: gmail-local-retrieval")]
        PKCE --> KeySend[("Keychain: gmail-local-transmission")]
        PKCE --> KeyMod[("Keychain: gmail-local-modify")]
        PKCE --> KeyCal[("Keychain: gmail-local-calendar")]
    end

    %% 2. Retrieval Pipeline
    subgraph Retrieval ["2. Retrieval Milestone"]
        Operator["Operator Input"] --> Search["search_messages(query, max=10..75)"]
        Search --> Candidates["Candidate Messages (Headers Only)"]
        Candidates --> EvalCount{"Candidate Count"}
        EvalCount -- "Exactly 1 (Read Objective)" --> ReadMsg["get_messages(id)"]
        EvalCount -- "Multiple Matches" --> PickMsg["Operator Selects Candidates"] --> ReadMsg

        ReadMsg --> CheckLimit{"10 Msgs and 1 MiB Body?"}
        CheckLimit -- "Pass" --> SafeBody["Decoded Body Disclosed"]
        CheckLimit -- "Exceeded" --> DropBody["Discard Body (No Partial Leak)"]

        SafeBody --> ListAtt["list_attachments(msg_id)"]
        ListAtt --> SelectAtt["Operator Names Attachment + Destination"]
        SelectAtt --> CheckFile{"File Exists?"}
        CheckFile -- "Yes" --> AbortFile["Abort: Overwrite Forbidden"]
        CheckFile -- "No" --> CheckSize{"25 MiB File / 50 MiB Total?"}
        CheckSize -- "Pass" --> Download["Atomic Download to Destination"]
        CheckSize -- "Fail" --> Purge["Purge Temp File"]
    end

    %% 3. Service Throttle
    subgraph Throttle ["3. Gmail API Service Protection (ADR 0007)"]
        Budget["Budget: 3,000 Units / 60s"] -.-> Search
        Concur["Max 4 In-Flight Requests"] -.-> ReadMsg
        Retry["Backoff: 1s, 2s, 4s, 8s (Max 5 / 60s)"] -.-> ListAtt
    end

    %% 4. Transmission Pipeline
    subgraph Transmission ["4. Transmission Milestone (GATED)"]
        Agent["Drafting Agent (AI)"] --> Frozen["Frozen Draft (SHA-256 Fingerprint)"]
        Frozen --> Stage["users.drafts.create (staged to Gmail Drafts)"]
        Stage --> Handoff["Send Handoff (CLI Command + Fingerprint)"]
        Handoff --> SendGate{"MANUAL SEND GATE: Operator Runs Sender"}
        SendGate -- "Operator Executes" --> Sender["Local Sender CLI"] --> SendAPI["users.drafts.send / users.messages.send"]
        SendGate -- "Operator Skips" --> NoSend["No Email Sent"]
    end

    %% 5. Triage Pipeline
    subgraph Triage ["5. Autonomous AFK Triage (ADR 0011, 0012, 0013)"]
        Scan["triage scan (headers only)"] --> Classify["Classify against policy + sender clusters"]
        Classify --> Protect{"Protected Category?"}
        Protect -- "Financial / 2FA / Receipt / Travel / Personal" --> Keep["Never a Target"]
        Protect -- "No" --> Partition["Partition into bundles (max 75, ADR 0013)"]
        Partition --> Plans["Fingerprinted CleanupPlan Artifacts"]
    end

    %% 6. Modification Pipeline
    subgraph Modify ["6. Modification Milestone (GATED)"]
        Plans --> Preview["cleanup preview (verify fingerprint + targets)"]
        PlanDirect["cleanup plan (query, action, limit)"] --> Preview
        Preview --> ModGate{"MANUAL MODIFY GATE: Operator Confirms Plan"}
        ModGate -- "Operator Executes" --> Mutate["users.messages.trash / users.messages.modify"]
        ModGate -- "Operator Skips" --> NoMutate["Mailbox Unchanged"]
        Mutate --> Reversible["Soft Delete: 30-day Trash, untrash restores"]
    end

    %% 7. Calendar Pipeline
    subgraph Calendar ["7. Calendar and Meet (ADR 0014, GATED)"]
        CalPreview["calendar-event preview (dry-run handoff)"] --> ActGate{"MANUAL ACTION GATE: Operator Confirms"}
        ActGate -- "Operator Executes" --> Insert["events.insert (conferenceDataVersion=1)"]
        ActGate -- "Operator Skips" --> NoEvent["No Event Created"]
        Insert --> ConfStatus{"conferenceData status"}
        ConfStatus -- "success" --> MeetLink["Meet Link Returned"]
        ConfStatus -- "pending" --> Poll["Bounded backoff poll: events.get"] --> MeetLink
        ConfStatus -- "failure" --> NoMeet["Event Created Without Meet Link"]
    end

    %% 8. Audit
    subgraph AuditLog ["8. Audit (ADR 0008)"]
        Sink[("~/.local/state/gmail-local/audit.log (0600, rotated at 5 MiB)")]
        SendAPI -.-> Sink
        Mutate -.-> Sink
        Insert -.-> Sink
        Download -.-> Sink
    end
```
