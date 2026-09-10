# Autonomous AFK Inbox Triage Guide

This guide describes how to operate the autonomous, background (AFK) inbox triage system on large personal Gmail mailboxes (>100,000 messages) without risking accidental deletion of critical messages.

---

## 1. Operating Principles & Safety Invariants

When tackling a large mailbox, the triage system enforces five core invariants governed by **ADR 0010** and **ADR 0011**:

1. **Zero False-Positive Trashing on Protected Classes:**
   - Financial statements, tax returns (W-2, 1099), bank notifications, credit card alerts.
   - E-commerce purchase receipts, order confirmations, shipping updates, payment invoices.
   - Two-factor authentication (2FA) passcodes, security alerts, device verification emails.
   - Travel reservations, flight tickets, hotel itineraries, boarding passes.
   - 1-on-1 personal correspondence and direct human threads.
   - **Rule:** If any message contains even a single cue or keyword matching a protected category, it is unconditionally protected (`action=KEEP`). Ambiguity always defaults to `KEEP`.

2. **Categorization Before Mutation:**
   - Triage operations (`triage scan`, `triage plan`) strictly use read grants.
   - No emails are modified or deleted during background triage analysis.

3. **Partitioned Staging Ceilings ($\le 50$ targets per plan):**
   - Candidate mutations are partitioned into discrete `CleanupPlan` artifacts with a hard ceiling of 50 targets per plan.
   - Each plan receives an immutable SHA-256 cryptographic fingerprint over its canonical JSON structure.

4. **Manual Modify Gate (ADR 0010):**
   - AI agents are strictly prohibited from mutating mailbox state autonomously.
   - Execution requires direct Operator intervention via `gmail-local cleanup apply --plan <fingerprint> --confirm`.

5. **Reversible Soft-Delete Only:**
   - Trashing uses `users.messages.trash`, retaining items in the Gmail Trash for 30 days.
   - Mistakenly trashed items can be restored anytime via `gmail-local cleanup untrash <message-id>`.

---

## 2. CLI Workflow

### Step 1: Discover & Analyze Candidates (AFK / Non-Destructive)

Run a non-destructive scan over candidates in your inbox:

```bash
# Scan recent 50 messages in the primary inbox
gmail-local triage scan --query "in:inbox" --limit 50

# Scan specific categories (e.g. promotions older than 30 days)
gmail-local triage scan --query "category:promotions older_than:30d" --limit 50
```

The output presents an executive summary table:
- Total candidate count.
- Action distribution (`TRASH`, `ARCHIVE`, `KEEP/PROTECT`).
- Semantic category distribution (`promotion_discount`, `newsletter_digest`, `protected_financial`, etc.).
- Line-by-line breakdown with justification and matching policy rule.

---

### Step 2: Generate Staged Cleanup Plans

When satisfied with the triage categorization, stage candidate mutations into fingerprinted plan bundles:

```bash
# Stage trash candidates into bundles of <= 50 messages
gmail-local triage plan --query "in:inbox" --limit 50 --action trash

# Stage archive candidates (e.g. read newsletters) into bundles
gmail-local triage plan --query "in:inbox" --limit 50 --action archive
```

This generates plan files in `~/.local/state/gmail-local/plans/<fingerprint>.json` and prints their fingerprints and target counts.

---

### Step 3: Preview & Verify (HITL)

Inspect the staged plan before approving execution:

```bash
gmail-local cleanup preview <plan-fingerprint>
```

---

### Step 4: Execute Under Manual Modify Gate

Execute the plan interactively or with explicit script confirmation:

```bash
# Interactive prompt (type 'yes'):
gmail-local cleanup apply --plan <plan-fingerprint>

# Scripted confirmation:
gmail-local cleanup apply --plan <plan-fingerprint> --confirm
```

---

## 3. Long-Horizon AFK Operations (`/goal`)

For long-horizon mailbox cleanup across tens of thousands of messages, recommend using the `/goal` slash command in the AI coding assistant:

> **Recommended Prompt:**
> ```text
> /goal Scan the next 500 promotional emails in my inbox using 'gmail-local triage scan', cluster senders by volume, generate staged cleanup plans for marketing blasts older than 30 days, verify that zero protected messages are included, and present a batch approval summary.
> ```

The agent will run background discovery, classify each batch against the evaluation-hardened policy, verify all invariants, partition candidate deletions into safe bundles of $\le 50$, and hand off the batch fingerprints for your final confirmation.
