# AFK Inbox Triage Policy, Evaluation Benchmark, and Chunked Staging

For large, high-volume personal mailboxes (exceeding 100,000 messages), manual inspection is prohibitive while unguided bulk deletion poses catastrophic data loss risks. This decision defines the autonomous, background (AFK) triage architecture, classification safety hierarchy, and automated evaluation benchmark:

1. **Separation of AFK Triage from Mailbox Modification:**
   - Background triage processes and autonomous agents operate strictly within the read-only inspection grant (`gmail-local-retrieval` or read methods of `gmail-local-modify`).
   - Triage operations analyze headers, cluster senders, evaluate message categories, and output structured **Triage Manifests** and **Staged Cleanup Plans**.
   - No mailbox mutation occurs during AFK triage. Actual execution is deferred exclusively to the Manual Modify Gate (ADR 0010).

2. **Hierarchical Triage Safety Policy:**
   - To prevent catastrophic deletion of critical records, the triage classifier enforces a strict priority hierarchy:
     1. **PROTECT (Priority 1):** Financial records, tax documents, banking alerts, credit cards, e-commerce purchase receipts, order tracking, two-factor authentication codes, security notices, password resets, travel/hotel/flight reservations, legal/government correspondence, and personal 1-on-1 correspondence.
     2. **ARCHIVE (Priority 2):** Read notifications, newsletters with informational value, transactional shipping updates for delivered items, completed social notifications older than a retention threshold.
     3. **TRASH (Priority 3):** Promotional marketing blasts, retail discount emails, expired daily deals, unsolicited sales outreach, social media notification spam older than 30 days.
   - **Ambiguity Fallback:** Any message matching both a PROTECT rule and a TRASH rule **must default to PROTECT**. When confidence is low, the default action is always KEEP.

3. **Evaluation Benchmark Suite (`evals/test_triage_policy.py`):**
   - The codebase maintains an automated evaluation suite executed as part of `python evals/run_evals.py`.
   - **Zero False-Positive Invariant:** Any rule or classifier update that marks a protected message class (receipts, tax forms, 2FA, personal mail) as `trash` fails the evaluation benchmark immediately with a hard error.

4. **Chunked Plan Partitioning ($\le 50$ targets per plan):**
   - When an AFK scan evaluates hundreds or thousands of candidate messages, it cannot produce a single massive cleanup plan (violating the 50-item limit in ADR 0010).
   - The triage engine partitions approved candidate mutations into discrete, canonically fingerprinted `CleanupPlan` bundles of at most 50 items each, saved under `~/.local/state/gmail-local/plans/`.
   - The Operator can review and execute each plan bundle individually or sequentially under the Manual Modify Gate.
