# Wayfinder Ticket: Autonomous AFK Inbox Triage & Evaluation Benchmark Pipeline

**Status:** Completed and verified 2026-09-10  
**Type:** `wayfinder:task`  
**Created:** 2026-09-10  
**Workspace:** `/Users/mag_station/Dev_Tools/Gmail-API`  
**Account:** `[REDACTED_USER_EMAIL]`  
**Governing ADRs:** [ADR 0001](docs/adr/0001-user-executed-send-gate.md), [ADR 0003](docs/adr/0003-separate-retrieval-and-transmission-credentials.md), [ADR 0008](docs/adr/0008-attachment-staging-and-audit-log-retention.md), [ADR 0010](docs/adr/0010-staged-cleanup-plan-and-manual-modify-gate.md), [ADR 0011](docs/adr/0011-afk-triage-policy-and-eval-benchmark.md), and [CONTEXT.md](CONTEXT.md).  
**Predecessor Tickets:** [WAYFINDER_GMAIL_API_READ_ACCESS.md](WAYFINDER_GMAIL_API_READ_ACCESS.md), [WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md](WAYFINDER_GMAIL_API_TRANSMISSION_ACCESS.md), [WAYFINDER_GMAIL_API_MODIFY_ACCESS.md](WAYFINDER_GMAIL_API_MODIFY_ACCESS.md).

---

## 1. Context & Motivation

The user's personal mailbox contains over **143,000 messages** (112,000+ unread), dominated by:
- `CATEGORY_PROMOTIONS`: ~71,300 messages
- `CATEGORY_UPDATES`: ~64,500 messages
- `CATEGORY_SOCIAL`: ~6,600 messages

Manually reviewing 143k emails through one-off searches is infeasible. However, blindly running bulk deletion queries risks catastrophic data loss (e.g. deleting receipts, tax documents, bank notices, 2FA recovery codes, or personal correspondence).

The Operator has requested an **autonomous AFK (Away-From-Keyboard) Inbox Triage Pipeline** equipped with formal **evals** to safely classify high-volume inbox backlogs, cluster senders, detect junk vs. critical mail, and generate staged, fingerprinted `CleanupPlan` batches that strictly preserve the **Manual Modify Gate** (ADR 0010).

---

## 2. Core Architecture

### 2.1 Separation of Concerns: AFK Analysis vs. HITL Execution
```
 +-------------------------------------------------------------------------+
 |                     AFK Phase (Autonomous / Background)                 |
 |                                                                         |
 | 1. Inbox Header Scanner (Batch query, rate-limited via retrieval grant)  |
 | 2. Rule & Heuristic Classifier (Multi-tier triage policy)               |
 | 3. Hard Safety Boundary Check (Zero False-Positive Protected Filter)    |
 | 4. Partitioning & Staging (Max 50 items/plan, deterministic SHA-256)    |
 | 5. Manifest & Handoff Generation (Summary by cluster, sender, volume)   |
 +------------------------------------+------------------------------------+
                                      |
                                      v
 +------------------------------------+------------------------------------+
 |                    HITL Phase (Operator Approval Gate)                  |
 |                                                                         |
 | 1. Operator reviews Triage Handoff / Summary Dashboard                  |
 | 2. Operator reviews plan previews (`gmail-local cleanup preview <fp>`)  |
 | 3. Operator executes Manual Modify Gate (`cleanup apply --confirm <fp>`) |
 | 4. Audit log records executed operations                                |
 +-------------------------------------------------------------------------+
```

### 2.2 Invariant Hierarchy
1. **Safety First (Zero False-Positive Trashing):**
   - Protected categories (Financial, Security/2FA, Purchases/Receipts, Legal/Government, Personal Threads, Travel/Flight Bookings, Calendar Invitations) must **NEVER** be categorized as `trash`.
   - If an email has ambiguous cues or matches both a promotional pattern and a receipt pattern, the classifier **MUST default to PROTECT/KEEP**.
2. **Deterministic Classification:**
   - The same message headers evaluated against the same policy must always yield the exact same decision and fingerprint.
3. **Strict Batch Ceilings ($\le 50$ targets):**
   - Large triage scans targeting hundreds or thousands of candidates must be automatically partitioned into discrete staged plans of $\le 50$ targets each.
4. **Append-Only Auditing:**
   - Every triage manifest and execution is tracked without logging private email bodies.

---

## 3. Evaluation Benchmark Suite (`evals/test_triage_policy.py`)

The evaluation suite validates the following test matrices:

1. **Safety Ground Truth (Precision = 1.0 on Protected Classes):**
   - Tax forms (W-2, 1099, IRS notices)
   - Banking & credit card statements (Chase, Wells Fargo, Amex)
   - E-commerce purchase receipts & invoices (Amazon, Apple, Stripe, PayPal)
   - Two-factor authentication & password resets (Google, GitHub, Auth0)
   - Travel reservations (Delta, United, Airbnb, Amtrak)
   - Personal 1-on-1 human correspondence
2. **Junk & Promotional Recall:**
   - Marketing mailers, retail discount blasts, expired coupons (`sale ends`, `50% off`)
   - Cold recruitment outreach
   - Automated digest newsletters (`morningwire`, `pulse`, `daily brief`)
   - Social network notifications older than 30 days
3. **Partitioning & Boundary Tests:**
   - Verifying that an inbox scan yielding 135 trash candidates partitions cleanly into 3 plans: 50 + 50 + 35 targets.
   - Verifying all plans satisfy `CleanupPlan.validate()`.

---

## 4. Verification Checklist

- [x] ADR 0011 authored and approved.
- [x] Evaluation benchmark `evals/test_triage_policy.py` implemented with comprehensive synthetic datasets.
- [x] Triage core module `src/gmail_local/triage.py` implemented with hierarchical classification rules.
- [x] Staged plan partitioning implemented (enforcing $\le 50$ limit per plan).
- [x] CLI commands `gmail-local triage scan` and `gmail-local triage plan` integrated into `cli.py`.
- [x] `evals/run_evals.py` and `pytest` pass with 100% success rate (214 unit tests, 32 evals).
- [x] Live dry-run scan executed against user's real inbox with zero destructive mutations.
