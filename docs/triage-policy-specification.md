# Overarching AFK Triage Policy & Scanner Specification

This specification formalizes the autonomous, background ("AFK") email triage policy, categorization hierarchy, domain clustering engine, and evaluation boundaries for the `gmail-local` system.

---

## 1. System Objectives & Mailbox Scale

In personal mailboxes with over 100,000 messages (e.g. 143k+ messages, 112k+ unread), manual individual email triage is impossible. Blind bulk deletion is unacceptably dangerous due to the presence of critical financial, tax, legal, medical, and personal records.

The **Overarching AFK Triage Policy & Scanner** bridges this gap by providing:
1. **Deterministic Multi-Tier Categorization:** Classifying incoming and historical messages against explicit, auditable safety rules.
2. **Zero False-Positive Safety Guarantee:** Ensuring financial, receipt, travel, 2FA, legal, and personal emails are never marked for deletion.
3. **Domain & Sender Clustering:** Grouping high-volume senders into reviewable cohorts to enable bulk decision-making.
4. **Time-To-Live (TTL) Decay Modeling:** Distinguishing fresh promotional offers from stale, expired marketing blasts (>14 days old).
5. **Partitioned Staging Ceilings:** Automatically breaking large mutations into staged `CleanupPlan` bundles of $\le 50$ items, strictly governed by the **Manual Modify Gate** ([ADR 0010](adr/0010-staged-cleanup-plan-and-manual-modify-gate.md)).

---

## 2. Policy Hierarchy & Classification Tiers

```
+-----------------------------------------------------------------------------+
| TIER 0: ABSOLUTE PROTECTED INVARIANTS (Action: KEEP, is_protected=True)     |
| Priority 1..10. Zero false-positive tolerance. Overrides all other tiers.   |
| - Financial & Tax (Banks, Brokerages, W-2, 1099, IRS)                       |
| - Purchases & Transactions (Order confirmations, Receipts, Invoices)        |
| - Security & Authentication (2FA, OTP, Device verification, Passwords)      |
| - Travel & Lodging (Flight tickets, Itineraries, Boarding passes, Hotels)   |
| - Medical & Healthcare (Doctor appointments, Lab results, Insurance)        |
| - Legal & Government (USCIS, Courts, DMV, Legal notices)                    |
| - Personal Communications (1-on-1 human correspondence, Direct replies)     |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| TIER 1: OPERATOR WHITELISTS & OVERRIDES                                     |
| Specific sender domains or address rules explicitly marked by the Operator. |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| TIER 2: CANDIDATES FOR TRASH (Action: TRASH, is_protected=False)            |
| Promotional mailers, retail discounts, marketing blasts, expired coupons.   |
| - Senders matching promotional subdomains (deals., promo., marketing.)      |
| - Subjects matching sales cues ("50% off", "Flash Sale", "Clearance")       |
| - Stale marketing blasts older than retention threshold (default: 14 days)  |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| TIER 3: CANDIDATES FOR ARCHIVE (Action: ARCHIVE, is_protected=False)        |
| Informational mailers that clutter the inbox but hold reference value.      |
| - News briefings & curated digests (Morning Wire, Athletic Pulse, Snacks)   |
| - Read notifications older than retention threshold                         |
| - Shipping deliveries confirmed delivered                                   |
+-----------------------------------------------------------------------------+
                                      |
                                      v
+-----------------------------------------------------------------------------+
| TIER 4: AMBIGUITY FALLBACK (Action: KEEP, is_protected=False)               |
| If confidence < 0.80 or if cues conflict, safely default to KEEP in inbox. |
+-----------------------------------------------------------------------------+
```

---

## 3. Conflict Resolution Matrix

| Candidate Characteristics | Detected Match A | Detected Match B | Resolution | Justification |
| :--- | :--- | :--- | :--- | :--- |
| Uber trip receipt with discount coupon | `protect_transaction` | `promo_discount` | **PROTECTED (KEEP)** | Financial/Receipt safety always overrides promotional cues. |
| Bank marketing credit card offer | `protect_financial` | `promo_discount` | **PROTECTED (KEEP)** | Domain is a primary financial institution; prevent bank alert deletion. |
| Retailer order shipment with promo footer | `protect_transaction` | `promo_discount` | **PROTECTED (KEEP)** | Order tracking details must be preserved. |
| Daily news digest with sponsored ad | `newsletter_digest` | `promo_discount` | **ARCHIVE** | Primary intent is news delivery; archive from inbox rather than trash. |
| Unknown sender with ambiguous body | None | None | **KEEP** | When in doubt, leave in inbox. |

---

## 4. Sender & Domain Clustering Architecture

Because an inbox of 143k messages typically contains hundreds of messages from identical sender domains, the scanner groups discovery candidates into `SenderCluster` cohorts:

```python
@dataclass
class SenderCluster:
    domain: str
    sender_addresses: List[str]
    message_count: int
    recommended_action: TriageAction
    category: TriageCategory
    sample_subjects: List[str]
```

### Clustering Workflow:
1. Extract sender domain from `From:` RFC 822 header (e.g., `TheAthletic@e1.theathletic.com` -> `theathletic.com`).
2. Aggregate message counts, unique senders, and sample subjects per domain.
3. Apply the Triage Policy to the domain cohort.
4. Output sorted cluster rankings (by message volume descending).
5. Enable 1-command bulk staging by domain cluster.

---

## 5. Staged Plan Partitioning

To maintain compliance with [ADR 0010](adr/0010-staged-cleanup-plan-and-manual-modify-gate.md) and prevent rate limit exhaustion or catastrophic bulk deletion:

1. Any scan producing $>50$ candidate mutations is partitioned into chunks of $\le 50$ targets.
2. Each plan chunk is assigned an independent canonical SHA-256 fingerprint:
   $$\text{Fingerprint} = \text{SHA-256}(\text{CanonicalJSON}(\text{targets}, \text{action}))$$
3. Each plan file is saved locally to `~/.local/state/gmail-local/plans/<fingerprint>.json`.
4. Execution requires Operator confirmation per plan or via sequential batch review.
