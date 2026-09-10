# Overarching AFK Triage Policy, Configurable Rule Engine, and Sender Clustering

This decision establishes the architecture for custom policy configuration, multi-pass scanner clustering, and evaluation bounds for high-volume email triage:

1. **Configurable External Policy (`~/.config/gmail-local/triage_policy.json`):**
   - While the core engine provides hardcoded safety defaults, operators require the flexibility to whitelist important senders, blacklist spammy newsletter domains, or tune promotional keywords.
   - The triage engine supports loading an external policy JSON file. If missing, it safely falls back to `TriagePolicy.default()`.
   - **Protection Invariant:** Custom policies cannot override the hardcoded safety layer unless explicitly forced by the Operator; critical financial, security, and transaction regexes are always enforced.

2. **Domain & Sender Clustering Analytics:**
   - Instead of processing emails strictly as isolated records, the scanner aggregates messages by sender domain (`SenderCluster`).
   - Senders accounting for large percentages of inbox clutter (e.g. 50+ emails from a single retail brand or newsletter) can be reviewed and staged as coherent batches.

3. **Triage Run Manifests (`~/.local/state/gmail-local/triage/manifest_<run_id>.json`):**
   - Each triage scan or plan generation writes an append-only JSON run manifest capturing scan parameters, query string, timestamp, candidate counts, cluster summaries, and generated plan fingerprints.
   - This maintains an auditable history of all AFK discovery sessions without disclosing private message bodies.

4. **Multi-Pass Scanner CLI:**
   - Introduces `gmail-local triage policy show` and `gmail-local triage policy init` to view and customize the active rules.
   - Introduces `gmail-local triage clusters` to display domain volume rankings across candidate searches.
