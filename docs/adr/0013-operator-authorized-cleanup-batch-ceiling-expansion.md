# ADR 0013: Operator-Authorized Expansion of Cleanup Batch Ceiling to 75 Targets

## Status
Accepted (Operator Authorized 2026-09-10)

## Context
In ADR 0010, the maximum batch ceiling for staged cleanup plans (`MAX_CLEANUP_BATCH_SIZE`) was originally established at 50 targets per bundle to ensure small, controlled mutation sets during initial implementation.

During active high-volume inbox triage on historical promotional cohorts (dating back to 2011–2013), candidate inspection queries routinely yield 75 messages per API call (`MAX_SEARCH_BOUND = 75`). The Operator explicitly requested:
> *"Let's up that to 75 messages per slice. I do know that we set 50 as a target per bundle, but we can overwrite that."*

## Decision
1. **Increase Batch Ceiling to 75 Targets:**
   - Updated `MAX_CLEANUP_BATCH_SIZE` in `gmail_local.config` from 50 to 75.
   - Partitioning logic in `TriagePlanGenerator.generate_staged_plans` and CLI subcommands now enforces 75 targets per bundle.
   - Forged or malformed plans exceeding 75 targets are strictly rejected by `CleanupPlan.validate()`.

2. **API Quota Alignment:**
   - Aligning `MAX_CLEANUP_BATCH_SIZE` with `MAX_SEARCH_BOUND = 75` enables 1:1 parity between single-page discovery scans and execution bundles, eliminating unnecessary fragment bundles when candidate sets fit within the 75-message retrieval window.

3. **Evaluation Benchmark Verification:**
   - Updated property-based invariants (`tests/test_properties.py`), model validation tests (`tests/test_models.py`), adversarial tamper evals (`evals/test_adversarial.py`), and triage partitioning evals (`evals/test_triage_policy.py`) to assert strict enforcement of the 75-target ceiling.
