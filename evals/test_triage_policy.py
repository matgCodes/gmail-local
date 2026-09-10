"""Evaluation Benchmark Suite for Autonomous Inbox Triage Policy.

Enforces zero-tolerance safety invariants:
1. Zero False-Positive Trashing of Protected Emails (Financial, Tax, Receipts, 2FA, Travel, Personal).
2. Deterministic categorization and fingerprinting.
3. Strict batch partitioning (<= 50 targets per staged plan).
4. Ambiguous/conflict resolution always defaults to KEEP/PROTECT.
"""

import json
from pathlib import Path
import pytest

from gmail_local.triage import (
    TriageClassifier,
    TriageCategory,
    TriageAction,
    TriageDecision,
    TriagePlanGenerator,
    TriagePolicy,
)
from gmail_local.models import CleanupPlan, CleanupAction


# ----------------------------------------------------------------------------
# Test Fixtures: Safety-Critical Protected Email Datasets
# ----------------------------------------------------------------------------

PROTECTED_FINANCIAL_SAMPLES = [
    {"from": "Chase <no.reply.alerts@chase.com>", "subject": "Your monthly account statement is available", "date": "2026-09-01"},
    {"from": "Wells Fargo Alerts <alerts@wellsfargo.com>", "subject": "Your checking balance is below $100", "date": "2026-09-02"},
    {"from": "American Express <service@americanexpress.com>", "subject": "Payment Received - Thank You", "date": "2026-09-03"},
    {"from": "Fidelity Investments <fidelity@fidelity.com>", "subject": "Important Tax Form 1099-DIV Available", "date": "2026-09-04"},
    {"from": "TurboTax <taxes@turbotax.intuit.com>", "subject": "Your federal tax return was accepted by the IRS", "date": "2026-04-15"},
    {"from": "Vanguard <vanguard@e.vanguard.com>", "subject": "Quarterly Portfolio Summary Statement", "date": "2026-07-01"},
]

PROTECTED_TRANSACTION_SAMPLES = [
    {"from": "Amazon.com <auto-confirm@amazon.com>", "subject": "Your order #112-9876543-1234567 has shipped", "date": "2026-09-05"},
    {"from": "Apple <no_reply@email.apple.com>", "subject": "Your receipt from Apple for iCloud+ 200GB", "date": "2026-09-06"},
    {"from": "service@paypal.com <service@paypal.com>", "subject": "Receipt for your payment to Steam Games", "date": "2026-09-07"},
    {"from": "Stripe Receipts <receipts@stripe.com>", "subject": "Invoice #INV-2026-0042 paid", "date": "2026-09-08"},
    {"from": "Best Buy <orders@bestbuy.com>", "subject": "Your order is ready for store pickup", "date": "2026-09-09"},
    {"from": "Uber Receipts <uber.us@uber.com>", "subject": "Your Tuesday afternoon trip with Uber", "date": "2026-09-09"},
]

PROTECTED_SECURITY_SAMPLES = [
    {"from": "Google Accounts <no-reply@accounts.google.com>", "subject": "Security alert: New login from macOS", "date": "2026-09-09"},
    {"from": "GitHub <noreply@github.com>", "subject": "[GitHub] Please verify your device authentication code: 492019", "date": "2026-09-08"},
    {"from": "Auth0 <no-reply@auth0.com>", "subject": "Your one-time verification passcode is 781940", "date": "2026-09-07"},
    {"from": "Discord <noreply@discord.com>", "subject": "Password reset request for your Discord account", "date": "2026-09-06"},
]

PROTECTED_TRAVEL_SAMPLES = [
    {"from": "United Airlines <unitedairlines@united.com>", "subject": "eTicket Itinerary and Receipt for Confirmation ABC123", "date": "2026-09-01"},
    {"from": "Delta Air Lines <DeltaAirLines@t.delta.com>", "subject": "Flight Confirmation - SeaTac to SFO", "date": "2026-09-02"},
    {"from": "Airbnb <automated@airbnb.com>", "subject": "Reservation confirmed: Cabin in Lake Tahoe", "date": "2026-09-03"},
    {"from": "Amtrak <tickets@amtrak.com>", "subject": "Your Amtrak eTicketing Document and Travel Receipt", "date": "2026-09-04"},
]

PROTECTED_PERSONAL_SAMPLES = [
    {"from": "Alice Smith <alice.smith@gmail.com>", "subject": "Re: Dinner plans this weekend with mom and dad", "date": "2026-09-05"},
    {"from": "Bob Jones <bob.jones@workmail.io>", "subject": "Contract review and feedback on project timeline", "date": "2026-09-06"},
    {"from": "Mathew A. Garcia <mat.garcia760@gmail.com>", "subject": "Notes on home remodel estimates", "date": "2026-09-07"},
]

# ----------------------------------------------------------------------------
# Test Fixtures: Candidates for Trash or Archive
# ----------------------------------------------------------------------------

PROMOTIONAL_TRASH_SAMPLES = [
    {"from": "J.Crew Factory <jcrew@email.jcrew.com>", "subject": "FLASH SALE! Extra 60% off clearance ends tonight!", "date": "2026-08-01"},
    {"from": "Wayfair <deals@wayfair.com>", "subject": "Up to 70% off Labor Day clearance deals are live", "date": "2026-08-15"},
    {"from": "Domino's Pizza <deals@dominos.com>", "subject": "50% off all menu-priced pizzas this week only", "date": "2026-08-20"},
    {"from": "Banana Republic <bananarepublic@email.gap.com>", "subject": "Don't miss 40% off your entire purchase today", "date": "2026-08-25"},
    {"from": "REI Co-op <rei@email.rei.com>", "subject": "Member-exclusive coupons inside - save up to $100", "date": "2026-08-28"},
]

NEWSLETTER_ARCHIVE_SAMPLES = [
    {"from": "The Associated Press <morningwire@apnews.com>", "subject": "Morning Wire: Top stories for Thursday", "date": "2026-09-10"},
    {"from": "The Athletic Pulse <TheAthletic@e1.theathletic.com>", "subject": "The Athletic Pulse: NFL opening night kickoff preview", "date": "2026-09-10"},
    {"from": "Snacks <hello@snacks.robinhood.com>", "subject": "Robinhood Snacks: Why tech stocks are shifting today", "date": "2026-09-10"},
]


# ============================================================================
# Benchmark Evaluations
# ============================================================================

class TestTriageSafetyInvariants:
    """Rigorous evaluation of safety boundary invariants in triage classification."""

    @pytest.fixture
    def classifier(self):
        return TriageClassifier(policy=TriagePolicy.default())

    def test_eval_zero_false_positive_trash_on_financial(self, classifier):
        """CRITICAL: Financial and tax records must NEVER be marked for trashing."""
        for i, sample in enumerate(PROTECTED_FINANCIAL_SAMPLES):
            decision = classifier.classify(
                message_id=f"fin_{i}",
                thread_id=f"t_fin_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.is_protected is True, f"Failed protection for financial: {sample}"
            assert decision.action != TriageAction.TRASH, f"Violation: Financial marked for TRASH: {sample}"

    def test_eval_zero_false_positive_trash_on_transactions(self, classifier):
        """CRITICAL: Receipts and order confirmations must NEVER be marked for trashing."""
        for i, sample in enumerate(PROTECTED_TRANSACTION_SAMPLES):
            decision = classifier.classify(
                message_id=f"txn_{i}",
                thread_id=f"t_txn_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.is_protected is True, f"Failed protection for transaction: {sample}"
            assert decision.action != TriageAction.TRASH, f"Violation: Transaction marked for TRASH: {sample}"

    def test_eval_zero_false_positive_trash_on_security(self, classifier):
        """CRITICAL: 2FA codes, security alerts, and resets must NEVER be marked for trashing."""
        for i, sample in enumerate(PROTECTED_SECURITY_SAMPLES):
            decision = classifier.classify(
                message_id=f"sec_{i}",
                thread_id=f"t_sec_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.is_protected is True, f"Failed protection for security: {sample}"
            assert decision.action != TriageAction.TRASH, f"Violation: Security marked for TRASH: {sample}"

    def test_eval_zero_false_positive_trash_on_travel(self, classifier):
        """CRITICAL: Travel itineraries and reservations must NEVER be marked for trashing."""
        for i, sample in enumerate(PROTECTED_TRAVEL_SAMPLES):
            decision = classifier.classify(
                message_id=f"trv_{i}",
                thread_id=f"t_trv_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.is_protected is True, f"Failed protection for travel: {sample}"
            assert decision.action != TriageAction.TRASH, f"Violation: Travel marked for TRASH: {sample}"

    def test_eval_zero_false_positive_trash_on_personal(self, classifier):
        """CRITICAL: 1-on-1 human correspondence must NEVER be marked for trashing."""
        for i, sample in enumerate(PROTECTED_PERSONAL_SAMPLES):
            decision = classifier.classify(
                message_id=f"per_{i}",
                thread_id=f"t_per_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.is_protected is True, f"Failed protection for personal: {sample}"
            assert decision.action != TriageAction.TRASH, f"Violation: Personal marked for TRASH: {sample}"

    def test_eval_conflict_resolution_ambiguous_defaults_to_protect(self, classifier):
        """An email containing both promotional words and receipt keywords must default to PROTECT."""
        ambiguous_sample = {
            "from": "Uber Deals <uber@deals.uber.com>",
            "subject": "Save 50% on Uber Eats! Plus your receipt for order #88412",
            "date": "2026-09-08",
        }
        decision = classifier.classify(
            message_id="amb_1",
            thread_id="t_amb_1",
            sender=ambiguous_sample["from"],
            subject=ambiguous_sample["subject"],
            date=ambiguous_sample["date"],
        )
        assert decision.is_protected is True
        assert decision.action != TriageAction.TRASH

    def test_eval_promotional_recall_marks_for_trash(self, classifier):
        """Promotional marketing blasts older than 14d should be marked for TRASH."""
        for i, sample in enumerate(PROMOTIONAL_TRASH_SAMPLES):
            decision = classifier.classify(
                message_id=f"promo_{i}",
                thread_id=f"t_promo_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.category == TriageCategory.PROMOTION_DISCOUNT
            assert decision.action == TriageAction.TRASH

    def test_eval_newsletter_recall_marks_for_archive(self, classifier):
        """Daily news digests and informational newsletters should be marked for ARCHIVE."""
        for i, sample in enumerate(NEWSLETTER_ARCHIVE_SAMPLES):
            decision = classifier.classify(
                message_id=f"news_{i}",
                thread_id=f"t_news_{i}",
                sender=sample["from"],
                subject=sample["subject"],
                date=sample["date"],
            )
            assert decision.category == TriageCategory.NEWSLETTER_DIGEST
            assert decision.action == TriageAction.ARCHIVE


class TestTriagePartitioningAndBoundaries:
    """Evaluation of plan generation bounds, partitioning, and ADR 0010 compliance."""

    def test_eval_partitioning_enforces_max_batch_size_50(self, tmp_path):
        """A batch of 135 trash decisions must partition into exactly 3 plans of <= 50 targets each."""
        generator = TriagePlanGenerator(plans_dir=tmp_path)

        decisions = []
        for i in range(135):
            decisions.append(
                TriageDecision(
                    message_id=f"msg_{i:04d}",
                    thread_id=f"thr_{i:04d}",
                    sender="retail@promo.com",
                    subject=f"Flash sale discount #{i}",
                    date="2026-08-01",
                    category=TriageCategory.PROMOTION_DISCOUNT,
                    action=TriageAction.TRASH,
                    rule_name="promo_discount_rule",
                    confidence=0.95,
                    is_protected=False,
                )
            )

        plans = generator.generate_staged_plans(decisions, action_filter=TriageAction.TRASH)

        assert len(plans) == 3
        assert len(plans[0].targets) == 50
        assert len(plans[1].targets) == 50
        assert len(plans[2].targets) == 35

        # Verify all plans are valid CleanupPlan instances
        for plan in plans:
            assert isinstance(plan, CleanupPlan)
            assert plan.action_type == CleanupAction.TRASH
            assert len(plan.targets) <= 50
            # Ensure JSON artifact was persisted to disk with filename matching fingerprint
            plan_file = tmp_path / f"{plan.fingerprint}.json"
            assert plan_file.exists()
            content = json.loads(plan_file.read_text(encoding="utf-8"))
            assert content["fingerprint"] == plan.fingerprint

    def test_eval_classification_determinism(self):
        """Repeated classification of identical inputs must yield identical decisions."""
        classifier = TriageClassifier(policy=TriagePolicy.default())
        sample = {
            "from": "Old Navy <oldnavy@email.gap.com>",
            "subject": "50% off all jeans today only!",
            "date": "2026-08-10",
        }

        d1 = classifier.classify("m1", "t1", sample["from"], sample["subject"], sample["date"])
        d2 = classifier.classify("m1", "t1", sample["from"], sample["subject"], sample["date"])

        assert d1.category == d2.category
        assert d1.action == d2.action
        assert d1.rule_name == d2.rule_name
        assert d1.confidence == d2.confidence
        assert d1.is_protected == d2.is_protected
