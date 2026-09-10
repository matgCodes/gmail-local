"""Unit tests for the autonomous inbox triage engine, classifier, and CLI."""

from unittest.mock import MagicMock
import pytest

from gmail_local.triage import (
    TriageClassifier,
    TriageCategory,
    TriageAction,
    TriageDecision,
    TriagePlanGenerator,
    TriagePolicy,
)
from gmail_local.models import CleanupPlan, CleanupAction, CandidateMessage


class TestTriageClassifierUnit:
    """Unit tests for TriageClassifier logic and boundary edge cases."""

    def test_default_policy_initialization(self):
        classifier = TriageClassifier()
        assert classifier.policy.name == "default_safety_policy"

    def test_empty_metadata_safe_keep(self):
        classifier = TriageClassifier()
        decision = classifier.classify(
            message_id="msg_empty",
            thread_id="thr_empty",
            sender="",
            subject="",
            date="",
        )
        assert decision.action == TriageAction.KEEP
        assert decision.category == TriageCategory.UNCATEGORIZED
        assert decision.is_protected is False

    def test_protect_financial_rule_triggers(self):
        classifier = TriageClassifier()
        decision = classifier.classify(
            message_id="msg_fin",
            thread_id="thr_fin",
            sender="Fidelity Alerts <Fidelity.Alerts@fidelity.com>",
            subject="Fidelity Alerts: Daily Balance",
            date="2026-09-10",
        )
        assert decision.is_protected is True
        assert decision.action == TriageAction.KEEP
        assert decision.category == TriageCategory.PROTECTED_FINANCIAL

    def test_protect_transaction_rule_triggers(self):
        classifier = TriageClassifier()
        decision = classifier.classify(
            message_id="msg_rec",
            thread_id="thr_rec",
            sender="Apple <no_reply@email.apple.com>",
            subject="Your receipt from Apple for iCloud+",
            date="2026-09-10",
        )
        assert decision.is_protected is True
        assert decision.action == TriageAction.KEEP
        assert decision.category == TriageCategory.PROTECTED_TRANSACTION

    def test_promo_discount_rule_triggers(self):
        classifier = TriageClassifier()
        decision = classifier.classify(
            message_id="msg_promo",
            thread_id="thr_promo",
            sender="Barnes & Noble <barnesandnoble@e.barnesandnoble.com>",
            subject="25% Off Pre-Order Edition Ends Tonight!",
            date="2026-09-10",
        )
        assert decision.is_protected is False
        assert decision.action == TriageAction.TRASH
        assert decision.category == TriageCategory.PROMOTION_DISCOUNT

    def test_newsletter_digest_rule_triggers(self):
        classifier = TriageClassifier()
        decision = classifier.classify(
            message_id="msg_news",
            thread_id="thr_news",
            sender="The Athletic <TheAthletic@e1.theathletic.com>",
            subject="The Athletic Pulse: Opening night kickoff",
            date="2026-09-10",
        )
        assert decision.is_protected is False
        assert decision.action == TriageAction.ARCHIVE
        assert decision.category == TriageCategory.NEWSLETTER_DIGEST

    def test_decision_to_dict_serialization(self):
        decision = TriageDecision(
            message_id="m123",
            thread_id="t123",
            sender="test@example.com",
            subject="Test Subject",
            date="2026-09-10",
            category=TriageCategory.NEWSLETTER_DIGEST,
            action=TriageAction.ARCHIVE,
            rule_name="test_rule",
            confidence=0.9,
            is_protected=False,
            reason="Test reason",
        )
        d = decision.to_dict()
        assert d["message_id"] == "m123"
        assert d["category"] == "newsletter_digest"
        assert d["action"] == "archive"
        assert d["is_protected"] is False


class TestTriagePlanGeneratorUnit:
    """Unit tests for TriagePlanGenerator chunking and artifact staging."""

    def test_empty_candidates_returns_empty_list(self, tmp_path):
        generator = TriagePlanGenerator(plans_dir=tmp_path)
        plans = generator.generate_staged_plans([], action_filter=TriageAction.TRASH)
        assert plans == []

    def test_protected_items_never_staged_for_trash(self, tmp_path):
        generator = TriagePlanGenerator(plans_dir=tmp_path)
        protected_decision = TriageDecision(
            message_id="prot_1",
            thread_id="t_prot_1",
            sender="bank@chase.com",
            subject="Bank Statement",
            date="2026-09-10",
            category=TriageCategory.PROTECTED_FINANCIAL,
            action=TriageAction.TRASH,  # Even if mistakenly set to TRASH
            rule_name="err",
            confidence=0.5,
            is_protected=True,  # Guard flag is True
        )
        plans = generator.generate_staged_plans([protected_decision], action_filter=TriageAction.TRASH)
        assert plans == []

    def test_archive_action_populates_remove_labels_inbox(self, tmp_path):
        generator = TriagePlanGenerator(plans_dir=tmp_path)
        archive_decision = TriageDecision(
            message_id="arch_1",
            thread_id="t_arch_1",
            sender="news@digest.com",
            subject="Daily Digest",
            date="2026-09-10",
            category=TriageCategory.NEWSLETTER_DIGEST,
            action=TriageAction.ARCHIVE,
            rule_name="news_rule",
            confidence=0.9,
            is_protected=False,
        )
        plans = generator.generate_staged_plans([archive_decision], action_filter=TriageAction.ARCHIVE)
        assert len(plans) == 1
        assert plans[0].action_type == CleanupAction.ARCHIVE
        assert plans[0].targets[0].remove_labels == ["INBOX"]


class TestTriageCLIUnit:
    """Unit tests for CLI commands cmd_triage_scan and cmd_triage_plan."""

    def test_cmd_triage_scan_with_candidates(self, capsys):
        from gmail_local.cli import cmd_triage_scan
        import argparse

        mock_retriever = MagicMock()
        mock_retriever.search_messages.return_value = [
            CandidateMessage(
                id="msg_test_1",
                thread_id="thr_test_1",
                date="2026-09-10",
                sender="Deals <deals@wayfair.com>",
                recipient="me@example.com",
                subject="Clearance: Extra 50% off furniture today!",
            ),
            CandidateMessage(
                id="msg_test_2",
                thread_id="thr_test_2",
                date="2026-09-10",
                sender="Fidelity <alerts@fidelity.com>",
                recipient="me@example.com",
                subject="Your account statement is ready",
            ),
        ]

        args = argparse.Namespace(
            query="in:inbox",
            limit=10,
            purpose="test_scan",
        )

        retcode = cmd_triage_scan(mock_retriever, args)
        assert retcode == 0

        captured = capsys.readouterr().out
        assert "INBOX TRIAGE POLICY SCAN BREAKDOWN" in captured
        assert "TRASH: 1" in captured
        assert "KEEP/PROTECT: 1" in captured

    def test_cmd_triage_plan_generates_staged_bundle(self, capsys, tmp_path, monkeypatch):
        from gmail_local.cli import cmd_triage_plan
        import argparse

        monkeypatch.setattr("gmail_local.triage.PLANS_DIR", tmp_path)

        mock_retriever = MagicMock()
        mock_retriever.search_messages.return_value = [
            CandidateMessage(
                id="msg_test_promo",
                thread_id="thr_test_promo",
                date="2026-09-10",
                sender="Deals <deals@wayfair.com>",
                recipient="me@example.com",
                subject="Clearance: Extra 50% off furniture today!",
            ),
        ]

        args = argparse.Namespace(
            query="category:promotions",
            limit=10,
            action="trash",
            purpose="test_plan",
        )

        retcode = cmd_triage_plan(mock_retriever, args)
        assert retcode == 0

        captured = capsys.readouterr().out
        assert "GENERATED 1 STAGED CLEANUP PLAN(S) VIA TRIAGE ENGINE" in captured
        assert "Target Action:  TRASH" in captured
        assert "cleanup apply --plan" in captured
