"""Unit tests for the autonomous inbox triage engine, classifier, and CLI."""

import argparse
import json
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from gmail_local.triage import (
    SenderCluster,
    TriageAction,
    TriageCategory,
    TriageClassifier,
    TriageDecision,
    TriageManifest,
    TriagePlanGenerator,
    TriagePolicy,
    TriageScanner,
    extract_sender_domain,
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


class TestTriagePolicyCustomization:
    """Unit tests for operator policy serialization, deserialization, and custom rules."""

    def test_policy_to_and_from_dict(self):
        policy = TriagePolicy(
            name="custom_test_policy",
            whitelist_senders=["vip@client.com"],
            blacklist_senders=["annoying@junk.com"],
            archive_senders=["digest@news.com"],
            custom_promo_keywords=["huge clearance"],
            custom_protect_keywords=["mortgage refi"],
        )
        d = policy.to_dict()
        restored = TriagePolicy.from_dict(d)
        assert restored.name == "custom_test_policy"
        assert "vip@client.com" in restored.whitelist_senders
        assert "annoying@junk.com" in restored.blacklist_senders
        assert "huge clearance" in restored.custom_promo_keywords

    def test_save_and_load_policy_file(self, tmp_path):
        policy_file = tmp_path / "custom_policy.json"
        policy = TriagePolicy(
            name="disk_policy",
            whitelist_senders=["lawyer@firm.com"],
        )
        saved = policy.save(policy_file)
        assert saved.exists()

        loaded = TriagePolicy.load(policy_file)
        assert loaded.name == "disk_policy"
        assert "lawyer@firm.com" in loaded.whitelist_senders

    def test_operator_whitelist_overrides_everything(self):
        policy = TriagePolicy(whitelist_senders=["deal_alert@vipclub.com"])
        classifier = TriageClassifier(policy=policy)
        decision = classifier.classify(
            message_id="wl_1",
            thread_id="t_wl_1",
            sender="deal_alert@vipclub.com",
            subject="50% off clearance flash sale",  # Promotional subject
            date="2026-09-10",
        )
        assert decision.is_protected is True
        assert decision.action == TriageAction.KEEP
        assert decision.category == TriageCategory.OPERATOR_WHITELIST

    def test_operator_blacklist_marks_trash(self):
        policy = TriagePolicy(blacklist_senders=["spammybrand.com"])
        classifier = TriageClassifier(policy=policy)
        decision = classifier.classify(
            message_id="bl_1",
            thread_id="t_bl_1",
            sender="Newsletter <news@spammybrand.com>",
            subject="Daily updates for you",
            date="2026-09-10",
        )
        assert decision.is_protected is False
        assert decision.action == TriageAction.TRASH
        assert decision.category == TriageCategory.OPERATOR_BLACKLIST

    def test_custom_protect_keyword_overrides_promo(self):
        policy = TriagePolicy(custom_protect_keywords=["escrow statement"])
        classifier = TriageClassifier(policy=policy)
        decision = classifier.classify(
            message_id="cpk_1",
            thread_id="t_cpk_1",
            sender="title@deals.com",
            subject="Save 20% on closing costs with your escrow statement",
            date="2026-09-10",
        )
        assert decision.is_protected is True
        assert decision.action == TriageAction.KEEP


class TestTriageScannerAndClustering:
    """Unit tests for domain clustering and scan manifest persistence."""

    def test_extract_sender_domain(self):
        assert extract_sender_domain("John Doe <john@example.com>") == "example.com"
        assert extract_sender_domain("news@theathletic.com") == "theathletic.com"
        assert extract_sender_domain("bare_string") == "unknown"

    def test_cluster_candidates_aggregates_and_sorts(self):
        candidates = [
            CandidateMessage(id="1", thread_id="t1", date="2026-09-10", sender="A <a@store.com>", recipient="me", subject="Deal 1"),
            CandidateMessage(id="2", thread_id="t2", date="2026-09-10", sender="B <b@store.com>", recipient="me", subject="Deal 2"),
            CandidateMessage(id="3", thread_id="t3", date="2026-09-10", sender="Bank <alerts@bank.com>", recipient="me", subject="Account statement"),
        ]
        scanner = TriageScanner(TriageClassifier())
        clusters = scanner.cluster_candidates(candidates)

        assert len(clusters) == 2
        # store.com should be rank 1 with 2 messages
        assert clusters[0].domain == "store.com"
        assert clusters[0].message_count == 2
        assert clusters[1].domain == "bank.com"
        assert clusters[1].message_count == 1
        assert clusters[1].recommended_action == TriageAction.KEEP

    def test_manifest_save_and_dict(self, tmp_path):
        manifest = TriageManifest(
            run_id="20260910_test",
            timestamp="2026-09-10T12:00:00Z",
            query="in:inbox",
            total_scanned=25,
            action_counts={"trash": 10, "archive": 10, "keep": 5},
            category_counts={"promotions": 10},
            top_clusters=[{"domain": "promo.com", "count": 10}],
            staged_plan_fingerprints=["fp123456"],
        )
        saved = manifest.save(triage_dir=tmp_path)
        assert saved.exists()
        loaded = json.loads(saved.read_text(encoding="utf-8"))
        assert loaded["run_id"] == "20260910_test"
        assert loaded["total_scanned"] == 25


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
            action=TriageAction.TRASH,
            rule_name="err",
            confidence=0.5,
            is_protected=True,
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
    """Unit tests for CLI commands."""

    def test_cmd_triage_scan_with_candidates(self, capsys):
        from gmail_local.cli import cmd_triage_scan

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
            policy=None,
            purpose="test_scan",
        )

        retcode = cmd_triage_scan(mock_retriever, args)
        assert retcode == 0

        captured = capsys.readouterr().out
        assert "INBOX TRIAGE POLICY SCAN BREAKDOWN" in captured
        assert "TRASH: 1" in captured
        assert "KEEP/PROTECT: 1" in captured

    def test_cmd_triage_clusters(self, capsys):
        from gmail_local.cli import cmd_triage_clusters

        mock_retriever = MagicMock()
        mock_retriever.search_messages.return_value = [
            CandidateMessage(
                id="msg_test_1",
                thread_id="thr_test_1",
                date="2026-09-10",
                sender="Deals <deals@wayfair.com>",
                recipient="me@example.com",
                subject="Clearance deals",
            ),
            CandidateMessage(
                id="msg_test_2",
                thread_id="thr_test_2",
                date="2026-09-10",
                sender="Deals <support@wayfair.com>",
                recipient="me@example.com",
                subject="Another clearance deal",
            ),
        ]

        args = argparse.Namespace(
            query="in:inbox",
            limit=10,
            policy=None,
            purpose="test_clusters",
        )

        retcode = cmd_triage_clusters(mock_retriever, args)
        assert retcode == 0

        captured = capsys.readouterr().out
        assert "INBOX SENDER DOMAIN CLUSTERS & VOLUME BREAKDOWN" in captured
        assert "wayfair.com" in captured

    def test_cmd_triage_policy_show_and_init(self, capsys, tmp_path):
        from gmail_local.cli import cmd_triage_policy_show, cmd_triage_policy_init

        mock_retriever = MagicMock()
        show_args = argparse.Namespace(policy=None)
        assert cmd_triage_policy_show(mock_retriever, show_args) == 0
        assert "TRIAGE POLICY CONFIGURATION" in capsys.readouterr().out

        init_file = tmp_path / "new_policy.json"
        init_args = argparse.Namespace(path=init_file, force=False)
        assert cmd_triage_policy_init(mock_retriever, init_args) == 0
        assert init_file.exists()
