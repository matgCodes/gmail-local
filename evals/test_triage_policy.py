"""Evaluation benchmark for autonomous inbox triage, opportunity extraction, and protection invariants."""

import pytest
from gmail_local.models import CleanupAction
from gmail_local.triage import (
    ExtractedJobPosting,
    GovernmentJobsExtractor,
    TriageAction,
    TriageCategory,
    TriageClassifier,
    TriagePlanGenerator,
    TriagePolicy,
)

SAMPLE_GOVERNMENT_JOBS_BODY = """
*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*
PLEASE DO NOT REPLY TO THIS E-MAIL
*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*---*

Dear Mathew,

County of Orange is now accepting applications for the following position(s):

Data Entry Specialist (https://www.governmentjobs.com/careers/oc/jobs/5475418)
Staff Specialist (https://www.governmentjobs.com/careers/oc/jobs/5469241)
Laborer - Part-Time (Maintenance & Operations) - Grant Funded (https://www.governmentjobs.com/careers/oc/jobs/5471787)

Click on a job title to view the complete job posting of any position listed.
"""


def test_government_jobs_extraction_precision():
    """Benchmark: Verify 100% parsing accuracy on multi-job emails and nested parentheses."""
    subject = "County of Orange Job Interest Card Notification"
    jobs = GovernmentJobsExtractor.extract_from_text(
        body_text=SAMPLE_GOVERNMENT_JOBS_BODY,
        subject=subject,
        date_str="2026-09-10",
        email_id="msg-123",
    )

    assert len(jobs) == 3

    # 1. Data Entry Specialist
    assert jobs[0].job_id == "5475418"
    assert jobs[0].title == "Data Entry Specialist"
    assert jobs[0].agency == "County of Orange"
    assert jobs[0].agency_slug == "oc"
    assert jobs[0].tier == 1  # Data keyword
    assert "data" in jobs[0].match_reason.lower()

    # 2. Staff Specialist
    assert jobs[1].job_id == "5469241"
    assert jobs[1].title == "Staff Specialist"
    assert jobs[1].tier == 1  # Specialist keyword

    # 3. Laborer with nested parentheses
    assert jobs[2].job_id == "5471787"
    assert jobs[2].title == "Laborer - Part-Time (Maintenance & Operations) - Grant Funded"
    assert jobs[2].tier == 3  # General


def test_government_jobs_deduplication_within_email():
    """Benchmark: Identical job IDs in the same email body must be deduplicated."""
    duplicate_body = """
    Data Analyst (https://www.governmentjobs.com/careers/santaana/jobs/11111)
    Data Analyst (https://www.governmentjobs.com/careers/santaana/jobs/11111)
    """
    jobs = GovernmentJobsExtractor.extract_from_text(
        body_text=duplicate_body,
        subject="City of Santa Ana Job Interest Card Notification",
    )
    assert len(jobs) == 1
    assert jobs[0].job_id == "11111"


def test_protected_emails_never_trashed():
    """Hard Invariant: Financial, security, tax, and travel emails MUST NEVER yield action=trash."""
    classifier = TriageClassifier()
    protected_cases = [
        ("service@paypal.com", "Your receipt from Acme Corp"),
        ("billing@stripe.com", "Invoice #1042 paid"),
        ("no-reply@accounts.google.com", "Your Google verification code is 123456"),
        ("security@bankofamerica.com", "Security Alert: Unusual sign-in attempt"),
        ("irs@tax.gov", "Your W-2 tax document is ready for review"),
        ("reservations@united.com", "Your flight confirmation and boarding pass"),
    ]

    for sender, subject in protected_cases:
        dec = classifier.classify(
            message_id="msg-prot",
            thread_id="th-prot",
            sender=sender,
            subject=subject,
            date="2026-09-10",
        )
        assert dec.action != TriageAction.TRASH, f"Violation: Trashing protected email '{subject}'"
        assert dec.is_protected is True
        assert dec.action == TriageAction.KEEP, f"Expected protected email to remain in inbox: '{subject}'"


def test_opportunity_alerts_yield_archive():
    """Safety Policy: Opportunity alerts should be archived, never trashed autonomously."""
    classifier = TriageClassifier()
    dec = classifier.classify(
        message_id="msg-opp",
        thread_id="th-opp",
        sender="info@governmentjobs.com",
        subject="City of Santa Ana Job Interest Card Notification",
        date="2026-09-10",
    )
    assert dec.category == TriageCategory.OPPORTUNITY_ALERT
    assert dec.action == TriageAction.ARCHIVE


def test_newsletters_yield_archive():
    """Safety Policy: Newsletters should be archived rather than trashed."""
    classifier = TriageClassifier()
    dec = classifier.classify(
        message_id="msg-news",
        thread_id="th-news",
        sender="newsletter@theepochtimes.com",
        subject="Morning Brief",
        date="2026-09-10",
    )
    assert dec.category == TriageCategory.NEWSLETTER_DIGEST
    assert dec.action == TriageAction.ARCHIVE


def test_promotions_yield_trash():
    """Policy: Commercial promotional blasts are candidates for soft-deletion."""
    classifier = TriageClassifier()
    dec = classifier.classify(
        message_id="msg-promo",
        thread_id="th-promo",
        sender="offers@marketing.brand.com",
        subject="50% off flash sale ends tonight!",
        date="2026-09-10",
        labels=["CATEGORY_PROMOTIONS"],
    )
    assert dec.category == TriageCategory.PROMOTION_DISCOUNT
    assert dec.action == TriageAction.TRASH


def test_plan_generator_partitions_at_50_limit(tmp_path):
    """Batch Boundary Invariant: Staged plans must never exceed 50 targets per plan."""
    classifier = TriageClassifier()
    decisions = []
    for i in range(120):
        d = classifier.classify(
            message_id=f"msg-{i}",
            thread_id=f"th-{i}",
            sender="promo@store.com",
            subject=f"Special Offer {i}",
            date="2026-09-10",
            labels=["CATEGORY_PROMOTIONS"],
        )
        decisions.append(d)

    generator = TriagePlanGenerator(plans_dir=tmp_path)
    plans = generator.generate_staged_plans(
        decisions=decisions,
        action_filter=TriageAction.TRASH,
        max_batch_size=50,
    )

    assert len(plans) == 3
    assert len(plans[0].targets) == 50
    assert len(plans[1].targets) == 50
    assert len(plans[2].targets) == 20
    for p in plans:
        assert p.fingerprint is not None
        assert p.action_type == CleanupAction.TRASH
