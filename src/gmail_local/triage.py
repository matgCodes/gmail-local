"""Autonomous AFK Inbox Triage Engine & Policy Classifier.

Classifies email metadata against hierarchical safety rules:
1. PROTECT (Financial, Invoices/Receipts, 2FA/Security, Travel, Personal) -> KEEP
2. PROMOTIONS (Sales, Expired coupons, Marketing blasts) -> TRASH
3. NEWSLETTERS / DIGESTS (Daily briefings, Curated roundups) -> ARCHIVE
4. DEFAULT / UNKNOWN -> KEEP

Partitions candidates into discrete, fingerprinted CleanupPlan artifacts (<= 50 targets each)
enforcing ADR 0010 and ADR 0011 safety boundaries.
"""

from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from gmail_local.config import PLANS_DIR, STATE_DIR
from gmail_local.models import (
    CleanupAction,
    CleanupPlan,
    CleanupTarget,
)

TRIAGE_DIR = STATE_DIR / "triage"


class TriageCategory(str, Enum):
    """Semantic category assigned by the triage policy classifier."""
    PROTECTED_FINANCIAL = "protected_financial"
    PROTECTED_TRANSACTION = "protected_transaction"
    PROTECTED_SECURITY = "protected_security"
    PROTECTED_TRAVEL = "protected_travel"
    PROTECTED_PERSONAL = "protected_personal"
    PROTECTED_LEGAL_GOV = "protected_legal_gov"
    PROMOTION_DISCOUNT = "promotion_discount"
    NEWSLETTER_DIGEST = "newsletter_digest"
    NOTIFICATION_SOCIAL = "notification_social"
    NOTIFICATION_SYSTEM = "notification_system"
    UNCATEGORIZED = "uncategorized"


class TriageAction(str, Enum):
    """Triage recommended mailbox action."""
    KEEP = "keep"
    ARCHIVE = "archive"
    TRASH = "trash"


@dataclass(frozen=True)
class TriageDecision:
    """Individual triage classification decision for a message."""
    message_id: str
    thread_id: str
    sender: str
    subject: str
    date: str
    category: TriageCategory
    action: TriageAction
    rule_name: str
    confidence: float
    is_protected: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "thread_id": self.thread_id,
            "sender": self.sender,
            "subject": self.subject,
            "date": self.date,
            "category": self.category.value,
            "action": self.action.value,
            "rule_name": self.rule_name,
            "confidence": self.confidence,
            "is_protected": self.is_protected,
            "reason": self.reason,
        }


@dataclass
class TriagePolicy:
    """Rules and pattern definitions governing triage categorization."""
    name: str = "default_safety_policy"

    # Compiled regex patterns for protected categories (Zero False-Positive Target)
    financial_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(account statement|checking balance|tax form|1099|w-2|irs|tax return|portfolio|dividend|brokerage)\b", re.I),
        re.compile(r"@(chase|wellsfargo|fidelity|vanguard|americanexpress|citi|bankofamerica|capitalone)\.com", re.I),
    ])

    transaction_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(receipt|invoice|your order|has shipped|ready for pickup|trip with uber|payment received|payment to|billing)\b", re.I),
        re.compile(r"@(amazon|apple|paypal|stripe|bestbuy|target|walmart)\.com", re.I),
    ])

    security_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(security alert|verification code|authentication code|passcode is|password reset|verify your device|one-time code|2fa|mfa)\b", re.I),
        re.compile(r"@(accounts\.google|auth0|github|discord|okta)\.com", re.I),
    ])

    travel_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(itinerary|eticket|flight confirmation|reservation confirmed|boarding pass|travel receipt|check-in is available)\b", re.I),
        re.compile(r"@(united|delta|aa|southwest|airbnb|amtrak|booking|expedia)\.com", re.I),
    ])

    personal_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(contract review|project timeline|dinner plans|lunch plans|coffee|sync up|catch up|quick call|one-on-one|notes on|remodel)\b", re.I),
    ])

    # Promotional cues
    promotional_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(flash sale|clearance|% off|coupons?|deals are live|ends tonight|save up to|special offer|doorbuster|promo code)\b", re.I),
        re.compile(r"@(deals\.|email\.|marketing\.|promo\.|response\.|offers\.)", re.I),
    ])

    # Newsletter digests
    newsletter_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"\b(morning wire|pulse:|the athletic pulse|morning brief|daily brief|robinhood snacks|snacks:|newsletter|weekly roundup|roundup)\b", re.I),
        re.compile(r"@(theepochtimes|apnews|e1\.theathletic|response\.cnbc|snacks\.robinhood)\.com", re.I),
    ])

    @classmethod
    def default(cls) -> "TriagePolicy":
        return cls()


class TriageClassifier:
    """Evaluates message metadata against triage safety policies."""

    def __init__(self, policy: Optional[TriagePolicy] = None):
        self.policy = policy or TriagePolicy.default()

    def classify(
        self,
        message_id: str,
        thread_id: str,
        sender: str,
        subject: str,
        date: str = "",
        labels: Optional[List[str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> TriageDecision:
        combined_text = f"{sender} {subject}"
        labels = labels or []
        headers = headers or {}

        # --------------------------------------------------------------------
        # TIER 1: PROTECT INVARIANTS (Zero False-Positive Tolerance)
        # Any match here forces action=KEEP and is_protected=True.
        # --------------------------------------------------------------------

        # 1.1 Financial
        for pat in self.policy.financial_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_FINANCIAL,
                    action=TriageAction.KEEP,
                    rule_name="protect_financial_rule",
                    confidence=1.0,
                    is_protected=True,
                    reason="Matched protected financial or tax pattern",
                )

        # 1.2 Transactions & Receipts (Overrides promotional words if present)
        for pat in self.policy.transaction_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_TRANSACTION,
                    action=TriageAction.KEEP,
                    rule_name="protect_transaction_rule",
                    confidence=1.0,
                    is_protected=True,
                    reason="Matched protected purchase receipt or invoice pattern",
                )

        # 1.3 Security & 2FA
        for pat in self.policy.security_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_SECURITY,
                    action=TriageAction.KEEP,
                    rule_name="protect_security_rule",
                    confidence=1.0,
                    is_protected=True,
                    reason="Matched protected security alert or authentication code",
                )

        # 1.4 Travel & Itineraries
        for pat in self.policy.travel_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_TRAVEL,
                    action=TriageAction.KEEP,
                    rule_name="protect_travel_rule",
                    confidence=1.0,
                    is_protected=True,
                    reason="Matched protected travel reservation or ticket itinerary",
                )

        # 1.5 Personal Correspondence
        # Direct user replies, conversation threads, or personal pattern cues
        for pat in self.policy.personal_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_PERSONAL,
                    action=TriageAction.KEEP,
                    rule_name="protect_personal_cue_rule",
                    confidence=0.95,
                    is_protected=True,
                    reason="Matched personal correspondence topic pattern",
                )

        if subject.lower().startswith("re: ") or subject.lower().startswith("fwd: "):
            # If it doesn't match promotional/marketing senders, treat as personal thread
            if not any(pat.search(sender) for pat in self.policy.promotional_patterns):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_PERSONAL,
                    action=TriageAction.KEEP,
                    rule_name="protect_personal_reply_rule",
                    confidence=0.95,
                    is_protected=True,
                    reason="Detected 1-on-1 personal reply or thread",
                )

        # --------------------------------------------------------------------
        # TIER 2: CANDIDATES FOR TRASH (Promotions & Marketing Blasts)
        # --------------------------------------------------------------------
        has_promo_label = "CATEGORY_PROMOTIONS" in labels
        matched_promo_pattern = any(pat.search(combined_text) for pat in self.policy.promotional_patterns)

        if matched_promo_pattern or has_promo_label:
            # Re-verify no personal cues
            if not subject.lower().startswith("re: "):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROMOTION_DISCOUNT,
                    action=TriageAction.TRASH,
                    rule_name="promo_discount_rule",
                    confidence=0.95,
                    is_protected=False,
                    reason="Matched promotional offer or marketing pattern",
                )

        # --------------------------------------------------------------------
        # TIER 3: CANDIDATES FOR ARCHIVE (Newsletters & Digests)
        # --------------------------------------------------------------------
        for pat in self.policy.newsletter_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.NEWSLETTER_DIGEST,
                    action=TriageAction.ARCHIVE,
                    rule_name="newsletter_digest_rule",
                    confidence=0.90,
                    is_protected=False,
                    reason="Matched news briefing or recurring digest",
                )

        # --------------------------------------------------------------------
        # TIER 4: DEFAULT UNKNOWN -> SAFE KEEP
        # --------------------------------------------------------------------
        return TriageDecision(
            message_id=message_id,
            thread_id=thread_id,
            sender=sender,
            subject=subject,
            date=date,
            category=TriageCategory.UNCATEGORIZED,
            action=TriageAction.KEEP,
            rule_name="default_keep_safe",
            confidence=0.50,
            is_protected=False,
            reason="Uncertain classification; safely defaulted to KEEP in inbox",
        )


class TriagePlanGenerator:
    """Generates partitioned, fingerprinted CleanupPlan artifacts from triage decisions."""

    def __init__(self, plans_dir: Path = PLANS_DIR):
        self.plans_dir = plans_dir
        self.plans_dir.mkdir(parents=True, exist_ok=True)

    def generate_staged_plans(
        self,
        decisions: List[TriageDecision],
        action_filter: Optional[TriageAction] = None,
        max_batch_size: int = 50,
        query: str = "triage_scan",
    ) -> List[CleanupPlan]:
        """Partitions decisions into discrete CleanupPlans of at most max_batch_size (ceiling: 50)."""
        max_batch = min(max_batch_size, 50)
        target_action = action_filter or TriageAction.TRASH

        # Filter candidate decisions
        candidates = [d for d in decisions if d.action == target_action and not d.is_protected]

        if not candidates:
            return []

        cleanup_action = CleanupAction.TRASH if target_action == TriageAction.TRASH else CleanupAction.ARCHIVE

        plans: List[CleanupPlan] = []
        for i in range(0, len(candidates), max_batch):
            chunk = candidates[i: i + max_batch]
            targets: List[CleanupTarget] = []
            for d in chunk:
                add_labels: List[str] = []
                remove_labels: List[str] = []
                if cleanup_action == CleanupAction.ARCHIVE:
                    remove_labels = ["INBOX"]

                targets.append(
                    CleanupTarget(
                        message_id=d.message_id,
                        thread_id=d.thread_id,
                        sender=d.sender,
                        subject=d.subject,
                        date=d.date,
                        action=cleanup_action,
                        add_labels=add_labels,
                        remove_labels=remove_labels,
                    )
                )

            # Build and validate plan
            plan = CleanupPlan(
                query=f"{query}_part_{len(plans)+1}",
                action_type=cleanup_action,
                targets=targets,
            )
            plan.validate()

            # Persist artifact
            plan_path = self.plans_dir / f"{plan.fingerprint}.json"
            plan_path.write_text(json.dumps(plan.to_dict(), indent=2), encoding="utf-8")
            plans.append(plan)

        return plans
