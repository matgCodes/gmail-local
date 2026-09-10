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
import email.utils
from typing import Any, Dict, List, Optional, Tuple

from gmail_local.config import CONFIG_DIR, PLANS_DIR, STATE_DIR
from gmail_local.models import (
    CandidateMessage,
    CleanupAction,
    CleanupPlan,
    CleanupTarget,
)

TRIAGE_DIR = STATE_DIR / "triage"
DEFAULT_POLICY_FILE = CONFIG_DIR / "triage_policy.json"


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
    OPPORTUNITY_ALERT = "opportunity_alert"
    OPERATOR_WHITELIST = "operator_whitelist"
    OPERATOR_BLACKLIST = "operator_blacklist"
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
class SenderCluster:
    """Aggregated volume and triage recommendations for a sender domain cohort."""
    domain: str
    message_count: int
    sender_addresses: List[str]
    recommended_action: TriageAction
    category: TriageCategory
    sample_subjects: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "message_count": self.message_count,
            "sender_addresses": list(self.sender_addresses),
            "recommended_action": self.recommended_action.value,
            "category": self.category.value,
            "sample_subjects": list(self.sample_subjects),
        }


def extract_sender_domain(sender_str: str) -> str:
    """Extracts clean domain host from RFC 822 From: header string."""
    _, addr = email.utils.parseaddr(sender_str)
    if "@" in addr:
        return addr.split("@", 1)[1].lower().strip()
    return "unknown"


# Target match keywords based on JOB_SEARCH_RUNBOOK.md
TIER_1_KEYWORDS = [
    "analyst", "programmer", "data", "developer", "software", "systems",
    "specialist", "coordinator", "intern", "internship", "project",
    "it ", "information technology", "gis", "research", "records",
    "emergency services", "development specialist", "technical", "engineering",
    "sustainability", "climate", "broadband", "civic", "reporting", "database"
]

TIER_2_KEYWORDS = [
    "inspector", "investigator", "practitioner", "officer", "supervisor",
    "manager", "planner", "education", "compliance", "technician", "assistant",
    "examiner", "appraiser", "buyer", "sanitarian"
]


@dataclass(frozen=True)
class ExtractedJobPosting:
    """A structured job posting extracted from an alert email."""
    job_id: str
    title: str
    agency: str
    agency_slug: str
    url: str
    date: str
    email_id: str
    tier: int = 3
    match_reason: str = "General Municipal Posting"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "title": self.title,
            "agency": self.agency,
            "agency_slug": self.agency_slug,
            "url": self.url,
            "date": self.date,
            "email_id": self.email_id,
            "tier": self.tier,
            "match_reason": self.match_reason,
        }


class GovernmentJobsExtractor:
    """Extracts structured job postings from info@governmentjobs.com notification emails."""

    JOB_PATTERN = re.compile(
        r"^\s*([^\n]+?)\s+\((https://www\.governmentjobs\.com/careers/([^/]+)/jobs/(\d+)[^\)]*)\)",
        re.MULTILINE,
    )

    @classmethod
    def score_title(cls, title: str) -> Tuple[int, str]:
        """Scores a job title against Job Search Runbook priority criteria."""
        t_lower = title.lower()
        for kw in TIER_1_KEYWORDS:
            if kw in t_lower:
                return 1, f"Matched Tier 1 keyword: '{kw}'"
        for kw in TIER_2_KEYWORDS:
            if kw in t_lower:
                return 2, f"Matched Tier 2 keyword: '{kw}'"
        return 3, "General Public Service Posting"

    @classmethod
    def extract_from_text(
        cls, body_text: str, subject: str = "", date_str: str = "", email_id: str = ""
    ) -> List[ExtractedJobPosting]:
        """Parses job postings from raw or extracted email body text."""
        agency = "Government Agency"
        if subject:
            agency_match = re.search(r"^(.+?)\s+Job Interest Card Notification", subject)
            if agency_match:
                agency = agency_match.group(1).strip()

        jobs: List[ExtractedJobPosting] = []
        seen_ids = set()

        for title_raw, url, slug, job_id in cls.JOB_PATTERN.findall(body_text):
            if job_id in seen_ids:
                continue
            seen_ids.add(job_id)
            title = " ".join(title_raw.strip().split())
            tier, reason = cls.score_title(title)
            jobs.append(
                ExtractedJobPosting(
                    job_id=job_id,
                    title=title,
                    agency=agency,
                    agency_slug=slug,
                    url=url,
                    date=date_str,
                    email_id=email_id,
                    tier=tier,
                    match_reason=reason,
                )
            )
        return jobs



@dataclass
class TriagePolicy:
    """Rules and pattern definitions governing triage categorization."""
    name: str = "default_safety_policy"

    # Operator overrides
    whitelist_senders: List[str] = field(default_factory=list)
    blacklist_senders: List[str] = field(default_factory=list)
    archive_senders: List[str] = field(default_factory=list)
    custom_promo_keywords: List[str] = field(default_factory=list)
    custom_protect_keywords: List[str] = field(default_factory=list)

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

    # Opportunity alerts & job notifications
    opportunity_patterns: List[re.Pattern] = field(default_factory=lambda: [
        re.compile(r"info@governmentjobs\.com", re.I),
        re.compile(r"\b(job interest card notification|job alert)\b", re.I),
    ])

    @classmethod
    def default(cls) -> "TriagePolicy":
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        """Serializes user-configurable policy rules to dictionary."""
        return {
            "name": self.name,
            "whitelist_senders": list(self.whitelist_senders),
            "blacklist_senders": list(self.blacklist_senders),
            "archive_senders": list(self.archive_senders),
            "custom_promo_keywords": list(self.custom_promo_keywords),
            "custom_protect_keywords": list(self.custom_protect_keywords),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TriagePolicy":
        """Instantiates TriagePolicy from a dictionary, keeping default safety patterns intact."""
        policy = cls.default()
        policy.name = data.get("name", "custom_policy")
        policy.whitelist_senders = list(data.get("whitelist_senders", []))
        policy.blacklist_senders = list(data.get("blacklist_senders", []))
        policy.archive_senders = list(data.get("archive_senders", []))
        policy.custom_promo_keywords = list(data.get("custom_promo_keywords", []))
        policy.custom_protect_keywords = list(data.get("custom_protect_keywords", []))
        return policy

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "TriagePolicy":
        """Loads policy from file or falls back to default."""
        target_path = path or DEFAULT_POLICY_FILE
        if target_path and target_path.exists():
            try:
                data = json.loads(target_path.read_text(encoding="utf-8"))
                return cls.from_dict(data)
            except Exception:
                return cls.default()
        return cls.default()

    def save(self, path: Optional[Path] = None) -> Path:
        """Saves current policy to JSON file."""
        target_path = path or DEFAULT_POLICY_FILE
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return target_path



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
        domain = extract_sender_domain(sender)

        # --------------------------------------------------------------------
        # TIER 0: OPERATOR WHITELIST (Absolute Override)
        # --------------------------------------------------------------------
        for wl in self.policy.whitelist_senders:
            wl_clean = wl.lower().strip()
            if wl_clean in sender.lower() or wl_clean == domain:
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.OPERATOR_WHITELIST,
                    action=TriageAction.KEEP,
                    rule_name="operator_whitelist",
                    confidence=1.0,
                    is_protected=True,
                    reason=f"Matched operator whitelist rule: '{wl}'",
                )

        # --------------------------------------------------------------------
        # TIER 1: PROTECT INVARIANTS (Zero False-Positive Tolerance)
        # Any match here forces action=KEEP and is_protected=True.
        # --------------------------------------------------------------------

        # Custom protect keywords
        for kw in self.policy.custom_protect_keywords:
            if re.search(r"\b" + re.escape(kw) + r"\b", combined_text, re.I):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.PROTECTED_TRANSACTION,
                    action=TriageAction.KEEP,
                    rule_name="custom_protect_keyword",
                    confidence=1.0,
                    is_protected=True,
                    reason=f"Matched custom protect keyword: '{kw}'",
                )

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
        # TIER 2: OPERATOR BLACKLIST / ARCHIVE OVERRIDES
        # --------------------------------------------------------------------
        for bl in self.policy.blacklist_senders:
            bl_clean = bl.lower().strip()
            if bl_clean in sender.lower() or bl_clean == domain:
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.OPERATOR_BLACKLIST,
                    action=TriageAction.TRASH,
                    rule_name="operator_blacklist",
                    confidence=1.0,
                    is_protected=False,
                    reason=f"Matched operator blacklist rule: '{bl}'",
                )

        for ar in self.policy.archive_senders:
            ar_clean = ar.lower().strip()
            if ar_clean in sender.lower() or ar_clean == domain:
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.NEWSLETTER_DIGEST,
                    action=TriageAction.ARCHIVE,
                    rule_name="operator_archive_rule",
                    confidence=1.0,
                    is_protected=False,
                    reason=f"Matched operator archive sender rule: '{ar}'",
                )

        # --------------------------------------------------------------------
        # TIER 3: CANDIDATES FOR TRASH (Promotions & Marketing Blasts)
        # --------------------------------------------------------------------
        has_promo_label = "CATEGORY_PROMOTIONS" in labels
        matched_promo_pattern = any(pat.search(combined_text) for pat in self.policy.promotional_patterns)
        matched_custom_promo = any(
            re.search(r"\b" + re.escape(kw) + r"\b", combined_text, re.I)
            for kw in self.policy.custom_promo_keywords
        )

        if matched_promo_pattern or has_promo_label or matched_custom_promo:
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
        # TIER 3.5: OPPORTUNITY ALERTS (Job Feeds & GovernmentJobs)
        # --------------------------------------------------------------------
        for pat in self.policy.opportunity_patterns:
            if pat.search(combined_text):
                return TriageDecision(
                    message_id=message_id,
                    thread_id=thread_id,
                    sender=sender,
                    subject=subject,
                    date=date,
                    category=TriageCategory.OPPORTUNITY_ALERT,
                    action=TriageAction.ARCHIVE,
                    rule_name="opportunity_alert_rule",
                    confidence=0.95,
                    is_protected=False,
                    reason="Matched opportunity alert or job interest notification",
                )

        # --------------------------------------------------------------------
        # TIER 4: CANDIDATES FOR ARCHIVE (Newsletters & Digests)
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
        # TIER 5: DEFAULT UNKNOWN -> SAFE KEEP
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


class TriageScanner:
    """High-volume multi-pass scanner and domain clustering analyzer."""

    def __init__(self, classifier: Optional[TriageClassifier] = None):
        self.classifier = classifier or TriageClassifier()

    def cluster_candidates(
        self,
        candidates: List[CandidateMessage],
    ) -> List[SenderCluster]:
        """Groups candidate messages by sender domain and computes aggregated metrics."""
        domain_map: Dict[str, Dict[str, Any]] = {}

        for c in candidates:
            domain = extract_sender_domain(c.sender)
            if domain not in domain_map:
                domain_map[domain] = {
                    "domain": domain,
                    "senders": set(),
                    "subjects": [],
                    "decisions": [],
                }

            domain_map[domain]["senders"].add(c.sender)
            if len(domain_map[domain]["subjects"]) < 3:
                domain_map[domain]["subjects"].append(c.subject)

            # Classify candidate
            decision = self.classifier.classify(
                message_id=c.id,
                thread_id=c.thread_id,
                sender=c.sender,
                subject=c.subject,
                date=c.date,
            )
            domain_map[domain]["decisions"].append(decision)

        clusters: List[SenderCluster] = []
        for domain, info in domain_map.items():
            total = len(info["decisions"])
            action_counts: Dict[TriageAction, int] = {}
            category_counts: Dict[TriageCategory, int] = {}
            is_any_protected = any(d.is_protected for d in info["decisions"])

            for d in info["decisions"]:
                action_counts[d.action] = action_counts.get(d.action, 0) + 1
                category_counts[d.category] = category_counts.get(d.category, 0) + 1

            if is_any_protected:
                rec_action = TriageAction.KEEP
                rec_cat = next((d.category for d in info["decisions"] if d.is_protected), TriageCategory.PROTECTED_TRANSACTION)
            else:
                rec_action = max(action_counts.items(), key=lambda x: x[1])[0]
                rec_cat = max(category_counts.items(), key=lambda x: x[1])[0]

            clusters.append(
                SenderCluster(
                    domain=domain,
                    message_count=total,
                    sender_addresses=sorted(list(info["senders"])),
                    recommended_action=rec_action,
                    category=rec_cat,
                    sample_subjects=info["subjects"],
                )
            )

        clusters.sort(key=lambda x: x.message_count, reverse=True)
        return clusters


@dataclass
class TriageManifest:
    """Immutable record of an AFK triage discovery and classification run."""
    run_id: str
    timestamp: str
    query: str
    total_scanned: int
    action_counts: Dict[str, int]
    category_counts: Dict[str, int]
    top_clusters: List[Dict[str, Any]]
    staged_plan_fingerprints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "query": self.query,
            "total_scanned": self.total_scanned,
            "action_counts": dict(self.action_counts),
            "category_counts": dict(self.category_counts),
            "top_clusters": list(self.top_clusters),
            "staged_plan_fingerprints": list(self.staged_plan_fingerprints),
        }

    def save(self, triage_dir: Path = TRIAGE_DIR) -> Path:
        triage_dir.mkdir(parents=True, exist_ok=True)
        path = triage_dir / f"manifest_{self.run_id}.json"
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return path


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
