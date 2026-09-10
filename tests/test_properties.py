"""Property-based invariant testing using Hypothesis.

Verifies structural invariants, path-traversal immunity, RFC-2047 decoding robustness,
HTML text extraction safety, and RateLimiter rolling window invariants across arbitrary inputs.
"""

from pathlib import Path
from typing import List, Tuple
import pytest
from hypothesis import given, settings, strategies as st

from gmail_local.config import RATE_LIMIT_MAX_UNITS, RATE_LIMIT_WINDOW_SECS
from gmail_local.mime_utils import (
    decode_rfc2047_header,
    html_to_plain_text,
    sanitize_filename,
)
from gmail_local.rate_limiter import RateLimiter, RateLimitExceededError


@pytest.mark.property
class TestMimePropertyInvariants:
    """Hypothesis generative invariant tests for MIME and filename utilities."""

    @given(st.text())
    @settings(max_examples=200)
    def test_sanitize_filename_invariants(self, filename: str) -> None:
        """Every string, no matter how adversarial, must produce a safe single path component."""
        sanitized = sanitize_filename(filename)

        # Invariant 1: Result is always a non-empty string
        assert isinstance(sanitized, str)
        assert len(sanitized) > 0

        # Invariant 2: Result contains no directory separators or null bytes
        assert "/" not in sanitized
        assert "\\" not in sanitized
        assert "\0" not in sanitized

        # Invariant 3: Result contains no forbidden filesystem characters
        forbidden = set('<>:"/\\|?*')
        assert not any(c in forbidden for c in sanitized)
        assert not any(ord(c) < 32 for c in sanitized)

        # Invariant 4: No leading dots or spaces (prevents hidden/traversal files)
        assert not sanitized.startswith(".")
        assert not sanitized.startswith(" ")
        assert not sanitized.endswith(" ")

        # Invariant 5: Safe path containment under any parent directory
        base_dir = Path("/safe/root/directory")
        resolved = base_dir / sanitized
        assert resolved.parent == base_dir
        assert resolved.name == sanitized

    @given(st.text(), st.text(min_size=1, max_size=20).filter(lambda s: "/" not in s and "\\" not in s))
    @settings(max_examples=100)
    def test_sanitize_filename_with_fallback(self, filename: str, fallback: str) -> None:
        """Fallback prefix is used properly when input collapses."""
        sanitized = sanitize_filename(filename, fallback_prefix=fallback)
        assert isinstance(sanitized, str)
        assert len(sanitized) > 0
        assert "/" not in sanitized
        assert "\\" not in sanitized

    @given(st.text())
    @settings(max_examples=200)
    def test_decode_rfc2047_never_crashes(self, header_val: str) -> None:
        """RFC 2047 decoding must never raise an unhandled exception on arbitrary input."""
        result = decode_rfc2047_header(header_val)
        assert isinstance(result, str)
        # If input has no RFC 2047 markers, it should remain string-stripped
        if "=?" not in header_val:
            assert result == header_val.strip()

    @given(st.text())
    @settings(max_examples=150)
    def test_html_to_plain_text_never_crashes(self, raw_html: str) -> None:
        """HTML parser must never crash on arbitrary input and must normalize whitespace."""
        text = html_to_plain_text(raw_html)
        assert isinstance(text, str)
        # No 3+ consecutive newlines in normalized plain text
        assert "\n\n\n" not in text

    @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
    @settings(max_examples=100)
    def test_html_script_tags_stripped(self, script_body: str) -> None:
        """Executable script tags and styles are stripped from plain text extraction."""
        # Ensure script body has no nested script closing tags
        safe_body = script_body.replace("</script>", "").replace("</SCRIPT>", "").replace("</", "")
        html_input = f"<script>{safe_body}</script>"
        result = html_to_plain_text(html_input)
        # Content inside script must be completely ignored
        assert result == ""


@pytest.mark.property
class TestRateLimiterPropertyInvariants:
    """Hypothesis invariant tests for RateLimiter quota tracking."""

    @given(
        st.lists(
            st.tuples(
                st.floats(min_value=0.0, max_value=300.0, allow_nan=False, allow_infinity=False),
                st.sampled_from(["users.messages.list", "users.messages.get", "users.messages.attachments.get"]),
            ),
            min_size=1,
            max_size=60,
        )
    )
    @settings(max_examples=100)
    def test_quota_ceiling_invariant(self, calls: List[Tuple[float, str]]) -> None:
        """Across any sequence of requests, current_units_in_window never exceeds max_units."""
        # Chronologically sort calls
        sorted_calls = sorted(calls, key=lambda c: c[0])
        limiter = RateLimiter(max_units=RATE_LIMIT_MAX_UNITS, window_secs=RATE_LIMIT_WINDOW_SECS)

        for timestamp, method in sorted_calls:
            units_before = limiter.current_units_in_window(now=timestamp)
            assert units_before <= limiter.max_units

            try:
                limiter.acquire_quota(method, now=timestamp)
                # If call succeeded, new window usage must still be <= max_units
                units_after = limiter.current_units_in_window(now=timestamp)
                assert units_after <= limiter.max_units
                assert units_after >= units_before
            except RateLimitExceededError:
                # If call failed, history was not modified
                units_after = limiter.current_units_in_window(now=timestamp)
                assert units_after == units_before

    @given(
        st.floats(min_value=10.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
        st.sampled_from(["users.messages.list", "users.messages.get", "users.messages.attachments.get"]),
    )
    @settings(max_examples=50)
    def test_window_eviction_invariant(self, base_time: float, method: str) -> None:
        """Acquired quota must fully expire after window_secs."""
        limiter = RateLimiter(max_units=RATE_LIMIT_MAX_UNITS, window_secs=RATE_LIMIT_WINDOW_SECS)

        cost = limiter.acquire_quota(method, now=base_time)
        assert limiter.current_units_in_window(now=base_time) == cost

        # Just before window expiry: still counted
        assert limiter.current_units_in_window(now=base_time + RATE_LIMIT_WINDOW_SECS - 0.001) == cost

        # At or after window expiry: evicted
        assert limiter.current_units_in_window(now=base_time + RATE_LIMIT_WINDOW_SECS + 0.001) == 0

    @given(st.integers(min_value=2, max_value=8))
    @settings(max_examples=20)
    def test_concurrent_quota_acquisition_invariant(self, num_threads: int) -> None:
        """Multi-threaded calls must strictly serialize and never exceed max_units."""
        import concurrent.futures

        limiter = RateLimiter(max_units=500, window_secs=60)
        fixed_now = 1000.0

        def worker() -> int:
            successes = 0
            for _ in range(15):
                try:
                    limiter.acquire_quota("users.messages.list", now=fixed_now)
                    successes += 1
                except RateLimitExceededError:
                    pass
            return successes

        with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(worker) for _ in range(num_threads)]
            concurrent.futures.wait(futures)

        # Invariant: Total acquired units must never exceed 500
        current = limiter.current_units_in_window(now=fixed_now)
        assert current <= 500


@pytest.mark.property
class TestTransmissionPropertyInvariants:
    """Hypothesis generative invariant tests for FrozenDraft and MIME composition."""

    email_strategy = st.from_regex(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", fullmatch=True)

    @given(
        st.lists(email_strategy, min_size=1, max_size=5, unique=True),
        st.text(min_size=1, max_size=50).filter(lambda s: "\r" not in s and "\n" not in s and s.strip()),
        st.text(min_size=1, max_size=500),
    )
    @settings(max_examples=50)
    def test_fingerprint_normalization_and_commutativity(
        self, emails: List[str], subject: str, body: str
    ) -> None:
        """Permuting recipient order, casing, or surrounding whitespace must not change fingerprint."""
        from gmail_local.models import FrozenDraft
        import random

        # Original
        d1 = FrozenDraft(to=emails, subject=subject, body_text=body)
        fp1 = d1.compute_fingerprint()

        # Permuted order with randomized case and whitespace
        permuted_emails = []
        for e in emails:
            cased = "".join(c.upper() if random.random() > 0.5 else c.lower() for c in e)
            padded = f"  {cased}  "
            permuted_emails.append(padded)
        random.shuffle(permuted_emails)

        d2 = FrozenDraft(to=permuted_emails, subject=f" {subject} ", body_text=body)
        fp2 = d2.compute_fingerprint()

        assert fp1 == fp2
        assert len(fp1) == 64

    @given(
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r\n\x00,;"),
            min_size=0,
            max_size=30,
        ),
        st.sampled_from(["\r", "\n", "\r\n", "\n\r"]),
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r\n\x00,;"),
            min_size=0,
            max_size=30,
        ),
    )
    @settings(max_examples=50)
    def test_crlf_rejection_invariant(self, prefix: str, crlf: str, suffix: str) -> None:
        """Any carriage return or newline in subject or addresses must strictly fail validation."""
        from gmail_local.models import FrozenDraft, FrozenDraftValidationError

        crlf_str = f"{prefix}{crlf}{suffix}"

        # In subject
        with pytest.raises(FrozenDraftValidationError, match="CRLF"):
            FrozenDraft(to=["user@example.com"], subject=crlf_str, body_text="hello").validate()

        # In recipient
        with pytest.raises(FrozenDraftValidationError, match="CRLF"):
            FrozenDraft(to=[f"user{crlf_str}@example.com"], subject="Valid Subject", body_text="hello").validate()

    @given(
        st.integers(min_value=11, max_value=50),
    )
    @settings(max_examples=20)
    def test_recipient_bound_invariant(self, recipient_count: int) -> None:
        """Exceeding 10 recipients must always raise FrozenDraftValidationError."""
        from gmail_local.models import FrozenDraft, FrozenDraftValidationError

        recipients = [f"user{i}@example.com" for i in range(recipient_count)]
        draft = FrozenDraft(to=recipients, subject="Hi", body_text="Hello")
        with pytest.raises(FrozenDraftValidationError, match="exceeds maximum bound of 10"):
            draft.validate()

    @given(
        st.text(min_size=1, max_size=2000),
    )
    @settings(max_examples=40)
    def test_mime_roundtrip_payload_integrity(self, body_text: str) -> None:
        """Arbitrary unicode text in body must round-trip through base64url payload perfectly."""
        import base64
        from email import message_from_bytes
        from email.policy import default
        from gmail_local.composer import build_draft_payload
        from gmail_local.models import FrozenDraft

        draft = FrozenDraft(to=["user@example.com"], subject="Unicode Test", body_text=body_text)
        payload = build_draft_payload(draft)

        raw_str = payload["message"]["raw"]
        padding = 4 - (len(raw_str) % 4)
        if padding and padding < 4:
            raw_str += "=" * padding

        decoded_bytes = base64.urlsafe_b64decode(raw_str)
        reconstructed = message_from_bytes(decoded_bytes, policy=default)

        # Invariant: Extracted text matches original text after RFC 5322 line ending normalization
        expected_body = body_text.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n")
        assert reconstructed.get_content().rstrip("\r\n") == expected_body


@pytest.mark.property
class TestModificationPropertyInvariants:
    """Hypothesis generative invariant tests for CleanupPlan and mailbox modification bounds."""

    msg_id_strategy = st.from_regex(r"[a-f0-9]{16}", fullmatch=True)

    @given(
        st.lists(msg_id_strategy, min_size=1, max_size=10, unique=True),
        st.text(min_size=1, max_size=40).filter(lambda s: "\r" not in s and "\n" not in s and s.strip()),
    )
    @settings(max_examples=40)
    def test_cleanup_plan_fingerprint_commutativity(self, msg_ids: List[str], query: str) -> None:
        """Permuting target message order or surrounding whitespace must not change fingerprint."""
        from gmail_local.models import CleanupAction, CleanupPlan, CleanupTarget
        import random

        targets1 = [
            CleanupTarget(
                message_id=mid,
                thread_id=f"th_{mid}",
                sender="sender@example.com",
                subject="Subject",
                date="2026-09-01",
                action=CleanupAction.TRASH,
            )
            for mid in msg_ids
        ]
        p1 = CleanupPlan(query=query, action_type=CleanupAction.TRASH, targets=targets1)
        fp1 = p1.compute_fingerprint()

        # Permute target order and add padding to query
        targets2 = list(targets1)
        random.shuffle(targets2)
        p2 = CleanupPlan(query=f"  {query}  ", action_type=CleanupAction.TRASH, targets=targets2)
        fp2 = p2.compute_fingerprint()

        assert fp1 == fp2
        assert len(fp1) == 64

    @given(
        st.integers(min_value=76, max_value=150),
    )
    @settings(max_examples=20)
    def test_cleanup_batch_ceiling_invariant(self, target_count: int) -> None:
        """Target count exceeding 75 messages must always raise CleanupPlanValidationError."""
        from gmail_local.models import CleanupAction, CleanupPlan, CleanupPlanValidationError, CleanupTarget

        targets = [
            CleanupTarget(
                message_id=f"msg_{i}",
                thread_id=f"th_{i}",
                sender="s@e.com",
                subject=f"Sub {i}",
                date="2026-09-01",
                action=CleanupAction.TRASH,
            )
            for i in range(target_count)
        ]
        plan = CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=targets)
        with pytest.raises(CleanupPlanValidationError, match="exceeds maximum batch bound of 75"):
            plan.validate()

    @given(
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r\n\x00"),
            min_size=0,
            max_size=20,
        ),
        st.sampled_from(["\r", "\n", "\r\n", "\n\r"]),
        st.text(
            alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters="\r\n\x00"),
            min_size=0,
            max_size=20,
        ),
    )
    @settings(max_examples=40)
    def test_cleanup_crlf_rejection_invariant(self, prefix: str, crlf: str, suffix: str) -> None:
        """Any CRLF characters in target message_id or label must strictly fail validation."""
        from gmail_local.models import CleanupAction, CleanupPlan, CleanupPlanValidationError, CleanupTarget

        bad_val = f"{prefix}{crlf}{suffix}"

        # Bad message_id
        t1 = CleanupTarget(
            message_id=bad_val,
            thread_id="th1",
            sender="s@e.com",
            subject="Sub",
            date="2026-09-01",
            action=CleanupAction.TRASH,
        )
        with pytest.raises(CleanupPlanValidationError, match="CRLF"):
            CleanupPlan(query="test", action_type=CleanupAction.TRASH, targets=[t1]).validate()

        # Bad label
        t2 = CleanupTarget(
            message_id="msg123",
            thread_id="th1",
            sender="s@e.com",
            subject="Sub",
            date="2026-09-01",
            action=CleanupAction.ADD_LABEL,
            add_labels=[bad_val],
        )
        with pytest.raises(CleanupPlanValidationError, match="CRLF"):
            CleanupPlan(query="test", action_type=CleanupAction.ADD_LABEL, targets=[t2]).validate()

