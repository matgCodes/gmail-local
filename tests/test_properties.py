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
