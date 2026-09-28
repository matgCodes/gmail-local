"""Read-only free/busy lookup and deterministic open-window engine (ADR 0016, Issue #11).

This module must not import retrieval, composer, or triage, so it can move with the
calendar code later (docs/book-meeting-skill-design.md section 8.4). All window math
runs on UTC instants; the requested timezone is used only to lay out the weekly hours
and to format output.
"""

import datetime
import json
import re
import zoneinfo
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from gmail_local.audit import AuditLogger
from gmail_local.auth import AuthManager
from gmail_local.config import (
    AVAILABILITY_RATE_LIMIT_MAX_UNITS,
    MAX_AVAILABILITY_RANGE_DAYS,
    MAX_AVAILABILITY_WINDOW_COUNT,
    MAX_FREEBUSY_CALENDARS,
)
from gmail_local.models import AuditEntry
from gmail_local.rate_limiter import RateLimiter

UTC = datetime.timezone.utc
WEEKDAY_KEYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
MAX_MINUTES_PER_DAY = 24 * 60

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_DURATION_RE = re.compile(r"^(\d{1,6})([mhd])$")
_DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days"}

Interval = Tuple[datetime.datetime, datetime.datetime]
HourRange = Tuple[datetime.time, datetime.time]


class AvailabilityError(Exception):
    """Base exception for availability operations."""


class AvailabilityValidationError(AvailabilityError):
    """Raised when window request arguments fail validation."""


class FreeBusyError(AvailabilityError):
    """Raised when a freeBusy response cannot be trusted as a complete busy list."""


@dataclass(frozen=True)
class Window:
    """A free stretch as half-open UTC instants."""
    start: datetime.datetime
    end: datetime.datetime

    def to_dict(self, tz: zoneinfo.ZoneInfo) -> Dict[str, str]:
        return {
            "start": self.start.astimezone(tz).isoformat(),
            "end": self.end.astimezone(tz).isoformat(),
        }


@dataclass(frozen=True)
class WindowRequest:
    """Validated arguments for `availability windows`."""
    date_from: datetime.date
    date_to: datetime.date
    tz: zoneinfo.ZoneInfo
    calendars: Tuple[str, ...]
    weekly_hours: Dict[str, Tuple[HourRange, ...]]
    buffer: datetime.timedelta
    min_notice: datetime.timedelta
    max_advance: datetime.timedelta
    min_length: datetime.timedelta
    count: int


def parse_duration(value: str, flag: str) -> datetime.timedelta:
    """Parses '30m', '4h', or '60d' into a timedelta."""
    match = _DURATION_RE.match(value.strip()) if isinstance(value, str) else None
    if not match:
        raise AvailabilityValidationError(f"{flag} must look like 30m, 4h, or 60d, got '{value}'.")
    amount, unit = match.groups()
    return datetime.timedelta(**{_DURATION_UNITS[unit]: int(amount)})


def parse_date(value: str, flag: str) -> datetime.date:
    """Parses a strict YYYY-MM-DD date."""
    if not isinstance(value, str) or not _DATE_RE.match(value.strip()):
        raise AvailabilityValidationError(f"{flag} must be YYYY-MM-DD, got '{value}'.")
    try:
        return datetime.date.fromisoformat(value.strip())
    except ValueError as e:
        raise AvailabilityValidationError(f"{flag} is not a valid date: {e}") from e


def _parse_hm(value: Any, day: str) -> datetime.time:
    if not isinstance(value, str) or not _HM_RE.match(value):
        raise AvailabilityValidationError(f"--hours-json '{day}' times must be HH:MM (00:00-23:59), got {value!r}.")
    hour, minute = value.split(":")
    return datetime.time(int(hour), int(minute))


def parse_weekly_hours(text: str) -> Dict[str, Tuple[HourRange, ...]]:
    """Parses weekly hours JSON, e.g. {"mon": [["09:00", "12:00"], ["13:00", "17:00"]]}.

    Ranges are sorted, overlapping ranges are rejected, and touching ranges are joined
    so a free stretch is never split at a range boundary.
    """
    try:
        raw = json.loads(text)
    except (TypeError, ValueError) as e:
        raise AvailabilityValidationError(f"--hours-json is not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise AvailabilityValidationError("--hours-json must be an object keyed by weekday (mon..sun).")

    hours: Dict[str, Tuple[HourRange, ...]] = {}
    for day, ranges in raw.items():
        if day not in WEEKDAY_KEYS:
            raise AvailabilityValidationError(
                f"--hours-json has unknown weekday '{day}'; use {', '.join(WEEKDAY_KEYS)}."
            )
        if not isinstance(ranges, list):
            raise AvailabilityValidationError(f"--hours-json '{day}' must be a list of [start, end] pairs.")
        parsed: List[HourRange] = []
        for pair in ranges:
            if not isinstance(pair, list) or len(pair) != 2:
                raise AvailabilityValidationError(f"--hours-json '{day}' entries must be [start, end] pairs.")
            start, end = _parse_hm(pair[0], day), _parse_hm(pair[1], day)
            if end <= start:
                raise AvailabilityValidationError(f"--hours-json '{day}' range {pair[0]}-{pair[1]} must end after it starts.")
            parsed.append((start, end))
        parsed.sort()
        joined: List[HourRange] = []
        for start, end in parsed:
            if joined and start < joined[-1][1]:
                raise AvailabilityValidationError(f"--hours-json '{day}' has overlapping ranges.")
            if joined and start == joined[-1][1]:
                joined[-1] = (joined[-1][0], end)
            else:
                joined.append((start, end))
        hours[day] = tuple(joined)

    if not any(hours.values()):
        raise AvailabilityValidationError("--hours-json has no open hours.")
    return hours


def parse_calendars(text: str) -> Tuple[str, ...]:
    """Parses a comma-separated calendar ID list, keeping order and dropping repeats."""
    ids: List[str] = []
    for part in (text or "").split(","):
        cid = part.strip()
        if not cid:
            continue
        if any(c in cid for c in ("\r", "\n", "\0")):
            raise AvailabilityValidationError("--calendars contains forbidden CRLF or null bytes.")
        if cid not in ids:
            ids.append(cid)
    if not ids:
        raise AvailabilityValidationError("--calendars must name at least one calendar (e.g. primary).")
    if len(ids) > MAX_FREEBUSY_CALENDARS:
        raise AvailabilityValidationError(
            f"--calendars names {len(ids)} calendars; the maximum is {MAX_FREEBUSY_CALENDARS}."
        )
    return tuple(ids)


def build_window_request(
    date_from: str,
    date_to: str,
    timezone_str: str,
    calendars: str,
    hours_json: str,
    buffer_min: int = 0,
    min_notice: str = "4h",
    max_advance: str = "60d",
    min_length_min: int = 60,
    count: int = 3,
) -> WindowRequest:
    """Validates raw CLI arguments into a WindowRequest. Makes no API call."""
    try:
        tz = zoneinfo.ZoneInfo(timezone_str.strip())
    except Exception as e:
        raise AvailabilityValidationError(f"Invalid IANA timezone '{timezone_str}': {e}") from e

    start_day = parse_date(date_from, "--from")
    end_day = parse_date(date_to, "--to")
    if end_day < start_day:
        raise AvailabilityValidationError(f"--to ({date_to}) must not be before --from ({date_from}).")
    span_days = (end_day - start_day).days + 1
    if span_days > MAX_AVAILABILITY_RANGE_DAYS:
        raise AvailabilityValidationError(
            f"Date range spans {span_days} days; the maximum is {MAX_AVAILABILITY_RANGE_DAYS}."
        )
    try:
        date_range_bounds(start_day, end_day, tz)
    except OverflowError as e:
        raise AvailabilityValidationError(f"Date range is out of bounds: {e}") from e

    if not 0 <= buffer_min <= MAX_MINUTES_PER_DAY:
        raise AvailabilityValidationError(f"--buffer must be 0-{MAX_MINUTES_PER_DAY} minutes, got {buffer_min}.")
    if not 1 <= min_length_min <= MAX_MINUTES_PER_DAY:
        raise AvailabilityValidationError(f"--min-length must be 1-{MAX_MINUTES_PER_DAY} minutes, got {min_length_min}.")
    if not 1 <= count <= MAX_AVAILABILITY_WINDOW_COUNT:
        raise AvailabilityValidationError(f"--count must be 1-{MAX_AVAILABILITY_WINDOW_COUNT}, got {count}.")

    return WindowRequest(
        date_from=start_day,
        date_to=end_day,
        tz=tz,
        calendars=parse_calendars(calendars),
        weekly_hours=parse_weekly_hours(hours_json),
        buffer=datetime.timedelta(minutes=buffer_min),
        min_notice=parse_duration(min_notice, "--min-notice"),
        max_advance=parse_duration(max_advance, "--max-advance"),
        min_length=datetime.timedelta(minutes=min_length_min),
        count=count,
    )


def _local_instant(day: datetime.date, hm: datetime.time, tz: zoneinfo.ZoneInfo) -> datetime.datetime:
    # zoneinfo resolves ambiguous and skipped wall times; everything after this is UTC.
    return datetime.datetime.combine(day, hm, tzinfo=tz).astimezone(UTC)


def date_range_bounds(date_from: datetime.date, date_to: datetime.date, tz: zoneinfo.ZoneInfo) -> Interval:
    """Local midnight starting date_from to local midnight after date_to, as UTC instants."""
    return (
        _local_instant(date_from, datetime.time(0), tz),
        _local_instant(date_to + datetime.timedelta(days=1), datetime.time(0), tz),
    )


def _floor_minute(instant: datetime.datetime) -> datetime.datetime:
    return instant.replace(second=0, microsecond=0)


def _ceil_minute(instant: datetime.datetime) -> datetime.datetime:
    floored = _floor_minute(instant)
    return floored if floored == instant else floored + datetime.timedelta(minutes=1)


def _merge(intervals: Sequence[Interval]) -> List[Interval]:
    merged: List[Interval] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def _subtract(block: Interval, busy: Sequence[Interval]) -> List[Interval]:
    """Free parts of a half-open block, given merged, sorted busy intervals."""
    cursor, block_end = block
    free: List[Interval] = []
    for busy_start, busy_end in busy:
        if busy_end <= cursor:
            continue
        if busy_start >= block_end:
            break
        if busy_start > cursor:
            free.append((cursor, busy_start))
        cursor = busy_end
        if cursor >= block_end:
            break
    if cursor < block_end:
        free.append((cursor, block_end))
    return free


def find_open_windows(
    busy: Sequence[Interval],
    request: WindowRequest,
    now: datetime.datetime,
) -> List[Window]:
    """Every free stretch inside the weekly hours that meets min_length, in time order.

    Pure: no I/O and no clock. Busy blocks are padded by the buffer on both sides.
    Minimum notice and maximum advance are measured from `now`, rounded inward to
    whole minutes.
    """
    now = now.astimezone(UTC)
    range_start, range_end = date_range_bounds(request.date_from, request.date_to, request.tz)
    earliest = max(range_start, _ceil_minute(now + request.min_notice))
    latest = min(range_end, _floor_minute(now + request.max_advance))
    padded = _merge(
        [(start.astimezone(UTC) - request.buffer, end.astimezone(UTC) + request.buffer) for start, end in busy]
    )

    found: List[Window] = []
    day = request.date_from
    while day <= request.date_to:
        for start_hm, end_hm in request.weekly_hours.get(WEEKDAY_KEYS[day.weekday()], ()):
            start = max(_local_instant(day, start_hm, request.tz), earliest)
            end = min(_local_instant(day, end_hm, request.tz), latest)
            if end <= start:
                continue
            for free_start, free_end in _subtract((start, end), padded):
                if free_end - free_start >= request.min_length:
                    found.append(Window(free_start, free_end))
        day += datetime.timedelta(days=1)
    return found


def _day_and_half(window: Window, tz: zoneinfo.ZoneInfo) -> Tuple[datetime.date, bool]:
    local = window.start.astimezone(tz)
    return local.date(), local.hour < 12


def spread_windows(windows: Sequence[Window], count: int, tz: zoneinfo.ZoneInfo) -> List[Window]:
    """Picks up to `count` windows, returned in time order.

    Each pick prefers the least-used day, then the less-used half of the day (morning
    starts before 12:00 local), then the earliest start. Deterministic for a given input.
    """
    remaining = sorted(windows, key=lambda w: w.start)
    day_uses: Dict[datetime.date, int] = {}
    half_uses = {True: 0, False: 0}
    chosen: List[Window] = []

    def score(window: Window) -> Tuple[int, int, datetime.datetime]:
        day, is_morning = _day_and_half(window, tz)
        return day_uses.get(day, 0), half_uses[is_morning], window.start

    while remaining and len(chosen) < count:
        pick = min(remaining, key=score)
        remaining.remove(pick)
        day, is_morning = _day_and_half(pick, tz)
        day_uses[day] = day_uses.get(day, 0) + 1
        half_uses[is_morning] += 1
        chosen.append(pick)
    return sorted(chosen, key=lambda w: w.start)


def open_windows(busy: Sequence[Interval], request: WindowRequest, now: datetime.datetime) -> List[Window]:
    """Finds free stretches and spreads the suggestions (design section 6, `open_windows`)."""
    return spread_windows(find_open_windows(busy, request, now), request.count, request.tz)


def _parse_instant(value: Any, calendar_id: str) -> datetime.datetime:
    if not isinstance(value, str):
        raise FreeBusyError(f"freeBusy returned a malformed busy block for calendar '{calendar_id}'.")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as e:
        raise FreeBusyError(f"freeBusy returned a malformed busy time for calendar '{calendar_id}'.") from e
    if parsed.tzinfo is None:
        raise FreeBusyError(f"freeBusy returned a busy time without an offset for calendar '{calendar_id}'.")
    return parsed.astimezone(UTC)


def parse_freebusy_response(response: Any, calendars: Sequence[str]) -> List[Interval]:
    """Collects busy blocks for every requested calendar, failing closed.

    A requested calendar that is missing, carries `errors[]` (any reason, since Google
    may add reasons), or has no `busy` list raises FreeBusyError. None of those cases is
    ever reported as free time.
    """
    entries = response.get("calendars") if isinstance(response, dict) else None
    if not isinstance(entries, dict):
        raise FreeBusyError("freeBusy response has no 'calendars' map; no windows reported.")

    busy: List[Interval] = []
    for cid in calendars:
        entry = entries.get(cid)
        if not isinstance(entry, dict):
            raise FreeBusyError(f"freeBusy returned no entry for calendar '{cid}'; no windows reported.")
        errors = entry.get("errors")
        if errors:
            reasons = sorted(
                {str(e.get("reason", "unknown")) if isinstance(e, dict) else "unknown" for e in errors}
            )
            raise FreeBusyError(
                f"freeBusy failed for calendar '{cid}' ({', '.join(reasons)}); no windows reported."
            )
        blocks = entry.get("busy")
        if not isinstance(blocks, list):
            raise FreeBusyError(f"freeBusy returned no busy list for calendar '{cid}'; no windows reported.")
        for block in blocks:
            if not isinstance(block, dict):
                raise FreeBusyError(f"freeBusy returned a malformed busy block for calendar '{cid}'.")
            start = _parse_instant(block.get("start"), cid)
            end = _parse_instant(block.get("end"), cid)
            if end < start:
                raise FreeBusyError(f"freeBusy returned a busy block that ends before it starts for calendar '{cid}'.")
            busy.append((start, end))
    return busy


def _validate_purpose(purpose: str) -> None:
    if not purpose or not purpose.strip():
        raise AvailabilityValidationError("--purpose cannot be empty.")
    if any(c in purpose for c in ("\r", "\n", "\0")):
        raise AvailabilityValidationError("--purpose contains forbidden CRLF or null bytes.")


class AvailabilityManager:
    """Reads free/busy on the read-only Availability Grant and turns it into open windows."""

    def __init__(
        self,
        auth_manager: Optional[AuthManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
        audit_logger: Optional[AuditLogger] = None,
        clock: Optional[Callable[[], datetime.datetime]] = None,
    ):
        self.auth_manager = auth_manager or AuthManager.for_availability()
        # Own limiter instance with a Calendar-sized budget; freeBusy never draws on the Gmail budget.
        self.rate_limiter = rate_limiter or RateLimiter(max_units=AVAILABILITY_RATE_LIMIT_MAX_UNITS)
        self.audit_logger = audit_logger or AuditLogger()
        self.clock = clock or (lambda: datetime.datetime.now(UTC))
        self._service = None

    def _get_service(self):
        """Constructs or returns cached Google Calendar API v3 service."""
        if self._service is None:
            from googleapiclient.discovery import build
            creds = self.auth_manager.get_credentials()
            self._service = build("calendar", "v3", credentials=creds, cache_discovery=False)
        return self._service

    def query_busy(self, request: WindowRequest) -> List[Interval]:
        """Runs one freebusy.query over the date range for exactly the requested calendars."""
        time_min, time_max = date_range_bounds(request.date_from, request.date_to, request.tz)
        body = {
            "timeMin": time_min.isoformat(),
            "timeMax": time_max.isoformat(),
            "timeZone": request.tz.key,
            "items": [{"id": cid} for cid in request.calendars],
        }
        service = self._get_service()
        response = self.rate_limiter.execute_with_retry(
            "freebusy.query",
            lambda: service.freebusy().query(body=body).execute(),
        )
        return parse_freebusy_response(response, request.calendars)

    def find_windows(self, request: WindowRequest, purpose: str = "availability_windows") -> Dict[str, Any]:
        """Returns {"snapshot_at", "windows": [{"start", "end"}]} and records one audit entry.

        The audit entry holds only the operation, the date range, and the window count.
        """
        _validate_purpose(purpose)
        now = self.clock().astimezone(UTC)
        windows = open_windows(self.query_busy(request), request, now)
        self.audit_logger.record(
            AuditEntry(
                operation="availability_windows",
                purpose=purpose,
                status="SUCCESS",
                details=(
                    f"from={request.date_from.isoformat()}_to={request.date_to.isoformat()}_"
                    f"windows={len(windows)}"
                ),
            )
        )
        return {
            "snapshot_at": now.isoformat(timespec="seconds"),
            "windows": [w.to_dict(request.tz) for w in windows],
        }
