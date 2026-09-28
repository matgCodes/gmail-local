"""Tests for the read-only freeBusy client and deterministic window engine (Issue #11)."""

import json
import os
import random
import subprocess
import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock
from zoneinfo import ZoneInfo

import pytest

from gmail_local.audit import AuditLogger
from gmail_local.availability import (
    AvailabilityManager,
    AvailabilityValidationError,
    FreeBusyError,
    Window,
    build_window_request,
    find_open_windows,
    open_windows,
    parse_calendars,
    parse_duration,
    parse_freebusy_response,
    parse_weekly_hours,
    spread_windows,
)
from gmail_local.config import (
    AVAILABILITY_RATE_LIMIT_MAX_UNITS,
    AVAILABILITY_SCOPE,
    KEYCHAIN_SERVICE_AVAILABILITY,
    METHOD_QUOTA_COSTS,
    RATE_LIMIT_MAX_UNITS,
)
from gmail_local.rate_limiter import RateLimiter

UTC = timezone.utc
LA_NAME = "America/Los_Angeles"
LA = ZoneInfo(LA_NAME)
WEEKDAY_HOURS = json.dumps({day: [["09:00", "17:00"]] for day in ("mon", "tue", "wed", "thu", "fri")})
NOW = datetime(2026, 9, 28, 8, 0, tzinfo=UTC)  # Monday 01:00 PDT


def make_request(**overrides):
    args = dict(
        date_from="2026-09-29",  # Tuesday
        date_to="2026-09-29",
        timezone_str=LA_NAME,
        calendars="primary",
        hours_json=WEEKDAY_HOURS,
        buffer_min=0,
        min_notice="0m",
        max_advance="60d",
        min_length_min=60,
        count=3,
    )
    args.update(overrides)
    return build_window_request(**args)


def busy(start: str, end: str):
    return datetime.fromisoformat(start), datetime.fromisoformat(end)


def pairs(windows):
    return [(w["start"], w["end"]) for w in (x.to_dict(LA) for x in windows)]


def window(start: str, end: str) -> Window:
    return Window(datetime.fromisoformat(start).astimezone(UTC), datetime.fromisoformat(end).astimezone(UTC))


# ---------------------------------------------------------------- window engine


def test_busy_blocks_crossing_window_edges_are_clipped():
    request = make_request()
    blocks = [
        busy("2026-09-29T08:00:00-07:00", "2026-09-29T10:00:00-07:00"),  # crosses the opening edge
        busy("2026-09-29T12:00:00-07:00", "2026-09-29T13:00:00-07:00"),  # inside
        busy("2026-09-29T16:30:00-07:00", "2026-09-29T18:00:00-07:00"),  # crosses the closing edge
        busy("2026-09-29T17:00:00-07:00", "2026-09-29T19:00:00-07:00"),  # touches the edge only
    ]
    assert pairs(find_open_windows(blocks, request, NOW)) == [
        ("2026-09-29T10:00:00-07:00", "2026-09-29T12:00:00-07:00"),
        ("2026-09-29T13:00:00-07:00", "2026-09-29T16:30:00-07:00"),
    ]


def test_overlapping_busy_blocks_from_several_calendars_are_merged():
    request = make_request()
    blocks = [
        busy("2026-09-29T10:00:00-07:00", "2026-09-29T11:30:00-07:00"),
        busy("2026-09-29T11:00:00-07:00", "2026-09-29T12:00:00-07:00"),
        busy("2026-09-29T11:15:00-07:00", "2026-09-29T11:45:00-07:00"),
    ]
    assert pairs(find_open_windows(blocks, request, NOW)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        ("2026-09-29T12:00:00-07:00", "2026-09-29T17:00:00-07:00"),
    ]


def test_buffer_pads_both_sides_of_each_busy_block():
    blocks = [busy("2026-09-29T12:00:00-07:00", "2026-09-29T13:00:00-07:00")]
    assert pairs(find_open_windows(blocks, make_request(buffer_min=15), NOW)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T11:45:00-07:00"),
        ("2026-09-29T13:15:00-07:00", "2026-09-29T17:00:00-07:00"),
    ]


def test_buffer_drops_gaps_that_fall_below_min_length():
    blocks = [
        busy("2026-09-29T10:00:00-07:00", "2026-09-29T11:00:00-07:00"),
        busy("2026-09-29T12:00:00-07:00", "2026-09-29T13:00:00-07:00"),
    ]
    assert pairs(find_open_windows(blocks, make_request(buffer_min=0), NOW)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        ("2026-09-29T11:00:00-07:00", "2026-09-29T12:00:00-07:00"),
        ("2026-09-29T13:00:00-07:00", "2026-09-29T17:00:00-07:00"),
    ]
    assert pairs(find_open_windows(blocks, make_request(buffer_min=15), NOW)) == [
        ("2026-09-29T13:15:00-07:00", "2026-09-29T17:00:00-07:00"),
    ]


def test_min_notice_cuts_off_the_start_rounded_up_to_a_whole_minute():
    now = datetime.fromisoformat("2026-09-29T06:30:20.500000-07:00")
    request = make_request(min_notice="4h")
    assert pairs(find_open_windows([], request, now)) == [
        ("2026-09-29T10:31:00-07:00", "2026-09-29T17:00:00-07:00"),
    ]


def test_min_notice_leaving_less_than_min_length_skips_to_the_next_day():
    now = datetime.fromisoformat("2026-09-29T12:30:00-07:00")
    request = make_request(date_to="2026-09-30", min_notice="4h")
    assert pairs(find_open_windows([], request, now)) == [
        ("2026-09-30T09:00:00-07:00", "2026-09-30T17:00:00-07:00"),
    ]


def test_max_advance_cuts_off_the_end():
    now = datetime.fromisoformat("2026-09-29T08:00:00-07:00")
    request = make_request(date_to="2026-10-01", max_advance="28h")
    assert pairs(find_open_windows([], request, now)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T17:00:00-07:00"),
        ("2026-09-30T09:00:00-07:00", "2026-09-30T12:00:00-07:00"),
    ]
    assert find_open_windows([], make_request(date_from="2026-10-01", date_to="2026-10-01", max_advance="1d"), now) == []


def test_dst_fall_back_uses_elapsed_time_not_wall_clock():
    # 2026-11-01 01:00 PDT -> 02:00 PST is two real hours, though only one on the clock.
    request = make_request(
        date_from="2026-11-01", date_to="2026-11-01",
        hours_json=json.dumps({"sun": [["01:00", "02:00"]]}), min_length_min=90,
    )
    found = find_open_windows([], request, NOW)
    assert pairs(found) == [("2026-11-01T01:00:00-07:00", "2026-11-01T02:00:00-08:00")]
    assert found[0].end - found[0].start == timedelta(hours=2)


def test_dst_spring_forward_uses_elapsed_time_not_wall_clock():
    # 2026-03-08 01:30 PST -> 03:30 PDT is one real hour, though two on the clock.
    now = datetime(2026, 2, 1, tzinfo=UTC)
    hours = json.dumps({"sun": [["01:30", "03:30"]]})
    request = make_request(date_from="2026-03-08", date_to="2026-03-08", hours_json=hours, min_length_min=90)
    assert find_open_windows([], request, now) == []

    request = make_request(date_from="2026-03-08", date_to="2026-03-08", hours_json=hours, min_length_min=60)
    assert pairs(find_open_windows([], request, now)) == [("2026-03-08T01:30:00-08:00", "2026-03-08T03:30:00-07:00")]


def test_dst_transition_week_keeps_local_hours_and_utc_busy_blocks_aligned():
    request = make_request(
        date_from="2026-10-30", date_to="2026-11-02",
        hours_json=json.dumps({"fri": [["09:00", "12:00"]], "mon": [["09:00", "12:00"]]}),
    )
    blocks = [busy("2026-11-02T17:00:00+00:00", "2026-11-02T18:00:00+00:00")]  # 09:00-10:00 PST
    assert pairs(find_open_windows(blocks, request, NOW)) == [
        ("2026-10-30T09:00:00-07:00", "2026-10-30T12:00:00-07:00"),
        ("2026-11-02T10:00:00-08:00", "2026-11-02T12:00:00-08:00"),
    ]


def test_no_open_windows_when_fully_busy():
    request = make_request(date_to="2026-09-30")
    blocks = [busy("2026-09-29T00:00:00-07:00", "2026-10-01T00:00:00-07:00")]
    assert find_open_windows(blocks, request, NOW) == []
    assert open_windows(blocks, request, NOW) == []


def test_no_open_windows_on_days_without_weekly_hours():
    request = make_request(date_from="2026-10-03", date_to="2026-10-04")  # Saturday, Sunday
    assert open_windows([], request, NOW) == []


def test_spread_prefers_different_days_then_morning_afternoon_mix():
    candidates = [
        window("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),  # Tue AM
        window("2026-09-29T14:00:00-07:00", "2026-09-29T15:00:00-07:00"),  # Tue PM
        window("2026-09-30T09:00:00-07:00", "2026-09-30T10:00:00-07:00"),  # Wed AM
        window("2026-09-30T14:00:00-07:00", "2026-09-30T15:00:00-07:00"),  # Wed PM
        window("2026-10-01T09:00:00-07:00", "2026-10-01T10:00:00-07:00"),  # Thu AM
    ]
    expected = [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        ("2026-09-30T14:00:00-07:00", "2026-09-30T15:00:00-07:00"),
        ("2026-10-01T09:00:00-07:00", "2026-10-01T10:00:00-07:00"),
    ]
    assert pairs(spread_windows(candidates, 3, LA)) == expected

    shuffled = list(candidates)
    random.Random(7).shuffle(shuffled)
    assert pairs(spread_windows(shuffled, 3, LA)) == expected


def test_spread_mixes_morning_and_afternoon_within_one_day():
    candidates = [
        window("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        window("2026-09-29T10:30:00-07:00", "2026-09-29T11:30:00-07:00"),
        window("2026-09-29T13:00:00-07:00", "2026-09-29T14:00:00-07:00"),
        window("2026-09-29T15:00:00-07:00", "2026-09-29T16:00:00-07:00"),
    ]
    assert pairs(spread_windows(candidates, 2, LA)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        ("2026-09-29T13:00:00-07:00", "2026-09-29T14:00:00-07:00"),
    ]


def test_spread_returns_everything_in_time_order_when_count_exceeds_candidates():
    candidates = [
        window("2026-09-30T09:00:00-07:00", "2026-09-30T10:00:00-07:00"),
        window("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
    ]
    assert pairs(spread_windows(candidates, 3, LA)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T10:00:00-07:00"),
        ("2026-09-30T09:00:00-07:00", "2026-09-30T10:00:00-07:00"),
    ]


def test_open_windows_limits_to_count_across_days():
    request = make_request(date_to="2026-10-02", count=3)
    assert pairs(open_windows([], request, NOW)) == [
        ("2026-09-29T09:00:00-07:00", "2026-09-29T17:00:00-07:00"),
        ("2026-09-30T09:00:00-07:00", "2026-09-30T17:00:00-07:00"),
        ("2026-10-01T09:00:00-07:00", "2026-10-01T17:00:00-07:00"),
    ]


# ---------------------------------------------------------------- argument parsing


@pytest.mark.parametrize("value,expected", [
    ("30m", timedelta(minutes=30)),
    ("4h", timedelta(hours=4)),
    ("60d", timedelta(days=60)),
    ("0m", timedelta(0)),
])
def test_parse_duration_accepts_minutes_hours_days(value, expected):
    assert parse_duration(value, "--min-notice") == expected


@pytest.mark.parametrize("value", ["4", "h", "-1h", "1.5h", "4 hours", "", "4w", "1234567d"])
def test_parse_duration_rejects_other_forms(value):
    with pytest.raises(AvailabilityValidationError, match="--min-notice"):
        parse_duration(value, "--min-notice")


def test_parse_weekly_hours_sorts_and_joins_touching_ranges():
    hours = parse_weekly_hours(json.dumps({"mon": [["13:00", "17:00"], ["09:00", "13:00"]], "fri": [["09:00", "12:00"]]}))
    assert hours == {"mon": ((time(9), time(17)),), "fri": ((time(9), time(12)),)}


@pytest.mark.parametrize("text,match", [
    ("not json", "not valid JSON"),
    ('[["09:00", "17:00"]]', "object keyed by weekday"),
    ('{"monday": [["09:00", "17:00"]]}', "unknown weekday"),
    ('{"mon": "09:00-17:00"}', "list of"),
    ('{"mon": [["09:00"]]}', "pairs"),
    ('{"mon": [["9:00", "17:00"]]}', "HH:MM"),
    ('{"mon": [["09:00", "24:00"]]}', "HH:MM"),
    ('{"mon": [[900, 1700]]}', "HH:MM"),
    ('{"mon": [["17:00", "09:00"]]}', "end after it starts"),
    ('{"mon": [["09:00", "09:00"]]}', "end after it starts"),
    ('{"mon": [["09:00", "12:00"], ["11:00", "13:00"]]}', "overlapping"),
    ("{}", "no open hours"),
    ('{"mon": []}', "no open hours"),
])
def test_parse_weekly_hours_rejects_bad_input(text, match):
    with pytest.raises(AvailabilityValidationError, match=match):
        parse_weekly_hours(text)


def test_parse_calendars_keeps_order_and_drops_repeats():
    assert parse_calendars(" primary, work@example.com ,primary,") == ("primary", "work@example.com")


@pytest.mark.parametrize("text,match", [
    ("", "at least one calendar"),
    (" , ,", "at least one calendar"),
    ("primary,bad\nid", "CRLF"),
    (",".join(f"c{i}@example.com" for i in range(51)), "maximum is 50"),
])
def test_parse_calendars_rejects_bad_input(text, match):
    with pytest.raises(AvailabilityValidationError, match=match):
        parse_calendars(text)


@pytest.mark.parametrize("overrides,match", [
    ({"timezone_str": "Mars/Phobos"}, "Invalid IANA timezone"),
    ({"date_from": "2026/09/29"}, "--from must be YYYY-MM-DD"),
    ({"date_from": "20260929"}, "--from must be YYYY-MM-DD"),
    ({"date_to": "2026-02-30"}, "--to is not a valid date"),
    ({"date_from": "2026-09-30", "date_to": "2026-09-29"}, "must not be before"),
    ({"date_to": "2027-09-30"}, "maximum is 366"),
    ({"buffer_min": -1}, "--buffer"),
    ({"buffer_min": 1441}, "--buffer"),
    ({"min_length_min": 0}, "--min-length"),
    ({"count": 0}, "--count"),
    ({"count": 11}, "--count"),
    ({"max_advance": "sixty days"}, "--max-advance"),
])
def test_build_window_request_rejects_bad_arguments(overrides, match):
    with pytest.raises(AvailabilityValidationError, match=match):
        make_request(**overrides)


# ---------------------------------------------------------------- freeBusy response


def test_parse_freebusy_response_collects_busy_blocks_from_every_calendar():
    response = {
        "calendars": {
            "primary": {"busy": [{"start": "2026-09-29T17:00:00Z", "end": "2026-09-29T18:00:00Z"}]},
            "work@example.com": {"busy": []},
        }
    }
    assert parse_freebusy_response(response, ("primary", "work@example.com")) == [
        (datetime(2026, 9, 29, 17, tzinfo=UTC), datetime(2026, 9, 29, 18, tzinfo=UTC)),
    ]


@pytest.mark.parametrize("response,match", [
    ({"calendars": {"primary": {"busy": []}, "gone@example.com": {"errors": [{"domain": "global", "reason": "notFound"}], "busy": []}}}, "notFound"),
    ({"calendars": {"primary": {"busy": []}, "gone@example.com": {"errors": [{"domain": "global", "reason": "somethingNew"}]}}}, "somethingNew"),
    ({"calendars": {"primary": {"busy": []}}}, "no entry for calendar 'gone@example.com'"),
    ({"kind": "calendar#freeBusy"}, "no 'calendars' map"),
    ({"calendars": {"primary": {"busy": []}, "gone@example.com": {}}}, "no busy list"),
    ({"calendars": {"primary": {"busy": [{"start": "yesterday", "end": "2026-09-29T18:00:00Z"}]}, "gone@example.com": {"busy": []}}}, "malformed busy time"),
    ({"calendars": {"primary": {"busy": [{"start": "2026-09-29T17:00:00", "end": "2026-09-29T18:00:00"}]}, "gone@example.com": {"busy": []}}}, "without an offset"),
    ({"calendars": {"primary": {"busy": [{"start": "2026-09-29T18:00:00Z", "end": "2026-09-29T17:00:00Z"}]}, "gone@example.com": {"busy": []}}}, "ends before it starts"),
])
def test_parse_freebusy_response_fails_closed(response, match):
    with pytest.raises(FreeBusyError, match=match):
        parse_freebusy_response(response, ("primary", "gone@example.com"))


# ---------------------------------------------------------------- AvailabilityManager


def make_manager(tmp_path: Path, response, now=NOW):
    service = MagicMock()
    service.freebusy.return_value.query.return_value.execute.return_value = response
    manager = AvailabilityManager(
        auth_manager=MagicMock(),
        rate_limiter=RateLimiter(max_units=AVAILABILITY_RATE_LIMIT_MAX_UNITS),
        audit_logger=AuditLogger(log_path=tmp_path / "audit.log"),
        clock=lambda: now,
    )
    manager._service = service
    return manager, service


def test_freebusy_request_uses_exactly_the_calendars_list(tmp_path):
    response = {"calendars": {"primary": {"busy": []}, "work@example.com": {"busy": []}}}
    manager, service = make_manager(tmp_path, response)

    manager.find_windows(make_request(date_to="2026-09-30", calendars="primary,work@example.com"))

    service.freebusy.return_value.query.assert_called_once()
    body = service.freebusy.return_value.query.call_args.kwargs["body"]
    assert body == {
        "timeMin": "2026-09-29T07:00:00+00:00",
        "timeMax": "2026-10-01T07:00:00+00:00",
        "timeZone": LA_NAME,
        "items": [{"id": "primary"}, {"id": "work@example.com"}],
    }


def test_find_windows_outputs_only_windows_and_snapshot_and_audits_only_range_and_count(tmp_path):
    response = {
        "calendars": {
            "primary": {"busy": [{"start": "2026-09-29T19:00:00Z", "end": "2026-09-29T20:00:00Z"}]},
            "work@example.com": {"busy": [{"start": "2026-09-30T16:00:00Z", "end": "2026-09-30T23:30:00Z"}]},
        }
    }
    manager, _ = make_manager(tmp_path, response)

    result = manager.find_windows(
        make_request(date_to="2026-09-30", calendars="primary,work@example.com"),
        purpose="book_meeting_windows",
    )

    assert set(result) == {"snapshot_at", "windows"}
    assert result["snapshot_at"] == "2026-09-28T08:00:00+00:00"
    assert result["windows"] == [
        {"start": "2026-09-29T09:00:00-07:00", "end": "2026-09-29T12:00:00-07:00"},
        {"start": "2026-09-29T13:00:00-07:00", "end": "2026-09-29T17:00:00-07:00"},
    ]

    log = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert log.count("\n") == 1
    assert "op=availability_windows" in log
    assert "purpose=book_meeting_windows" in log
    assert "status=SUCCESS" in log
    assert "details=from=2026-09-29_to=2026-09-30_windows=2" in log
    assert "work@example.com" not in log
    assert "primary" not in log
    assert "2026-09-29T19:00:00Z" not in log
    assert "-07:00" not in log  # no window times; ts= is UTC


def test_find_windows_with_calendar_errors_raises_and_records_nothing(tmp_path):
    response = {
        "calendars": {
            "primary": {"busy": []},
            "gone@example.com": {"errors": [{"domain": "global", "reason": "notFound"}], "busy": []},
        }
    }
    manager, _ = make_manager(tmp_path, response)

    with pytest.raises(FreeBusyError, match="notFound"):
        manager.find_windows(make_request(calendars="primary,gone@example.com"))

    assert "availability_windows" not in (tmp_path / "audit.log").read_text(encoding="utf-8")


def test_find_windows_rejects_purpose_with_line_breaks_before_any_call(tmp_path):
    manager, service = make_manager(tmp_path, {"calendars": {"primary": {"busy": []}}})

    with pytest.raises(AvailabilityValidationError, match="--purpose"):
        manager.find_windows(make_request(), purpose="ok\nop=forged")

    service.freebusy.assert_not_called()
    manager.auth_manager.get_credentials.assert_not_called()


def test_freebusy_draws_one_unit_from_its_own_limiter_not_the_gmail_budget(tmp_path):
    assert METHOD_QUOTA_COSTS["freebusy.query"] == 1
    assert AVAILABILITY_RATE_LIMIT_MAX_UNITS < RATE_LIMIT_MAX_UNITS

    manager, _ = make_manager(tmp_path, {"calendars": {"primary": {"busy": []}}})
    manager.find_windows(make_request())
    assert manager.rate_limiter.current_units_in_window() == 1

    default_manager = AvailabilityManager(audit_logger=AuditLogger(log_path=tmp_path / "default.log"))
    assert default_manager.rate_limiter.max_units == AVAILABILITY_RATE_LIMIT_MAX_UNITS


def test_default_manager_loads_only_the_availability_grant(tmp_path):
    manager = AvailabilityManager(audit_logger=AuditLogger(log_path=tmp_path / "audit.log"))
    assert manager.auth_manager.scopes == [AVAILABILITY_SCOPE]
    assert manager.auth_manager.keychain_service == KEYCHAIN_SERVICE_AVAILABILITY


def test_availability_module_does_not_import_retrieval_composer_or_triage():
    src = Path(__file__).resolve().parents[1] / "src"
    code = (
        "import sys, gmail_local.availability as a; "
        "print(a.__file__); "
        "print(','.join(m for m in ('gmail_local.retrieval', 'gmail_local.composer', 'gmail_local.triage') "
        "if m in sys.modules))"
    )
    env = {**os.environ, "PYTHONPATH": str(src)}
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=30, check=True)
    module_file, loaded = proc.stdout.splitlines()
    assert Path(module_file).resolve().is_relative_to(src)
    assert loaded == ""
