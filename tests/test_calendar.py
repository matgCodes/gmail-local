"""Tests for Google Calendar and Google Meet integration."""

import re
import pytest

from gmail_local.calendar import (
    CalendarError,
    CalendarValidationError,
    CalendarConferenceError,
    CalendarIdempotencyError,
    ManualActionGateViolationError,
    generate_calendar_event_id,
    validate_calendar_event_inputs,
)


def test_generate_calendar_event_id_determinism_and_format():
    summary = "Executive Strategy Session"
    start = "2026-09-22T10:00:00-07:00"
    end = "2026-09-22T10:35:00-07:00"
    tz = "America/Los_Angeles"
    attendees = ["alice@example.com", "bob@example.com"]
    has_meet = True

    eid1 = generate_calendar_event_id(summary, start, end, tz, attendees, has_meet)
    eid2 = generate_calendar_event_id(summary, start, end, tz, ["bob@example.com", "alice@example.com"], has_meet)

    # Determinism: attendees sorted canonically
    assert eid1 == eid2

    # Format: base32hex lowercase string [a-v0-9]
    assert re.match(r"^[a-v0-9]{5,64}$", eid1)

    # Sensitivity: changing summary changes ID
    eid3 = generate_calendar_event_id("Different Summary", start, end, tz, attendees, has_meet)
    assert eid3 != eid1

    # Sensitivity: changing time changes ID
    eid4 = generate_calendar_event_id(summary, "2026-09-22T11:00:00-07:00", end, tz, attendees, has_meet)
    assert eid4 != eid1

    # Sensitivity: changing has_meet changes ID
    eid5 = generate_calendar_event_id(summary, start, end, tz, attendees, False)
    assert eid5 != eid1


def test_validate_calendar_event_inputs_success():
    validate_calendar_event_inputs(
        summary="Architecture sync",
        start_iso="2026-09-22T10:00:00-07:00",
        end_iso="2026-09-22T10:30:00-07:00",
        timezone_str="America/Los_Angeles",
        attendees=["alice@example.com", "bob@example.com"],
        send_updates="all",
    )


@pytest.mark.parametrize(
    "summary,start,end,tz,attendees,send_updates,match_err",
    [
        ("", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "Summary cannot be empty"),
        ("   ", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "Summary cannot be empty"),
        ("Bad\nSummary", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "CRLF or null bytes"),
        ("Bad\rSummary", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "CRLF or null bytes"),
        ("Bad\x00Summary", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "CRLF or null bytes"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "Mars/Phobos", [], "none", "Invalid IANA timezone"),
        ("Valid", "invalid-start", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "none", "Invalid start datetime"),
        ("Valid", "2026-09-22T10:00:00-07:00", "invalid-end", "America/Los_Angeles", [], "none", "Invalid end datetime"),
        ("Valid", "2026-09-22T10:30:00-07:00", "2026-09-22T10:00:00-07:00", "America/Los_Angeles", [], "none", "End time must be after start time"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:00:00-07:00", "America/Los_Angeles", [], "none", "End time must be after start time"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [f"u{i}@ex.com" for i in range(11)], "none", "exceeds maximum bound"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", ["invalid-email"], "none", "Invalid attendee email"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", ["bad\n@ex.com"], "none", "CRLF or null bytes"),
        ("Valid", "2026-09-22T10:00:00-07:00", "2026-09-22T10:30:00-07:00", "America/Los_Angeles", [], "invalid_updates", "send_updates must be one of"),
    ],
)
def test_validate_calendar_event_inputs_failures(summary, start, end, tz, attendees, send_updates, match_err):
    with pytest.raises(CalendarValidationError, match=match_err):
        validate_calendar_event_inputs(
            summary=summary,
            start_iso=start,
            end_iso=end,
            timezone_str=tz,
            attendees=attendees,
            send_updates=send_updates,
        )


def test_calendar_manager_preview_event():
    from gmail_local.calendar import CalendarManager

    manager = CalendarManager()
    preview = manager.preview_event(
        summary="Executive Strategy Session",
        start_iso="2026-09-22T10:00:00-07:00",
        end_iso="2026-09-22T10:35:00-07:00",
        timezone_str="America/Los_Angeles",
        description="Strategic goals discussion",
        attendees=["alice@example.com"],
        has_meet=True,
        send_updates="all",
    )

    assert preview.event.summary == "Executive Strategy Session"
    assert preview.event.start == "2026-09-22T10:00:00-07:00"
    assert preview.event.end == "2026-09-22T10:35:00-07:00"
    assert preview.event.timezone == "America/Los_Angeles"
    assert preview.event.has_meet is True
    assert preview.send_updates == "all"
    assert len(preview.event.attendees) == 1
    assert preview.event.attendees[0].email == "alice@example.com"

    # Verify Handoff Markdown contents
    md = preview.handoff_markdown
    assert "CALENDAR EVENT HANDOFF" in md
    assert preview.event.compute_fingerprint() in md
    assert preview.event.id in md
    assert "Executive Strategy Session" in md
    assert "35 minutes" in md
    assert "Google Meet:        ENABLED" in md
    assert "Attendees:          1 recipient(s)" in md
    assert "Send Updates:       ALL" in md
    assert "calendar-event create" in md
    assert "--confirm" in md


def test_calendar_manager_create_event_action_gate():
    from gmail_local.calendar import CalendarManager, ManualActionGateViolationError
    from gmail_local.models import CalendarEvent

    manager = CalendarManager()
    event = CalendarEvent(
        id="test_evt_1",
        summary="Sync",
        start="2026-09-22T10:00:00-07:00",
        end="2026-09-22T10:30:00-07:00",
        timezone="America/Los_Angeles",
    )

    with pytest.raises(ManualActionGateViolationError, match="Manual Action Gate"):
        manager.create_event(event, confirm=False)


def test_calendar_manager_create_event_success_and_audit_redaction(tmp_path):
    from unittest.mock import MagicMock
    from gmail_local.audit import AuditLogger
    from gmail_local.calendar import CalendarManager
    from gmail_local.models import Attendee, CalendarEvent

    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)
    manager = CalendarManager(audit_logger=logger)

    mock_service = MagicMock()
    manager._service = mock_service

    event = CalendarEvent(
        id="c1a2b3c4d5e6f7a8b9c0d1e2f3",
        summary="Executive Interview",
        description="Confidential medical candidate discussion",
        start="2026-09-22T10:00:00-07:00",
        end="2026-09-22T10:35:00-07:00",
        timezone="America/Los_Angeles",
        attendees=[Attendee(email="secret_candidate@example.com")],
        has_meet=True,
    )

    mock_insert = mock_service.events().insert
    mock_insert.return_value.execute.return_value = {
        "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
        "status": "confirmed",
        "htmlLink": "https://calendar.google.com/event?eid=abc",
        "conferenceData": {
            "createRequest": {
                "status": {"statusCode": "success"}
            },
            "entryPoints": [
                {
                    "entryPointType": "video",
                    "uri": "https://meet.google.com/abc-defg-hij",
                    "label": "meet.google.com/abc-defg-hij",
                }
            ],
            "conferenceId": "abc-defg-hij",
        },
    }

    created = manager.create_event(event, send_updates="all", confirm=True)

    assert created.html_link == "https://calendar.google.com/event?eid=abc"
    assert created.conference is not None
    assert created.conference.uri == "https://meet.google.com/abc-defg-hij"
    assert created.conference.conference_id == "abc-defg-hij"

    # Verify API payload call
    mock_insert.assert_called_once()
    call_kwargs = mock_insert.call_args.kwargs
    assert call_kwargs["calendarId"] == "primary"
    assert call_kwargs["conferenceDataVersion"] == 1
    assert call_kwargs["sendUpdates"] == "all"
    body = call_kwargs["body"]
    assert body["id"] == "c1a2b3c4d5e6f7a8b9c0d1e2f3"
    assert body["summary"] == "Executive Interview"
    assert body["conferenceData"]["createRequest"]["conferenceSolutionKey"]["type"] == "hangoutsMeet"

    # Verify audit log contains zero PII
    log_content = log_file.read_text(encoding="utf-8")
    assert "op=calendar_event_create" in log_content
    assert "eid=c1a2b3c4d5e6f7a8b9c0d1e2f3" in log_content
    assert "status=SUCCESS" in log_content
    assert "secret_candidate@example.com" not in log_content
    assert "Confidential" not in log_content
    assert "meet.google.com/abc-defg-hij" not in log_content


def test_calendar_manager_create_event_idempotency_409(tmp_path):
    from unittest.mock import MagicMock
    from httplib2 import Response
    from googleapiclient.errors import HttpError
    from gmail_local.audit import AuditLogger
    from gmail_local.calendar import CalendarManager
    from gmail_local.models import CalendarEvent

    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)
    manager = CalendarManager(audit_logger=logger)

    mock_service = MagicMock()
    manager._service = mock_service

    event = CalendarEvent(
        id="c1a2b3c4d5e6f7a8b9c0d1e2f3",
        summary="Executive Interview",
        start="2026-09-22T10:00:00-07:00",
        end="2026-09-22T10:35:00-07:00",
        timezone="America/Los_Angeles",
        has_meet=True,
    )

    # 409 Conflict on insert
    err409 = HttpError(Response({"status": 409}), b"Event ID already exists")
    mock_service.events().insert.return_value.execute.side_effect = err409

    # events().get succeeds with existing event
    mock_service.events().get.return_value.execute.return_value = {
        "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
        "status": "confirmed",
        "htmlLink": "https://calendar.google.com/event?eid=existing",
        "conferenceData": {
            "entryPoints": [
                {
                    "entryPointType": "video",
                    "uri": "https://meet.google.com/abc-defg-hij",
                }
            ],
            "conferenceId": "abc-defg-hij",
        },
    }

    created = manager.create_event(event, confirm=True)
    assert created.html_link == "https://calendar.google.com/event?eid=existing"
    assert created.conference is not None
    assert created.conference.uri == "https://meet.google.com/abc-defg-hij"


def test_calendar_manager_create_event_meet_pending_polling(tmp_path):
    from unittest.mock import MagicMock, patch
    from gmail_local.audit import AuditLogger
    from gmail_local.calendar import CalendarManager
    from gmail_local.models import CalendarEvent

    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)
    manager = CalendarManager(audit_logger=logger)

    mock_service = MagicMock()
    manager._service = mock_service

    event = CalendarEvent(
        id="c1a2b3c4d5e6f7a8b9c0d1e2f3",
        summary="Executive Interview",
        start="2026-09-22T10:00:00-07:00",
        end="2026-09-22T10:35:00-07:00",
        timezone="America/Los_Angeles",
        has_meet=True,
    )

    # insert returns pending
    mock_service.events().insert.return_value.execute.return_value = {
        "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
        "status": "confirmed",
        "conferenceData": {
            "createRequest": {
                "status": {"statusCode": "pending"}
            }
        },
    }

    # First get returns pending, second returns success
    get_call = mock_service.events().get.return_value.execute
    get_call.side_effect = [
        {
            "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
            "conferenceData": {
                "createRequest": {"status": {"statusCode": "pending"}}
            },
        },
        {
            "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
            "htmlLink": "https://calendar.google.com/event?eid=resolved",
            "conferenceData": {
                "createRequest": {"status": {"statusCode": "success"}},
                "entryPoints": [
                    {"entryPointType": "video", "uri": "https://meet.google.com/polled-link"}
                ],
                "conferenceId": "polled-link",
            },
        },
    ]

    with patch("time.sleep") as mock_sleep:
        created = manager.create_event(event, confirm=True)
        assert mock_sleep.call_count >= 1

    assert created.conference is not None
    assert created.conference.uri == "https://meet.google.com/polled-link"


def test_calendar_manager_create_event_meet_failure_raises_error():
    from unittest.mock import MagicMock
    from gmail_local.calendar import CalendarManager, CalendarConferenceError
    from gmail_local.models import CalendarEvent

    manager = CalendarManager()
    mock_service = MagicMock()
    manager._service = mock_service

    event = CalendarEvent(
        id="c1a2b3c4d5e6f7a8b9c0d1e2f3",
        summary="Executive Interview",
        start="2026-09-22T10:00:00-07:00",
        end="2026-09-22T10:35:00-07:00",
        timezone="America/Los_Angeles",
        has_meet=True,
    )

    mock_service.events().insert.return_value.execute.return_value = {
        "id": "c1a2b3c4d5e6f7a8b9c0d1e2f3",
        "conferenceData": {
            "createRequest": {
                "status": {"statusCode": "failure"}
            }
        },
    }

    with pytest.raises(CalendarConferenceError, match="Google Meet conference creation failed"):
        manager.create_event(event, confirm=True)


def test_calendar_manager_create_event_no_meet(tmp_path):
    from unittest.mock import MagicMock
    from gmail_local.audit import AuditLogger
    from gmail_local.calendar import CalendarManager
    from gmail_local.models import CalendarEvent

    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_path=log_file)
    manager = CalendarManager(audit_logger=logger)

    mock_service = MagicMock()
    manager._service = mock_service

    event = CalendarEvent(
        id="no_meet_evt_1",
        summary="In-Person Lunch",
        start="2026-09-22T12:00:00-07:00",
        end="2026-09-22T13:00:00-07:00",
        timezone="America/Los_Angeles",
        has_meet=False,
    )

    mock_insert = mock_service.events().insert
    mock_insert.return_value.execute.return_value = {
        "id": "no_meet_evt_1",
        "status": "confirmed",
        "htmlLink": "https://calendar.google.com/event?eid=nomeet",
    }

    created = manager.create_event(event, confirm=True)
    assert created.html_link == "https://calendar.google.com/event?eid=nomeet"
    assert created.conference is None

    mock_insert.assert_called_once()
    call_kwargs = mock_insert.call_args.kwargs
    assert "conferenceDataVersion" not in call_kwargs
    assert "conferenceData" not in call_kwargs["body"]
