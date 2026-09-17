"""Google Calendar event creation and Google Meet integration."""

import base64
import datetime
import hashlib
import json
import re
from typing import Any, Dict, List, Optional
import uuid
import zoneinfo

from gmail_local.config import MAX_EVENT_ATTENDEES

_EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class CalendarError(Exception):
    """Base exception for calendar operations."""


class CalendarValidationError(CalendarError):
    """Raised when event parameters fail validation."""


class CalendarConferenceError(CalendarError):
    """Raised when Google Meet conference generation fails or times out."""


class CalendarIdempotencyError(CalendarError):
    """Raised when an idempotency conflict cannot be resolved."""


class ManualActionGateViolationError(CalendarError):
    """Raised when an external mutation is attempted without explicit confirmation."""


def generate_calendar_event_id(
    summary: str,
    start_iso: str,
    end_iso: str,
    timezone_str: str,
    attendees: List[str],
    has_meet: bool,
) -> str:
    """Generates a RFC 4648 base32hex event ID from canonical event attributes."""
    canonical_obj = {
        "summary": summary.strip(),
        "start": start_iso.strip(),
        "end": end_iso.strip(),
        "timezone": timezone_str.strip(),
        "attendees": sorted(a.strip().lower() for a in attendees),
        "has_meet": has_meet,
    }
    raw_json = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(raw_json.encode("utf-8")).digest()

    # RFC 4648 base32hex (a-v, 0-9), lowercase, stripped padding
    b32_encoded = base64.b32hexencode(digest).decode("ascii").lower().rstrip("=")
    return b32_encoded[:64]


def validate_calendar_event_inputs(
    summary: str,
    start_iso: str,
    end_iso: str,
    timezone_str: str,
    attendees: Optional[List[str]] = None,
    send_updates: str = "none",
) -> None:
    """Validates calendar event input arguments against security bounds and schemas."""
    if not summary or not summary.strip():
        raise CalendarValidationError("Summary cannot be empty or whitespace.")

    for field_name, val in [("Summary", summary), ("Timezone", timezone_str)]:
        if any(c in val for c in ("\r", "\n", "\0")):
            raise CalendarValidationError(f"{field_name} contains forbidden CRLF or null bytes.")

    if send_updates not in ("none", "externalOnly", "all"):
        raise CalendarValidationError(
            f"send_updates must be one of ('none', 'externalOnly', 'all'), got '{send_updates}'."
        )

    try:
        tz = zoneinfo.ZoneInfo(timezone_str.strip())
    except Exception as e:
        raise CalendarValidationError(f"Invalid IANA timezone '{timezone_str}': {e}") from e

    try:
        start_dt = datetime.datetime.fromisoformat(start_iso.strip())
    except Exception as e:
        raise CalendarValidationError(f"Invalid start datetime '{start_iso}': {e}") from e

    try:
        end_dt = datetime.datetime.fromisoformat(end_iso.strip())
    except Exception as e:
        raise CalendarValidationError(f"Invalid end datetime '{end_iso}': {e}") from e

    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=tz)
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=tz)

    if end_dt <= start_dt:
        raise CalendarValidationError(
            f"End time must be after start time (start: {start_iso}, end: {end_iso})."
        )

    att_list = attendees or []
    if len(att_list) > MAX_EVENT_ATTENDEES:
        raise CalendarValidationError(
            f"Attendee count {len(att_list)} exceeds maximum bound of {MAX_EVENT_ATTENDEES}."
        )

    for att in att_list:
        if any(c in att for c in ("\r", "\n", "\0")):
            raise CalendarValidationError(f"Attendee email '{att}' contains forbidden CRLF or null bytes.")
        if not _EMAIL_REGEX.match(att.strip()):
            raise CalendarValidationError(f"Invalid attendee email '{att}'.")


def format_calendar_handoff_markdown(
    event: "CalendarEvent",
    send_updates: str,
) -> str:
    """Formats human-readable and CLI-executable Calendar Event Handoff block."""
    tz = zoneinfo.ZoneInfo(event.timezone.strip())
    start_dt = datetime.datetime.fromisoformat(event.start.strip())
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=tz)
    end_dt = datetime.datetime.fromisoformat(event.end.strip())
    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=tz)

    duration_secs = int((end_dt - start_dt).total_seconds())
    duration_mins = duration_secs // 60
    if duration_mins >= 60 and duration_mins % 60 == 0:
        duration_str = f"{duration_mins // 60} hour(s)"
    elif duration_mins >= 60:
        duration_str = f"{duration_mins // 60} hour(s) {duration_mins % 60} minutes"
    else:
        duration_str = f"{duration_mins} minutes"

    fp = event.compute_fingerprint()
    meet_str = "ENABLED (Will generate unique conference space)" if event.has_meet else "DISABLED"
    updates_label = {
        "all": "ALL (Google Calendar will send email invitations)",
        "externalOnly": "EXTERNAL_ONLY (Invitations sent to external guests only)",
        "none": "NONE (No email invitations sent)",
    }.get(send_updates, send_updates.upper())

    lines = [
        "=========================== CALENDAR EVENT HANDOFF ===========================",
        f"Event Fingerprint:  {fp}",
        f"Event ID (Target):  {event.id}",
        f"Summary:            {event.summary}",
        f"Start Time:         {event.start} ({event.timezone})",
        f"End Time:           {event.end} ({event.timezone})",
        f"Duration:           {duration_str}",
        f"Google Meet:        {meet_str}",
        f"Attendees:          {len(event.attendees)} recipient(s)",
        f"Send Updates:       {updates_label}",
        "",
        "To authorize creation on your primary Google Calendar, run:",
        "  gmail-local calendar-event create \\",
        f"    --summary {repr(event.summary)} \\",
        f"    --start {repr(event.start)} \\",
        f"    --end {repr(event.end)} \\",
        f"    --timezone {repr(event.timezone)} \\",
    ]
    for a in event.attendees:
        lines.append(f"    --attendee {repr(a.email)} \\")
    if event.has_meet:
        lines.append("    --meet \\")
    if event.description:
        lines.append(f"    --description {repr(event.description)} \\")
    lines.append(f"    --send-updates {send_updates} \\")
    lines.append("    --confirm")
    lines.append("==============================================================================")
    return "\n".join(lines)


class CalendarManager:
    """Manages Google Calendar event operations and Google Meet integration."""

    def __init__(
        self,
        auth_manager: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
    ):
        from gmail_local.audit import AuditLogger
        from gmail_local.auth import AuthManager
        from gmail_local.rate_limiter import RateLimiter

        self.auth_manager = auth_manager or AuthManager.for_calendar()
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_logger = audit_logger or AuditLogger()
        self._service = None

    def preview_event(
        self,
        summary: str,
        start_iso: str,
        end_iso: str,
        timezone_str: str,
        description: Optional[str] = None,
        attendees: Optional[List[str]] = None,
        has_meet: bool = True,
        send_updates: str = "none",
    ) -> "CalendarPreview":
        """Validates inputs, generates deterministic ID, and builds preview handoff."""
        from gmail_local.models import Attendee, CalendarEvent, CalendarPreview

        att_list = attendees or []
        validate_calendar_event_inputs(
            summary=summary,
            start_iso=start_iso,
            end_iso=end_iso,
            timezone_str=timezone_str,
            attendees=att_list,
            send_updates=send_updates,
        )

        event_id = generate_calendar_event_id(
            summary=summary,
            start_iso=start_iso,
            end_iso=end_iso,
            timezone_str=timezone_str,
            attendees=att_list,
            has_meet=has_meet,
        )

        event = CalendarEvent(
            id=event_id,
            summary=summary.strip(),
            start=start_iso.strip(),
            end=end_iso.strip(),
            timezone=timezone_str.strip(),
            description=description.strip() if description else None,
            attendees=[Attendee(email=a.strip()) for a in att_list],
            has_meet=has_meet,
        )

        handoff_md = format_calendar_handoff_markdown(event, send_updates=send_updates)
        return CalendarPreview(
            event=event,
            send_updates=send_updates,
            handoff_markdown=handoff_md,
        )

    def _get_service(self):
        """Constructs or returns cached Google Calendar API v3 service."""
        if self._service is None:
            from googleapiclient.discovery import build
            creds = self.auth_manager.get_credentials()
            self._service = build("calendar", "v3", credentials=creds, cache_discovery=False)
        return self._service

    def create_event(
        self,
        event: "CalendarEvent",
        send_updates: str = "none",
        confirm: bool = False,
    ) -> "CalendarEvent":
        """Executes Google Calendar event creation under Manual Action Gate."""
        from dataclasses import replace
        import time
        from googleapiclient.errors import HttpError
        from gmail_local.models import AuditEntry, ConferenceData

        if not confirm:
            raise ManualActionGateViolationError(
                "Manual Action Gate: Calendar event creation requires explicit confirmation. "
                "Pass --confirm to authorize this operation."
            )

        if send_updates not in ("none", "externalOnly", "all"):
            raise CalendarValidationError(
                f"send_updates must be one of ('none', 'externalOnly', 'all'), got '{send_updates}'."
            )

        service = self._get_service()

        # Construct request body
        body: Dict[str, Any] = {
            "id": event.id,
            "summary": event.summary,
            "start": {
                "dateTime": event.start,
                "timeZone": event.timezone,
            },
            "end": {
                "dateTime": event.end,
                "timeZone": event.timezone,
            },
        }
        if event.description:
            body["description"] = event.description

        if event.attendees:
            body["attendees"] = [
                {"email": a.email, "responseStatus": a.response_status}
                for a in event.attendees
            ]

        if event.has_meet:
            body["conferenceData"] = {
                "createRequest": {
                    "requestId": f"req-{uuid.uuid4()}",
                    "conferenceSolutionKey": {
                        "type": "hangoutsMeet",
                    },
                }
            }

        insert_kwargs: Dict[str, Any] = {
            "calendarId": "primary",
            "sendUpdates": send_updates,
            "body": body,
        }
        if event.has_meet:
            insert_kwargs["conferenceDataVersion"] = 1

        is_conflict = False
        try:
            resp = self.rate_limiter.execute_with_retry(
                "events.insert",
                lambda: service.events().insert(**insert_kwargs).execute(),
            )
        except HttpError as e:
            if e.resp.status == 409:
                is_conflict = True
                get_kwargs: Dict[str, Any] = {
                    "calendarId": "primary",
                    "eventId": event.id,
                }
                if event.has_meet:
                    get_kwargs["conferenceDataVersion"] = 1
                resp = self.rate_limiter.execute_with_retry(
                    "events.get",
                    lambda: service.events().get(**get_kwargs).execute(),
                )
            else:
                raise

        html_link = resp.get("htmlLink")

        # Conference resolution if has_meet
        conference_obj: Optional[ConferenceData] = None
        if event.has_meet:
            conf_data = resp.get("conferenceData", {})
            create_req = conf_data.get("createRequest", {})
            status_code = create_req.get("status", {}).get("statusCode")

            if status_code == "failure":
                raise CalendarConferenceError(
                    f"Google Meet conference creation failed for event '{event.id}'."
                )

            if status_code == "pending":
                poll_schedule = [0.5, 1.0, 2.0, 4.0]
                resolved = False
                for delay in poll_schedule:
                    time.sleep(delay)
                    polled = self.rate_limiter.execute_with_retry(
                        "events.get",
                        lambda: service.events().get(
                            calendarId="primary",
                            eventId=event.id,
                            conferenceDataVersion=1,
                        ).execute(),
                    )
                    polled_conf = polled.get("conferenceData", {})
                    polled_status = (
                        polled_conf.get("createRequest", {})
                        .get("status", {})
                        .get("statusCode")
                    )
                    if polled_status == "success":
                        conf_data = polled_conf
                        if polled.get("htmlLink"):
                            html_link = polled.get("htmlLink")
                        resolved = True
                        break
                    elif polled_status == "failure":
                        raise CalendarConferenceError(
                            f"Google Meet conference creation failed for event '{event.id}'."
                        )

                if not resolved:
                    raise CalendarConferenceError(
                        f"Google Meet conference creation timed out in 'pending' state for event '{event.id}'."
                    )

            entry_points = conf_data.get("entryPoints", [])
            video_uri = None
            phone_uri = None
            phone_pin = None
            label = None
            for ep in entry_points:
                if ep.get("entryPointType") == "video":
                    video_uri = ep.get("uri")
                    label = ep.get("label")
                elif ep.get("entryPointType") == "phone":
                    phone_uri = ep.get("uri")
                    phone_pin = ep.get("pin")

            conference_id = conf_data.get("conferenceId") or ""
            if video_uri:
                conference_obj = ConferenceData(
                    uri=video_uri,
                    conference_id=conference_id,
                    entry_point_type="video",
                    status="success",
                    label=label,
                    phone_uri=phone_uri,
                    phone_pin=phone_pin,
                )

        status_label = "CONFLICT_RESOLVED" if is_conflict else "SUCCESS"
        self.audit_logger.record(
            AuditEntry(
                operation="calendar_event_create",
                purpose="create_event",
                status=status_label,
                event_id=event.id,
                fingerprint=event.compute_fingerprint(),
                details=(
                    f"start={event.start}_end={event.end}_tz={event.timezone}_"
                    f"attendees={len(event.attendees)}_has_meet={event.has_meet}"
                ),
            )
        )

        return replace(
            event,
            html_link=html_link,
            conference=conference_obj,
            fingerprint=event.compute_fingerprint(),
        )
