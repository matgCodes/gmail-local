"""Command-line interface for gmail-local."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import List

from gmail_local.auth import AuthError, AuthManager
from gmail_local.composer import (
    GmailDraftManager,
    create_frozen_draft,
    load_draft_locally,
    save_draft_locally,
)
from gmail_local.config import (
    DEFAULT_SEARCH_BOUND,
    DRAFTS_DIR,
    MAX_CLEANUP_BATCH_SIZE,
    MAX_SEARCH_BOUND,
    PLANS_DIR,
)
from gmail_local.calendar import (
    CalendarConferenceError,
    CalendarError,
    CalendarManager,
    CalendarValidationError,
    ManualActionGateViolationError,
)
from gmail_local.models import (
    Attendee,
    CalendarEvent,
    CalendarPreview,
    CleanupAction,
    CleanupPlan,
    CleanupPlanValidationError,
    CleanupTarget,
    ConferenceData,
    FrozenDraft,
    FrozenDraftValidationError,
)
from gmail_local.modifier import (
    GmailModifier,
    ManualModifyGateViolationError,
    SecurityViolationError,
    load_plan_locally,
    save_plan_locally,
)
from gmail_local.retrieval import GmailRetriever, RetrievalBoundError
from gmail_local.sender import GmailSender
from gmail_local.triage import (
    DEFAULT_POLICY_FILE,
    TriageAction,
    TriageCategory,
    TriageClassifier,
    TriageDecision,
    TriageManifest,
    TriagePlanGenerator,
    TriagePolicy,
    TriageScanner,
)


def cmd_status(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Report account and authorization status without exposing token secrets."""
    status = retriever.auth.get_status()
    print("=== Gmail Local Retrieval Status ===")
    print(f"Account:          {status['account']}")
    print(f"Keychain Service: {status['keychain_service']}")
    print(f"Client Secret:    {'Found' if status['has_client_secret'] else 'Missing (~/.config/gmail-local/client_secret.json)'}")
    print(f"Keychain Token:   {'Present' if status['has_keychain_token'] else 'Not stored (run login)'}")
    print(f"Token Valid:      {'Yes (active & refreshable)' if status['is_valid'] else 'No'}")
    print(f"Scope:            {status['scope']}")
    return 0 if status["is_valid"] else 1


def cmd_login(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute interactive OAuth login with PKCE in the system browser."""
    print("Initiating OAuth login flow with Google...")
    print("A browser window will open requesting consent for 'gmail.readonly'.")
    try:
        account = retriever.auth.run_interactive_login(open_browser=not args.no_browser)
        print(f"Successfully authorized and stored refresh token in Keychain for {account}!")
        return 0
    except AuthError as e:
        print(f"Authorization error: {e}", file=sys.stderr)
        return 1


def cmd_revoke(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Revoke authorization and delete Keychain credentials."""
    print("Revoking Google OAuth token and clearing Keychain entry...")
    try:
        retriever.auth.revoke()
        print("Successfully revoked and removed credentials from Keychain.")
        return 0
    except Exception as e:
        print(f"Revocation error: {e}", file=sys.stderr)
        return 1


def cmd_compose_status(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Report transmission authorization status without exposing token secrets."""
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_transmission(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_transmission()
    )
    status = auth.get_status()
    print("=== Gmail Local Transmission Status ===")
    print(f"Account:          {status['account']}")
    print(f"Keychain Service: {status['keychain_service']}")
    print(f"Client Secret:    {'Found' if status['has_client_secret'] else 'Missing (~/.config/gmail-local/client_secret_transmission.json)'}")
    print(f"Keychain Token:   {'Present' if status['has_keychain_token'] else 'Not stored (run compose-login)'}")
    print(f"Token Valid:      {'Yes (active & refreshable)' if status['is_valid'] else 'No'}")
    print(f"Scope:            {status['scope']}")
    return 0 if status["is_valid"] else 1


def cmd_compose_login(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute interactive OAuth login for transmission (gmail.compose) with PKCE."""
    print("Initiating Transmission OAuth login flow with Google...")
    print("A browser window will open requesting consent for 'gmail.compose'.")
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_transmission(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_transmission()
    )
    try:
        account = auth.run_interactive_login(open_browser=not args.no_browser)
        print(f"Successfully authorized transmission and stored refresh token in Keychain for {account}!")
        return 0
    except AuthError as e:
        print(f"Transmission authorization error: {e}", file=sys.stderr)
        return 1


def cmd_compose_revoke(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Revoke transmission authorization and clear transmission Keychain entry."""
    print("Revoking Transmission OAuth token and clearing Keychain entry...")
    auth = AuthManager.for_transmission()
    try:
        auth.revoke()
        print("Successfully revoked transmission credentials and removed from Keychain.")
        return 0
    except Exception as e:
        print(f"Transmission revocation error: {e}", file=sys.stderr)
        return 1


def cmd_modify_status(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Report mailbox modification authorization status without exposing token secrets."""
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_modification(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_modification()
    )
    status = auth.get_status()
    print("=== Gmail Local Modification Status ===")
    print(f"Account:          {status['account']}")
    print(f"Keychain Service: {status['keychain_service']}")
    print(f"Client Secret:    {'Found' if status['has_client_secret'] else 'Missing (~/.config/gmail-local/client_secret_modify.json)'}")
    print(f"Keychain Token:   {'Present' if status['has_keychain_token'] else 'Not stored (run modify-login)'}")
    print(f"Token Valid:      {'Yes (active & refreshable)' if status['is_valid'] else 'No'}")
    print(f"Scope:            {status['scope']}")
    return 0 if status["is_valid"] else 1


def cmd_modify_login(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute interactive OAuth login for modification (gmail.modify) with PKCE."""
    print("Initiating Modification OAuth login flow with Google...")
    print("A browser window will open requesting consent for 'gmail.modify'.")
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_modification(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_modification()
    )
    try:
        account = auth.run_interactive_login(open_browser=not args.no_browser)
        print(f"Successfully authorized modification and stored refresh token in Keychain for {account}!")
        return 0
    except AuthError as e:
        print(f"Modification authorization error: {e}", file=sys.stderr)
        return 1


def cmd_modify_revoke(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Revoke modification authorization and clear modification Keychain entry."""
    print("Revoking Modification OAuth token and clearing Keychain entry...")
    auth = AuthManager.for_modification()
    try:
        auth.revoke()
        print("Successfully revoked modification credentials and removed from Keychain.")
        return 0
    except Exception as e:
        print(f"Modification revocation error: {e}", file=sys.stderr)
        return 1


def cmd_calendar_status(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Report calendar authorization status without exposing token secrets."""
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_calendar(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_calendar()
    )
    status = auth.get_status()
    print("=== Gmail Local Calendar Status ===")
    print(f"Account:          {status['account']}")
    print(f"Keychain Service: {status['keychain_service']}")
    print(f"Client Secret:    {'Found' if status['has_client_secret'] else 'Missing (~/.config/gmail-local/client_secret_calendar.json or client_secret_meet.json)'}")
    print(f"Keychain Token:   {'Present' if status['has_keychain_token'] else 'Not stored (run calendar-login)'}")
    print(f"Token Valid:      {'Yes (active & refreshable)' if status['is_valid'] else 'No'}")
    print(f"Scope:            {status['scope']}")
    return 0 if status["is_valid"] else 1


def cmd_calendar_login(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute interactive OAuth login for calendar (calendar.events.owned) with PKCE."""
    print("Initiating Calendar OAuth login flow with Google...")
    print("A browser window will open requesting consent for 'calendar.events.owned'.")
    secret_path = getattr(args, "client_secret", None)
    auth = (
        AuthManager.for_calendar(client_secret_path=secret_path)
        if secret_path
        else AuthManager.for_calendar()
    )
    try:
        account = auth.run_interactive_login(open_browser=not args.no_browser)
        print(f"Successfully authorized calendar and stored refresh token in Keychain for {account}!")
        return 0
    except AuthError as e:
        print(f"Calendar authorization error: {e}", file=sys.stderr)
        return 1


def cmd_calendar_revoke(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Revoke calendar authorization and clear calendar Keychain entry."""
    print("Revoking Calendar OAuth token and clearing Keychain entry...")
    auth = AuthManager.for_calendar()
    try:
        auth.revoke()
        print("Successfully revoked calendar credentials and removed from Keychain.")
        return 0
    except Exception as e:
        print(f"Calendar revocation error: {e}", file=sys.stderr)
        return 1


def cmd_calendar_event_preview(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Preview a Calendar event and generate standard handoff markdown."""
    manager = CalendarManager()
    try:
        preview = manager.preview_event(
            summary=args.summary,
            start_iso=args.start,
            end_iso=args.end,
            timezone_str=args.timezone,
            description=args.description,
            attendees=args.attendees,
            has_meet=args.meet,
            send_updates=args.send_updates,
        )
        print(preview.handoff_markdown)
        return 0
    except Exception as e:
        print(f"Calendar event preview error: {e}", file=sys.stderr)
        return 1


def cmd_calendar_event_create(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Create a Calendar event behind Manual Action Gate."""
    manager = CalendarManager()
    try:
        preview = manager.preview_event(
            summary=args.summary,
            start_iso=args.start,
            end_iso=args.end,
            timezone_str=args.timezone,
            description=args.description,
            attendees=args.attendees,
            has_meet=args.meet,
            send_updates=args.send_updates,
        )
    except Exception as e:
        print(f"Calendar event validation error: {e}", file=sys.stderr)
        return 1

    event = preview.event

    if not args.confirm:
        if not sys.stdin.isatty():
            print(
                "Manual Action Gate violation: Calendar event creation in non-interactive environment requires explicit --confirm flag.",
                file=sys.stderr,
            )
            return 1
        try:
            print(preview.handoff_markdown)
            user_input = input("Type 'yes' to authorize calendar event creation: ")
            if user_input.strip().lower() != "yes":
                print("Event creation aborted by operator.", file=sys.stderr)
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nEvent creation aborted by operator.", file=sys.stderr)
            return 1

    try:
        created = manager.create_event(
            event=event,
            send_updates=args.send_updates,
            confirm=True,
        )
        print("\n======================= CALENDAR EVENT CREATION RECEIPT =======================")
        print("Status:          SUCCESS")
        print(f"Event ID:        {created.id}")
        print(f"Summary:         {created.summary}")
        print(f"Start:           {created.start} ({created.timezone})")
        print(f"End:             {created.end} ({created.timezone})")
        print(f"HTML Link:       {created.html_link or 'N/A'}")
        print(f"Google Meet:     {created.conference.uri if created.conference else 'None'}")
        print(f"Conference ID:   {created.conference.conference_id if created.conference else 'None'}")
        print(f"Attendees:       {len(created.attendees)} recipient(s)")
        print(f"Send Updates:    {args.send_updates.upper()}")
        print("==============================================================================")
        return 0
    except Exception as e:
        print(f"Calendar event creation failed: {e}", file=sys.stderr)
        return 1


def cmd_calendar_event(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Entry point when no calendar-event subcommand is given."""
    print("Usage: gmail-local calendar-event [preview|create] [options]")
    return 0


def cmd_draft(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Create an immutable FrozenDraft and optionally stage to Gmail Drafts."""
    # Resolve body
    body_text = ""
    if getattr(args, "body_file", None):
        body_path = Path(args.body_file).expanduser()
        if not body_path.exists():
            print(f"Error: Body file not found: {args.body_file}", file=sys.stderr)
            return 1
        body_text = body_path.read_text(encoding="utf-8")
    elif getattr(args, "body", None):
        body_text = args.body
    else:
        print("Error: Either --body or --body-file is required.", file=sys.stderr)
        return 1

    # Resolve HTML
    body_html = None
    if getattr(args, "html_file", None):
        html_path = Path(args.html_file).expanduser()
        if not html_path.exists():
            print(f"Error: HTML file not found: {args.html_file}", file=sys.stderr)
            return 1
        body_html = html_path.read_text(encoding="utf-8")
    elif getattr(args, "html", None):
        body_html = args.html

    try:
        thread_id = getattr(args, "thread_id", None)
        in_reply_to = getattr(args, "in_reply_to", None)
        references = getattr(args, "references", None)
        reply_to_message_id = getattr(args, "reply_to_message_id", None)
        if reply_to_message_id:
            if thread_id or in_reply_to or references:
                raise FrozenDraftValidationError(
                    "--reply-to-message-id cannot be combined with manual thread headers."
                )
            reply_metadata = retriever.get_reply_metadata(
                reply_to_message_id,
                purpose=f"{args.purpose}_thread_context",
            )
            if args.subject.strip() != reply_metadata.subject.strip():
                raise FrozenDraftValidationError(
                    "Guaranteed threaded replies require the subject to exactly match "
                    f"the selected message subject: {reply_metadata.subject}"
                )
            thread_id = reply_metadata.thread_id
            in_reply_to = reply_metadata.rfc_message_id
            references = list(reply_metadata.references)

        draft = create_frozen_draft(
            to=args.to,
            subject=args.subject,
            body_text=body_text,
            cc=getattr(args, "cc", None),
            bcc=getattr(args, "bcc", None),
            body_html=body_html,
            thread_id=thread_id,
            in_reply_to=in_reply_to,
            references=references,
            attachment_paths=getattr(args, "attach", None),
            attachment_mode=getattr(args, "attach_mode", "auto"),
        )

        staging_info = "Local Only"
        if not getattr(args, "local_only", False):
            draft_manager = GmailDraftManager()
            draft = draft_manager.save_draft(draft, purpose=args.purpose)
            staging_info = f"Staged to Gmail Drafts (Draft ID: {draft.draft_id})"

        # Persist locally for sender resolution and auditing
        try:
            save_draft_locally(draft, drafts_dir=DRAFTS_DIR)
        except Exception:
            pass

        # Output Send Handoff
        fp = draft.compute_fingerprint()
        body_bytes = len(draft.body_text.encode("utf-8")) + (len(draft.body_html.encode("utf-8")) if draft.body_html else 0)
        att_bytes = sum(att.size_bytes for att in draft.attachments)
        total_bytes = body_bytes + att_bytes

        print("=== SEND HANDOFF ===")
        print(f"Draft Fingerprint: {fp}")
        print(f"Recipients (To):  {', '.join(draft.to)}")
        if draft.cc:
            print(f"Recipients (Cc):  {', '.join(draft.cc)}")
        if draft.bcc:
            print(f"Recipients (Bcc): {', '.join(draft.bcc)}")
        print(f"Subject:          {draft.subject}")
        if draft.thread_id:
            print(f"Thread ID:        {draft.thread_id}")
        if draft.attachments:
            att_names = ", ".join(f"{a.filename} ({a.size_bytes} B)" for a in draft.attachments)
            print(f"Attachments:      {att_names}")
        print(f"Payload Size:     {total_bytes:,} bytes")
        print(f"Gmail Staging:    {staging_info}")
        if draft.draft_id:
            print("\nTo inspect this draft in Gmail:")
            print("  Open https://mail.google.com/#drafts")
        print("\nTo authorize transmission, the Operator must independently run:")
        print(f"  gmail-local send --draft {fp} --confirm")
        print("====================")
        return 0

    except (FrozenDraftValidationError, RetrievalBoundError, AuthError) as e:
        print(f"Draft creation error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Draft creation failed: {e}", file=sys.stderr)
        return 1


def cmd_send(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute manual send gate and transmit a FrozenDraft."""
    draft = None
    try:
        draft = load_draft_locally(args.draft, drafts_dir=DRAFTS_DIR)
    except (FileNotFoundError, FrozenDraftValidationError):
        pass

    if draft is None:
        try:
            draft_manager = GmailDraftManager()
            remote_draft = draft_manager.get_draft(args.draft, purpose=args.purpose)
            msg_payload = remote_draft.get("message", {}).get("payload", {})
            headers = {h["name"].lower(): h["value"] for h in msg_payload.get("headers", [])}
            to_list = [addr.strip() for addr in headers.get("to", "").split(",") if addr.strip()]
            cc_list = [addr.strip() for addr in headers.get("cc", "").split(",") if addr.strip()]
            bcc_list = [addr.strip() for addr in headers.get("bcc", "").split(",") if addr.strip()]
            subject_val = headers.get("subject", "(no subject)")
            snippet_val = remote_draft.get("message", {}).get("snippet", "")
            draft = FrozenDraft(
                to=to_list or ["(staged recipient)"],
                subject=subject_val,
                body_text=snippet_val,
                cc=cc_list,
                bcc=bcc_list,
                draft_id=remote_draft.get("id"),
            )
        except Exception:
            pass

    if draft is None:
        print(f"Draft not found matching identifier: '{args.draft}'", file=sys.stderr)
        return 1

    fp = draft.compute_fingerprint()
    body_bytes = len(draft.body_text.encode("utf-8")) + (len(draft.body_html.encode("utf-8")) if draft.body_html else 0)
    att_bytes = sum(att.size_bytes for att in draft.attachments)
    total_bytes = body_bytes + att_bytes

    print("=== MANUAL SEND GATE: TRANSMISSION AUTHORIZATION ===")
    print(f"Draft Fingerprint: {fp}")
    print(f"Recipients (To):  {', '.join(draft.to)}")
    if draft.cc:
        print(f"Recipients (Cc):  {', '.join(draft.cc)}")
    if draft.bcc:
        print(f"Recipients (Bcc): {', '.join(draft.bcc)}")
    print(f"Subject:          {draft.subject}")
    if draft.attachments:
        att_names = ", ".join(f"{a.filename} ({a.size_bytes} B)" for a in draft.attachments)
        print(f"Attachments:      {att_names}")
    print(f"Payload Size:     {total_bytes:,} bytes")
    if draft.draft_id:
        print(f"Gmail Draft ID:   {draft.draft_id}")
    print("====================================================")

    if not args.confirm:
        if not sys.stdin.isatty():
            print(
                "Manual Send Gate violation: Transmission in non-interactive environment requires explicit --confirm flag.",
                file=sys.stderr,
            )
            return 1
        try:
            user_input = input("Type 'yes' to authorize transmission of this message: ")
            if user_input.strip().lower() != "yes":
                print("Transmission aborted by operator.", file=sys.stderr)
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nTransmission aborted by operator.", file=sys.stderr)
            return 1

    try:
        sender = GmailSender()
        result = sender.send(draft, purpose=args.purpose)
        print("\n========================== TRANSMISSION RECEIPT ==========================")
        print("Status:                     SENT")
        print(f"Message ID:                 {result['id']}")
        print(f"Thread ID:                  {result['threadId']}")
        if result.get("draft_id"):
            print(f"Draft ID:                   {result['draft_id']}")
        print(f"Fingerprint:                {result['fingerprint']}")
        print(f"Timestamp:                  {datetime.now(timezone.utc).isoformat()}")
        print("\n--- Delivery Verification Summary ---")
        print("Local Attachment Integrity: VERIFIED (Digest & size match local disk)")
        if result.get("draft_id"):
            print("Remote Draft Readback:      VERIFIED (Raw MIME tree & payload match Frozen Draft)")
        else:
            print("Remote Draft Readback:      N/A (Unstaged direct send)")
        print(f"Gmail Send API Acceptance:  ACCEPTED (API accepted transmission; returned ID: {result['id']})")
        print("Stored Sent Raw Message:    PENDING RETRIEVAL INSPECTION (Query stored raw via 'read' or API)")
        print("Recipient/UI Presentation:  NOT PROGRAMMATICALLY VERIFIED (Client UI rendering depends on mail user agent)")
        print("==========================================================================")
        return 0
    except (FrozenDraftValidationError, AuthError) as e:
        print(f"Transmission error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Transmission failed: {e}", file=sys.stderr)
        return 1


def cmd_drafts(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """List or inspect Gmail drafts."""
    draft_manager = GmailDraftManager()
    if getattr(args, "drafts_subcommand", None) == "list":
        try:
            drafts = draft_manager.list_drafts(max_results=args.limit, purpose=args.purpose)
            if not drafts:
                print("No drafts found in Gmail mailbox.")
                return 0
            print(f"Found {len(drafts)} draft(s) in mailbox:")
            print("-" * 60)
            for d in drafts:
                d_id = d.get("id", "unknown")
                msg = d.get("message", {})
                snippet = msg.get("snippet", "")
                print(f"Draft ID: {d_id}")
                if snippet:
                    print(f"  Snippet: {snippet}")
                print("-" * 60)
            return 0
        except Exception as e:
            print(f"Failed to list drafts: {e}", file=sys.stderr)
            return 1
    elif getattr(args, "drafts_subcommand", None) == "get":
        try:
            draft = draft_manager.get_draft(args.draft_id, purpose=args.purpose)
            print(f"Draft ID: {draft.get('id')}")
            msg = draft.get("message", {})
            print(f"Message ID: {msg.get('id')}")
            print(f"Snippet: {msg.get('snippet')}")
            return 0
        except Exception as e:
            print(f"Failed to get draft: {e}", file=sys.stderr)
            return 1
    else:
        print("Specify 'list' or 'get <draft_id>'", file=sys.stderr)
        return 1


def cmd_cleanup_plan(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Generate a staged cleanup plan matching query and action."""
    try:
        action_enum = CleanupAction(args.action)
        modifier = GmailModifier()
        plan = modifier.build_plan(
            query=args.query,
            action=action_enum,
            add_labels=getattr(args, "add_label", None),
            remove_labels=getattr(args, "remove_label", None),
            limit=args.limit,
            purpose=args.purpose,
        )
        print(plan.to_handoff_summary())
        return 0
    except (CleanupPlanValidationError, AuthError) as e:
        print(f"Cleanup plan error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Cleanup plan generation failed: {e}", file=sys.stderr)
        return 1


def cmd_cleanup_preview(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Preview targets in a staged cleanup plan."""
    try:
        plan = load_plan_locally(args.plan, plans_dir=PLANS_DIR)
        fp = plan.compute_fingerprint()
        print("=== CLEANUP PLAN PREVIEW ===")
        print(f"Plan Fingerprint: {fp}")
        print(f"Action:           {plan.action_type.value.upper()}")
        print(f"Query:            {plan.query}")
        print(f"Target Count:     {len(plan.targets)} messages")
        print("----------------------------------------------------------------")
        for t in plan.targets:
            add_str = f" +[{','.join(t.add_labels)}]" if t.add_labels else ""
            rem_str = f" -[{','.join(t.remove_labels)}]" if t.remove_labels else ""
            print(f"[{t.message_id}] {t.date} | {t.sender} | {t.subject}{add_str}{rem_str}")
        print("================================================================")
        return 0
    except Exception as e:
        print(f"Failed to preview cleanup plan: {e}", file=sys.stderr)
        return 1


def cmd_cleanup_apply(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute manual modify gate and apply a staged cleanup plan."""
    try:
        plan = load_plan_locally(args.plan, plans_dir=PLANS_DIR)
    except Exception as e:
        print(f"Cleanup plan not found matching identifier: '{args.plan}': {e}", file=sys.stderr)
        return 1

    fp = plan.compute_fingerprint()
    print("=== MANUAL MODIFY GATE: MAILBOX MUTATION AUTHORIZATION ===")
    print(f"Plan Fingerprint: {fp}")
    print(f"Action Type:      {plan.action_type.value.upper()}")
    print(f"Search Query:     {plan.query}")
    print(f"Target Messages:  {len(plan.targets)}")
    print("=========================================================")

    if not args.confirm:
        if not sys.stdin.isatty():
            print(
                "Manual Modify Gate violation: Mailbox modification in non-interactive environment requires explicit --confirm flag.",
                file=sys.stderr,
            )
            return 1
        try:
            user_input = input("Type 'yes' to authorize mailbox modification: ")
            if user_input.strip().lower() != "yes":
                print("Modification aborted by operator.", file=sys.stderr)
                return 1
        except (KeyboardInterrupt, EOFError):
            print("\nModification aborted by operator.", file=sys.stderr)
            return 1

    try:
        modifier = GmailModifier()
        result = modifier.apply_plan(plan, confirm=True, purpose=args.purpose)
        print("\n======================= CLEANUP EXECUTION RECEIPT =======================")
        print("Status:          SUCCESS")
        print(f"Plan FP:         {result['fingerprint']}")
        print(f"Action:          {result['action'].upper()}")
        print(f"Processed:       {result['processed']} messages")
        print("=========================================================================")
        return 0
    except Exception as e:
        print(f"Cleanup execution failed: {e}", file=sys.stderr)
        return 1


def cmd_cleanup_untrash(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Restore a message from Gmail Trash."""
    try:
        modifier = GmailModifier()
        res = modifier.untrash(args.message_id, purpose=args.purpose)
        print(f"Restored message '{res['message_id']}' from Trash.")
        return 0
    except Exception as e:
        print(f"Failed to untrash message '{args.message_id}': {e}", file=sys.stderr)
        return 1


def cmd_cleanup(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Dispatch cleanup subcommands."""
    sub = getattr(args, "cleanup_subcommand", None)
    if sub == "plan":
        return cmd_cleanup_plan(retriever, args)
    elif sub == "preview":
        return cmd_cleanup_preview(retriever, args)
    elif sub == "apply":
        return cmd_cleanup_apply(retriever, args)
    elif sub == "untrash":
        return cmd_cleanup_untrash(retriever, args)
    else:
        print("Specify a cleanup subcommand: plan, preview, apply, or untrash", file=sys.stderr)
        return 1


def cmd_triage_scan(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Scan candidate messages, classify via triage policy, and display categorized breakdown."""
    try:
        if args.limit > MAX_SEARCH_BOUND:
            candidates = retriever.search_candidates_paginated(
                query=args.query,
                total_limit=args.limit,
                purpose=args.purpose,
            )
        else:
            candidates = retriever.search_messages(
                query=args.query,
                max_results=args.limit,
                purpose=args.purpose,
            )
        if not candidates:
            print(f"No messages matched triage query: '{args.query}'")
            return 0

        policy_path = getattr(args, "policy", None)
        policy = TriagePolicy.load(policy_path)
        classifier = TriageClassifier(policy=policy)
        decisions: List[TriageDecision] = []
        for c in candidates:
            decision = classifier.classify(
                message_id=c.id,
                thread_id=c.thread_id,
                sender=c.sender,
                subject=c.subject,
                date=c.date,
                labels=list(c.labels),
            )
            decisions.append(decision)

        # Count by category & action
        action_counts = {TriageAction.TRASH: 0, TriageAction.ARCHIVE: 0, TriageAction.KEEP: 0}
        category_counts: dict[str, int] = {}
        for d in decisions:
            action_counts[d.action] = action_counts.get(d.action, 0) + 1
            cat_name = d.category.value
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

        scanner = TriageScanner(classifier)
        clusters = scanner.cluster_candidates(candidates)

        print("=" * 78)
        print("  INBOX TRIAGE POLICY SCAN BREAKDOWN")
        print("=" * 78)
        print(f"Query:           {args.query}")
        print(f"Policy:          {policy.name}")
        print(f"Scanned:         {len(decisions)} messages")
        print(f"Action Summary:  TRASH: {action_counts[TriageAction.TRASH]} | ARCHIVE: {action_counts[TriageAction.ARCHIVE]} | KEEP/PROTECT: {action_counts[TriageAction.KEEP]}")
        print("-" * 78)
        print("Category Distribution:")
        for cat, cnt in sorted(category_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {cat:25s}: {cnt:3d} messages")
        print("-" * 78)

        print("Top Domain Clusters:")
        for cl in clusters[:5]:
            act_badge = f"[{cl.recommended_action.value.upper()}]"
            print(f"  {act_badge:9s} {cl.domain:30s}: {cl.message_count:3d} msgs")
        print("-" * 78)

        print("Detailed Candidate Decisions:")
        for i, d in enumerate(decisions, 1):
            action_badge = f"[{d.action.value.upper()}]"
            prot_badge = "[PROTECTED]" if d.is_protected else ""
            print(f"[{i:02d}] {action_badge:9s} {prot_badge:11s} ID: {d.message_id}")
            print(f"     From:    {d.sender}")
            print(f"     Subject: {d.subject}")
            print(f"     Reason:  {d.reason} (rule: {d.rule_name})")
            print("-" * 78)

        # Save manifest
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest = TriageManifest(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            query=args.query,
            total_scanned=len(decisions),
            action_counts={k.value: v for k, v in action_counts.items()},
            category_counts=category_counts,
            top_clusters=[c.to_dict() for c in clusters[:10]],
        )
        manifest_path = manifest.save()

        print(f"Triage manifest saved: {manifest_path}")
        print("To generate staged execution plans, run:")
        print(f"  gmail-local triage plan --query \"{args.query}\" --limit {args.limit} --action trash")
        return 0
    except Exception as e:
        print(f"Triage scan failed with error: {e}", file=sys.stderr)
        return 1


def cmd_triage_plan(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Scan candidate messages and generate partitioned CleanupPlan artifacts."""
    try:
        if args.limit > MAX_SEARCH_BOUND:
            candidates = retriever.search_candidates_paginated(
                query=args.query,
                total_limit=args.limit,
                purpose=args.purpose,
            )
        else:
            candidates = retriever.search_messages(
                query=args.query,
                max_results=args.limit,
                purpose=args.purpose,
            )
        if not candidates:
            print(f"No messages matched triage query: '{args.query}'")
            return 0

        policy_path = getattr(args, "policy", None)
        policy = TriagePolicy.load(policy_path)
        classifier = TriageClassifier(policy=policy)
        decisions: List[TriageDecision] = []
        for c in candidates:
            decision = classifier.classify(
                message_id=c.id,
                thread_id=c.thread_id,
                sender=c.sender,
                subject=c.subject,
                date=c.date,
                labels=list(c.labels),
            )
            decisions.append(decision)

        target_action = TriageAction.TRASH if args.action == "trash" else TriageAction.ARCHIVE
        generator = TriagePlanGenerator()
        plans = generator.generate_staged_plans(
            decisions=decisions,
            action_filter=target_action,
            max_batch_size=MAX_CLEANUP_BATCH_SIZE,
            query=args.query,
        )

        if not plans:
            print(f"No candidates matched action '{args.action}' after applying triage safety rules.")
            return 0

        print("=" * 78)
        print(f"  GENERATED {len(plans)} STAGED CLEANUP PLAN(S) VIA TRIAGE ENGINE")
        print("=" * 78)
        total_targets = sum(len(p.targets) for p in plans)
        print(f"Target Action:  {target_action.value.upper()}")
        print(f"Total Targets:  {total_targets} across {len(plans)} bundle(s) (<= {MAX_CLEANUP_BATCH_SIZE} items/bundle)")
        print("-" * 78)

        for idx, plan in enumerate(plans, 1):
            print(f"Bundle [{idx}/{len(plans)}]:")
            print(f"  Fingerprint: {plan.fingerprint}")
            print(f"  Targets:     {len(plan.targets)}")
            print(f"  Plan File:   ~/.local/state/gmail-local/plans/{plan.fingerprint}.json")
            print(f"  Preview:     gmail-local cleanup preview {plan.fingerprint}")
            print(f"  Apply:       gmail-local cleanup apply --plan {plan.fingerprint} --confirm")
            print("-" * 78)

        # Save manifest
        run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        manifest = TriageManifest(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            query=args.query,
            total_scanned=len(decisions),
            action_counts={args.action: total_targets},
            category_counts={},
            top_clusters=[],
            staged_plan_fingerprints=[p.fingerprint for p in plans],
        )
        manifest.save()

        print("All plans staged safely. Execute via Manual Modify Gate when ready.")
        return 0
    except Exception as e:
        print(f"Triage plan generation failed with error: {e}", file=sys.stderr)
        return 1


def cmd_triage_clusters(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Analyze domain volume and clustering distribution for candidates."""
    try:
        if args.limit > MAX_SEARCH_BOUND:
            candidates = retriever.search_candidates_paginated(
                query=args.query,
                total_limit=args.limit,
                purpose=args.purpose,
            )
        else:
            candidates = retriever.search_messages(
                query=args.query,
                max_results=args.limit,
                purpose=args.purpose,
            )
        if not candidates:
            print(f"No messages matched query: '{args.query}'")
            return 0

        policy_path = getattr(args, "policy", None)
        policy = TriagePolicy.load(policy_path)
        classifier = TriageClassifier(policy=policy)
        scanner = TriageScanner(classifier)
        clusters = scanner.cluster_candidates(candidates)

        print("=" * 78)
        print("  INBOX SENDER DOMAIN CLUSTERS & VOLUME BREAKDOWN")
        print("=" * 78)
        print(f"Query:        {args.query}")
        print(f"Scanned:      {len(candidates)} candidates")
        print(f"Clusters:     {len(clusters)} unique sender domains")
        print("-" * 78)

        for i, cl in enumerate(clusters, 1):
            act_badge = f"[{cl.recommended_action.value.upper()}]"
            print(f"[{i:02d}] {act_badge:9s} {cl.domain:32s} Count: {cl.message_count:3d}")
            print(f"     Category: {cl.category.value}")
            print(f"     Senders:  {', '.join(cl.sender_addresses[:2])}")
            if cl.sample_subjects:
                print(f"     Samples:  \"{cl.sample_subjects[0][:60]}\"")
            print("-" * 78)

        return 0
    except Exception as e:
        print(f"Clustering analysis failed with error: {e}", file=sys.stderr)
        return 1


def cmd_triage_loop(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Execute autonomous AFK triage loop over candidate query until limit is reached."""
    if not args.confirm:
        print(
            "Manual Modify Gate: triage loop in non-interactive environment requires explicit --confirm flag.",
            file=sys.stderr,
        )
        return 1

    policy_path = getattr(args, "policy", None)
    policy = TriagePolicy.load(policy_path)
    classifier = TriageClassifier(policy=policy)
    generator = TriagePlanGenerator()
    modifier = GmailModifier()

    target_action = TriageAction.TRASH if args.action == "trash" else TriageAction.ARCHIVE
    total_processed = 0
    total_protected_skipped = 0
    iteration = 0
    max_total = args.max_total
    batch_size = min(args.batch_size, MAX_CLEANUP_BATCH_SIZE)

    print("=" * 78)
    print("  AUTONOMOUS AFK INBOX TRIAGE LOOP")
    print("=" * 78)
    print(f"Query:        {args.query}")
    print(f"Target Action:{target_action.value.upper()}")
    print(f"Max Cap:      {max_total} messages")
    print(f"Slice Size:   {batch_size} messages/batch")
    print(f"Policy:       {policy.name}")
    print("-" * 78)

    while total_processed < max_total:
        iteration += 1

        # Retrieve candidates
        candidates = retriever.search_messages(
            query=args.query,
            max_results=batch_size,
            purpose=f"{args.purpose}_iter_{iteration}",
        )
        if not candidates:
            print(f"\n[Loop] No more messages matching query '{args.query}'. Loop complete.")
            break

        # Classify candidates
        decisions: List[TriageDecision] = []
        for c in candidates:
            d = classifier.classify(
                message_id=c.id,
                thread_id=c.thread_id,
                sender=c.sender,
                subject=c.subject,
                date=c.date,
                labels=list(c.labels),
            )
            decisions.append(d)

        # Count skipped
        protected_in_batch = sum(1 for d in decisions if d.is_protected or d.action != target_action)
        total_protected_skipped += protected_in_batch

        plans = generator.generate_staged_plans(
            decisions=decisions,
            action_filter=target_action,
            max_batch_size=batch_size,
            query=args.query,
        )

        if not plans:
            print(f"\n[Iteration {iteration}] All {len(candidates)} candidates in slice are protected/kept. Halting loop to prevent spinning.")
            break

        # Bound by remaining max_total quota
        remaining = max_total - total_processed
        all_targets = [t for p in plans for t in p.targets]
        if len(all_targets) > remaining:
            all_targets = all_targets[:remaining]
            from gmail_local.modifier import CleanupPlan
            plans = [CleanupPlan(query=args.query, action_type=plans[0].action_type, targets=all_targets)]

        batch_targets = sum(len(p.targets) for p in plans)
        for p in plans:
            modifier.apply_plan(p, confirm=True, purpose=args.purpose)

        total_processed += batch_targets
        print(f"[Iteration {iteration:02d}] Applied {batch_targets:2d} {target_action.value.upper()} mutations (Cumulative: {total_processed}/{max_total})")

    print("=" * 78)
    print("  TRIAGE LOOP COMPLETED")
    print("=" * 78)
    print(f"Total Iterations:        {iteration}")
    print(f"Total Messages Processed:{total_processed}")
    print(f"Total Protected Skipped: {total_protected_skipped}")
    print("=" * 78)
    return 0


def cmd_triage_policy_show(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Displays current active triage policy configuration."""
    policy_path = getattr(args, "policy", None)
    policy = TriagePolicy.load(policy_path)
    print("=" * 78)
    print(f"  TRIAGE POLICY CONFIGURATION: {policy.name}")
    print("=" * 78)
    print(f"Whitelist Senders ({len(policy.whitelist_senders)}):")
    for s in policy.whitelist_senders or ["(none)"]:
        print(f"  + {s}")
    print(f"\nBlacklist Senders ({len(policy.blacklist_senders)}):")
    for s in policy.blacklist_senders or ["(none)"]:
        print(f"  - {s}")
    print(f"\nArchive Senders ({len(policy.archive_senders)}):")
    for s in policy.archive_senders or ["(none)"]:
        print(f"  ~ {s}")
    print(f"\nCustom Promo Keywords ({len(policy.custom_promo_keywords)}):")
    for kw in policy.custom_promo_keywords or ["(none)"]:
        print(f"  * {kw}")
    print(f"\nCustom Protect Keywords ({len(policy.custom_protect_keywords)}):")
    for kw in policy.custom_protect_keywords or ["(none)"]:
        print(f"  * {kw}")
    print("-" * 78)
    return 0


def cmd_triage_policy_init(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Initializes a starter triage_policy.json file."""
    path = getattr(args, "path", None) or DEFAULT_POLICY_FILE
    if path.exists() and not getattr(args, "force", False):
        print(f"Policy file already exists at {path}. Use --force to overwrite.", file=sys.stderr)
        return 1

    sample_policy = TriagePolicy(
        name="operator_custom_policy",
        whitelist_senders=["important.client.com", "family.org"],
        blacklist_senders=["spammybrand.com", "junkdeals.net"],
        archive_senders=["e1.theathletic.com", "apnews.com"],
        custom_promo_keywords=["special vip offer", "exclusive savings"],
        custom_protect_keywords=["mortgage", "escrow"],
    )
    saved_path = sample_policy.save(path)
    print(f"Successfully initialized starter triage policy at: {saved_path}")
    return 0


def cmd_triage(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Entrypoint for triage subcommands."""
    sub = getattr(args, "triage_subcommand", None)
    if sub == "scan":
        return cmd_triage_scan(retriever, args)
    elif sub == "plan":
        return cmd_triage_plan(retriever, args)
    elif sub == "clusters":
        return cmd_triage_clusters(retriever, args)
    elif sub == "policy":
        policy_sub = getattr(args, "policy_subcommand", None)
        if policy_sub == "show":
            return cmd_triage_policy_show(retriever, args)
        elif policy_sub == "init":
            return cmd_triage_policy_init(retriever, args)
        else:
            print("Specify a policy subcommand: show or init", file=sys.stderr)
            return 1
    else:
        print("Specify a triage subcommand: scan, plan, clusters, or policy", file=sys.stderr)
        return 1



def cmd_search(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Search messages and display bounded header-level candidate results."""
    try:
        candidates = retriever.search_messages(
            query=args.query,
            max_results=args.limit,
            purpose=args.purpose,
        )
        if not candidates:
            print(f"No messages matched query: '{args.query}'")
            return 0

        print(f"Found {len(candidates)} candidate(s) (Headers Only):")
        print("-" * 78)
        for i, c in enumerate(candidates, 1):
            print(f"[{i}] ID: {c.id}")
            print(f"    Date:    {c.date}")
            print(f"    From:    {c.sender}")
            print(f"    Subject: {c.subject}")
            print("-" * 78)
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"Search failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Search failed with error: {e}", file=sys.stderr)
        return 1


def cmd_preview(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Fetch body-derived snippets for explicitly selected candidate IDs."""
    try:
        previews = retriever.preview_candidates(
            candidate_ids=args.message_ids,
            purpose=args.purpose,
        )
        print(f"=== Candidate Previews ({len(previews)}) ===")
        for p in previews:
            print(f"ID: {p.id}")
            print(f"From: {p.sender} | Subject: {p.subject}")
            print(f"Snippet: {p.preview or '(No preview available)'}")
            print("-" * 78)
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"Preview failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Preview failed with error: {e}", file=sys.stderr)
        return 1


def cmd_read(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Retrieve full messages enforcing the 10-message & 1 MiB aggregate body limits."""
    try:
        messages = retriever.get_messages(
            message_ids=args.message_ids,
            purpose=args.purpose,
        )
        if not messages:
            print("No messages retrieved.")
            return 0

        print(f"=== Retrieved {len(messages)} Full Message(s) ===")
        for m in messages:
            print("=" * 78)
            print(f"Message ID: {m.id}")
            print(f"Date:       {m.date}")
            print(f"From:       {m.sender}")
            print(f"To:         {m.recipient}")
            print(f"Subject:    {m.subject}")
            print(f"Body Size:  {m.body_bytes} bytes")
            if m.attachments:
                print(f"Attachments ({len(m.attachments)}):")
                for att in m.attachments:
                    inline_tag = " [INLINE]" if att.is_inline else ""
                    print(f"  - {att.filename} ({att.mime_type}, {att.size_bytes}B, ID: {att.attachment_id}){inline_tag}")
            print("-" * 78)
            print(m.body_text)
            print("=" * 78)
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"Read failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Read failed with error: {e}", file=sys.stderr)
        return 1


def cmd_attachments(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """List attachment metadata for a message without downloading."""
    try:
        attachments = retriever.list_attachments(
            message_id=args.message_id,
            purpose=args.purpose,
        )
        if not attachments:
            print(f"No attachments found for message ID: {args.message_id}")
            return 0

        print(f"=== Attachments for Message {args.message_id} ({len(attachments)}) ===")
        for att in attachments:
            inline = " (Inline)" if att.is_inline else ""
            print(f"Filename:      {att.filename}{inline}")
            print(f"Attachment ID: {att.attachment_id}")
            print(f"MIME Type:     {att.mime_type}")
            print(f"Size:          {att.size_bytes} bytes")
            print("-" * 78)
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"List attachments failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"List attachments failed with error: {e}", file=sys.stderr)
        return 1


def cmd_download(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Download an attachment with atomic staging and no-overwrite verification."""
    target_path = Path(args.dest)
    try:
        selections = [(args.message_id, args.attachment_id, target_path)]
        paths = retriever.download_attachments(selections, purpose=args.purpose)
        for p in paths:
            print(f"Successfully downloaded attachment to: {p}")
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"Download failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Download failed with error: {e}", file=sys.stderr)
        return 1


def cmd_history(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Check incremental history changes since start_history_id."""
    try:
        delta = retriever.get_history(
            start_history_id=args.start_history_id,
            purpose=args.purpose,
        )
        if delta.is_expired:
            print(f"History ID '{delta.history_id}' has expired (HTTP 404). A full mailbox sync is required.")
            return 0
        print(f"=== History Delta (Since {args.start_history_id}) ===")
        print(f"Current History ID: {delta.history_id}")
        print(f"Messages Added ({len(delta.messages_added)}): {', '.join(delta.messages_added) if delta.messages_added else 'None'}")
        print(f"Messages Deleted ({len(delta.messages_deleted)}): {', '.join(delta.messages_deleted) if delta.messages_deleted else 'None'}")
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"History sync failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"History sync failed with error: {e}", file=sys.stderr)
        return 1


def cmd_thread(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """Inspect conversation thread summary mapping constituent messages."""
    try:
        summary = retriever.get_thread(
            thread_id=args.thread_id,
            purpose=args.purpose,
        )
        print(f"=== Conversation Thread: {summary.thread_id} ===")
        print(f"Subject:      {summary.subject}")
        print(f"Messages:     {summary.message_count}")
        print(f"Participants: {', '.join(summary.participants)}")
        print(f"Message IDs:  {', '.join(summary.message_ids)}")
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"Thread inspection failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Thread inspection failed with error: {e}", file=sys.stderr)
        return 1


def cmd_labels(retriever: GmailRetriever, args: argparse.Namespace) -> int:
    """List all mailbox labels (system and user) with IDs."""
    try:
        labels = retriever.list_labels(purpose=args.purpose)
        if not labels:
            print("No labels found.")
            return 0
        print(f"=== Mailbox Labels ({len(labels)}) ===")
        print(f"{'ID':<30} {'TYPE':<10} {'NAME'}")
        print("-" * 65)
        for l in labels:
            print(f"{l.id:<30} {l.type:<10} {l.name}")
        return 0
    except (RetrievalBoundError, AuthError) as e:
        print(f"List labels failed: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"List labels failed with error: {e}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(
        prog="gmail-local",
        description="Locally operated Gmail and Calendar integration with least-privilege security bounds and manual gates on every write.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available commands")

    # status
    p_status = subparsers.add_parser("status", help="Check account and Keychain token status")
    p_status.set_defaults(func=cmd_status)

    # login
    p_login = subparsers.add_parser("login", help="Run interactive OAuth2 login in browser")
    p_login.add_argument("--no-browser", action="store_true", help="Do not automatically launch system browser")
    p_login.set_defaults(func=cmd_login)

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke authorization and clear Keychain entry")
    p_revoke.set_defaults(func=cmd_revoke)

    # compose-status
    p_comp_status = subparsers.add_parser("compose-status", help="Check Transmission Grant status")
    p_comp_status.add_argument("--client-secret", type=Path, default=None, help="Path to transmission client secret JSON")
    p_comp_status.set_defaults(func=cmd_compose_status)

    # compose-login
    p_comp_login = subparsers.add_parser("compose-login", help="Run interactive OAuth2 login for transmission (gmail.compose)")
    p_comp_login.add_argument("--client-secret", type=Path, default=None, help="Path to transmission client secret JSON")
    p_comp_login.add_argument("--no-browser", action="store_true", help="Do not automatically launch system browser")
    p_comp_login.set_defaults(func=cmd_compose_login)

    # compose-revoke
    p_comp_revoke = subparsers.add_parser("compose-revoke", help="Revoke transmission authorization and clear Keychain entry")
    p_comp_revoke.set_defaults(func=cmd_compose_revoke)

    # modify-status
    p_mod_status = subparsers.add_parser("modify-status", help="Check Modification Grant status")
    p_mod_status.add_argument("--client-secret", type=Path, default=None, help="Path to modification client secret JSON")
    p_mod_status.set_defaults(func=cmd_modify_status)

    # modify-login
    p_mod_login = subparsers.add_parser("modify-login", help="Run interactive OAuth2 login for modification (gmail.modify)")
    p_mod_login.add_argument("--client-secret", type=Path, default=None, help="Path to modification client secret JSON")
    p_mod_login.add_argument("--no-browser", action="store_true", help="Do not automatically launch system browser")
    p_mod_login.set_defaults(func=cmd_modify_login)

    # modify-revoke
    p_mod_revoke = subparsers.add_parser("modify-revoke", help="Revoke modification authorization and clear Keychain entry")
    p_mod_revoke.set_defaults(func=cmd_modify_revoke)

    # calendar-status
    p_cal_status = subparsers.add_parser("calendar-status", help="Check Calendar Grant status")
    p_cal_status.add_argument("--client-secret", type=Path, default=None, help="Path to calendar client secret JSON")
    p_cal_status.set_defaults(func=cmd_calendar_status)

    # calendar-login
    p_cal_login = subparsers.add_parser("calendar-login", help="Run interactive OAuth2 login for Calendar (calendar.events.owned)")
    p_cal_login.add_argument("--client-secret", type=Path, default=None, help="Path to calendar client secret JSON")
    p_cal_login.add_argument("--no-browser", action="store_true", help="Do not automatically launch system browser")
    p_cal_login.set_defaults(func=cmd_calendar_login)

    # calendar-revoke
    p_cal_revoke = subparsers.add_parser("calendar-revoke", help="Revoke calendar authorization and clear Keychain entry")
    p_cal_revoke.set_defaults(func=cmd_calendar_revoke)

    # calendar-event
    p_cal_event = subparsers.add_parser("calendar-event", help="Preview or create Google Calendar events with Google Meet")
    p_cal_event_sub = p_cal_event.add_subparsers(dest="calendar_event_subcommand")

    for sub_name, sub_help, sub_func in [
        ("preview", "Preview a Calendar event and generate dry-run handoff", cmd_calendar_event_preview),
        ("create", "Create a Calendar event on primary calendar under Manual Action Gate", cmd_calendar_event_create),
    ]:
        p_sub = p_cal_event_sub.add_parser(sub_name, help=sub_help)
        p_sub.add_argument("--summary", required=True, help="Title or summary of the event")
        p_sub.add_argument("--start", required=True, help="Start time in ISO 8601 format (e.g. 2026-09-22T10:00:00-07:00)")
        p_sub.add_argument("--end", required=True, help="End time in ISO 8601 format (e.g. 2026-09-22T10:35:00-07:00)")
        p_sub.add_argument("--timezone", required=True, help="IANA timezone (e.g. America/Los_Angeles)")
        p_sub.add_argument("--description", default=None, help="Optional event description")
        p_sub.add_argument("--attendee", action="append", default=[], dest="attendees", help="Attendee email address (max 10)")
        p_sub.add_argument("--meet", action="store_true", default=False, help="Enable Google Meet conference generation")
        p_sub.add_argument("--send-updates", choices=["none", "externalOnly", "all"], default="none", help="Send email notifications")
        if sub_name == "create":
            p_sub.add_argument("--confirm", action="store_true", default=False, help="Explicit human confirmation for non-interactive execution")
        p_sub.add_argument("--purpose", default=f"calendar_event_{sub_name}", help="Operator-stated purpose for audit log")
        p_sub.set_defaults(func=sub_func)
    p_cal_event.set_defaults(func=cmd_calendar_event)

    # cleanup
    p_cleanup = subparsers.add_parser("cleanup", help="Staged mailbox modification and cleanup")
    p_cleanup_sub = p_cleanup.add_subparsers(dest="cleanup_subcommand")

    p_cl_plan = p_cleanup_sub.add_parser("plan", help="Generate a staged cleanup plan")
    p_cl_plan.add_argument("--query", required=True, help="Gmail search query for targets")
    p_cl_plan.add_argument(
        "--action",
        required=True,
        choices=["trash", "archive", "mark_read", "add_label", "remove_label"],
        help="Action to perform",
    )
    p_cl_plan.add_argument("--add-label", nargs="*", default=[], help="Labels to apply")
    p_cl_plan.add_argument("--remove-label", nargs="*", default=[], help="Labels to remove")
    p_cl_plan.add_argument("--limit", type=int, default=10, help=f"Max candidate messages (1-{MAX_CLEANUP_BATCH_SIZE})")
    p_cl_plan.add_argument("--purpose", default="cleanup_plan", help="Operator-stated purpose for audit log")
    p_cl_plan.set_defaults(func=cmd_cleanup_plan)

    p_cl_prev = p_cleanup_sub.add_parser("preview", help="Preview targets in a staged cleanup plan")
    p_cl_prev.add_argument("plan", help="Fingerprint or path of the plan")
    p_cl_prev.set_defaults(func=cmd_cleanup_preview)

    p_cl_apply = p_cleanup_sub.add_parser("apply", help="Execute a staged cleanup plan under Manual Modify Gate")
    p_cl_apply.add_argument("--plan", required=True, help="Fingerprint or path of the plan")
    p_cl_apply.add_argument("--confirm", action="store_true", help="Explicit human confirmation for non-interactive execution")
    p_cl_apply.add_argument("--purpose", default="cleanup_apply", help="Operator-stated purpose for audit log")
    p_cl_apply.set_defaults(func=cmd_cleanup_apply)

    p_cl_untrash = p_cleanup_sub.add_parser("untrash", help="Restore a message from Gmail Trash")
    p_cl_untrash.add_argument("message_id", help="Message ID to restore")
    p_cl_untrash.add_argument("--purpose", default="cleanup_untrash", help="Operator-stated purpose for audit log")
    p_cl_untrash.set_defaults(func=cmd_cleanup_untrash)

    p_cleanup.set_defaults(func=cmd_cleanup)

    # triage
    p_triage = subparsers.add_parser("triage", help="Autonomous AFK inbox triage and staged classification")
    p_triage_sub = p_triage.add_subparsers(dest="triage_subcommand")

    p_tr_scan = p_triage_sub.add_parser("scan", help="Scan candidates and display categorized triage breakdown")
    p_tr_scan.add_argument("--query", default="in:inbox", help="Search query (default: in:inbox)")
    p_tr_scan.add_argument("--limit", type=int, default=75, help="Candidates to inspect (1-500)")
    p_tr_scan.add_argument("--policy", type=Path, default=None, help="Path to custom triage policy JSON")
    p_tr_scan.add_argument("--purpose", default="triage_scan", help="Operator-stated purpose for audit log")
    p_tr_scan.set_defaults(func=cmd_triage_scan)

    p_tr_plan = p_triage_sub.add_parser("plan", help="Scan candidates and generate partitioned CleanupPlan artifacts")
    p_tr_plan.add_argument("--query", default="in:inbox", help="Search query (default: in:inbox)")
    p_tr_plan.add_argument("--limit", type=int, default=MAX_CLEANUP_BATCH_SIZE, help="Candidates to inspect (1-500)")
    p_tr_plan.add_argument("--action", choices=["trash", "archive"], default="trash", help="Target action to stage into plans")
    p_tr_plan.add_argument("--policy", type=Path, default=None, help="Path to custom triage policy JSON")
    p_tr_plan.add_argument("--purpose", default="triage_plan", help="Operator-stated purpose for audit log")
    p_tr_plan.set_defaults(func=cmd_triage_plan)

    p_tr_clusters = p_triage_sub.add_parser("clusters", help="Analyze domain volume and clustering distribution")
    p_tr_clusters.add_argument("--query", default="in:inbox", help="Search query (default: in:inbox)")
    p_tr_clusters.add_argument("--limit", type=int, default=150, help="Candidates to inspect (1-500)")
    p_tr_clusters.add_argument("--policy", type=Path, default=None, help="Path to custom triage policy JSON")
    p_tr_clusters.add_argument("--purpose", default="triage_clusters", help="Operator-stated purpose for audit log")
    p_tr_clusters.set_defaults(func=cmd_triage_clusters)

    p_tr_loop = p_triage_sub.add_parser("loop", help="Autonomous loop executing staged triage batches up to a target cap")
    p_tr_loop.add_argument("--query", default="category:promotions", help="Search query (default: category:promotions)")
    p_tr_loop.add_argument("--max-total", type=int, default=500, help="Maximum total messages to process (1-2000)")
    p_tr_loop.add_argument("--batch-size", type=int, default=MAX_CLEANUP_BATCH_SIZE, help=f"Slice size per iteration (1-{MAX_CLEANUP_BATCH_SIZE})")
    p_tr_loop.add_argument("--action", choices=["trash", "archive"], default="trash", help="Target action to stage and apply")
    p_tr_loop.add_argument("--policy", type=Path, default=None, help="Path to custom triage policy JSON")
    p_tr_loop.add_argument("--confirm", action="store_true", help="Explicit human confirmation for autonomous loop execution")
    p_tr_loop.add_argument("--purpose", default="triage_loop", help="Operator-stated purpose for audit log")
    p_tr_loop.set_defaults(func=cmd_triage_loop)

    p_tr_policy = p_triage_sub.add_parser("policy", help="Inspect or initialize triage policy configuration")
    p_tr_policy_sub = p_tr_policy.add_subparsers(dest="policy_subcommand")

    p_pol_show = p_tr_policy_sub.add_parser("show", help="Display active policy configuration")
    p_pol_show.add_argument("--policy", type=Path, default=None, help="Path to custom triage policy JSON")
    p_pol_show.set_defaults(func=cmd_triage_policy_show)

    p_pol_init = p_tr_policy_sub.add_parser("init", help="Create starter triage_policy.json file")
    p_pol_init.add_argument("--path", type=Path, default=None, help="Destination path (default: ~/.config/gmail-local/triage_policy.json)")
    p_pol_init.add_argument("--force", action="store_true", help="Overwrite existing policy file")
    p_pol_init.set_defaults(func=cmd_triage_policy_init)

    p_triage.set_defaults(func=cmd_triage)

    # draft
    p_draft = subparsers.add_parser("draft", help="Compose a FrozenDraft and optionally stage to Gmail Drafts")
    p_draft.add_argument("--to", nargs="+", required=True, help="One or more destination email addresses")
    p_draft.add_argument("--subject", required=True, help="Email subject line")
    p_draft.add_argument("--body", help="Email body plain text")
    p_draft.add_argument("--body-file", help="Path to plain text file containing body")
    p_draft.add_argument("--cc", nargs="*", default=[], help="Cc email addresses")
    p_draft.add_argument("--bcc", nargs="*", default=[], help="Bcc email addresses")
    p_draft.add_argument("--html", help="HTML alternative body text")
    p_draft.add_argument("--html-file", help="Path to HTML file containing body")
    p_draft.add_argument("--attach", nargs="*", default=[], help="Local file paths to attach")
    p_draft.add_argument(
        "--attach-mode",
        choices=["auto", "snapshot", "compatibility", "invitation"],
        default="auto",
        help="Attachment presentation mode (default: auto; for .ics: snapshot=text/calendar, compatibility=application/octet-stream, invitation=method=REQUEST)",
    )
    p_draft.add_argument("--thread-id", help="Gmail thread ID for a guaranteed threaded reply")
    p_draft.add_argument("--in-reply-to", help="Message-ID this draft replies to")
    p_draft.add_argument("--references", nargs="*", default=[], help="Message-ID reference chain")
    p_draft.add_argument(
        "--reply-to-message-id",
        help="Selected Gmail message ID; securely resolves all required thread headers",
    )
    p_draft.add_argument("--local-only", action="store_true", help="Generate local FrozenDraft without pushing to Gmail")
    p_draft.add_argument("--purpose", default="compose_draft", help="Operator-stated purpose for audit log")
    p_draft.set_defaults(func=cmd_draft)

    # drafts
    p_drafts = subparsers.add_parser("drafts", help="Inspect Gmail drafts")
    p_drafts_sub = p_drafts.add_subparsers(dest="drafts_subcommand")

    p_dl_list = p_drafts_sub.add_parser("list", help="List drafts in Gmail mailbox")
    p_dl_list.add_argument("--limit", type=int, default=10, help="Max drafts to list (1-75)")
    p_dl_list.add_argument("--purpose", default="list_drafts", help="Operator-stated purpose for audit log")

    p_dl_get = p_drafts_sub.add_parser("get", help="Get draft details by ID")
    p_dl_get.add_argument("draft_id", help="Gmail Draft ID")
    p_dl_get.add_argument("--purpose", default="get_draft", help="Operator-stated purpose for audit log")
    p_drafts.set_defaults(func=cmd_drafts)

    # send
    p_send = subparsers.add_parser("send", help="Guarded manual transmission of a FrozenDraft")
    p_send.add_argument("--draft", required=True, help="Fingerprint, draft ID, or local JSON path")
    p_send.add_argument("--confirm", action="store_true", help="Explicit human confirmation for non-interactive execution")
    p_send.add_argument("--purpose", default="user_transmission", help="Operator-stated purpose for audit log")
    p_send.set_defaults(func=cmd_send)

    # search
    p_search = subparsers.add_parser("search", help="Bounded header search for messages")
    p_search.add_argument("query", help="Gmail search query (e.g. 'from:court is:unread')")
    p_search.add_argument("--limit", type=int, default=DEFAULT_SEARCH_BOUND, help="Max candidates (1-75)")
    p_search.add_argument("--purpose", default="search", help="Operator-stated purpose for audit log")
    p_search.set_defaults(func=cmd_search)

    # preview
    p_preview = subparsers.add_parser("preview", help="Preview short body snippets for candidate IDs")
    p_preview.add_argument("message_ids", nargs="+", help="One or more candidate message IDs")
    p_preview.add_argument("--purpose", default="preview", help="Operator-stated purpose for audit log")
    p_preview.set_defaults(func=cmd_preview)

    # read
    p_read = subparsers.add_parser("read", help="Read full messages (max 10 msgs, 1 MiB aggregate body)")
    p_read.add_argument("message_ids", nargs="+", help="One or more selected message IDs")
    p_read.add_argument("--purpose", default="read", help="Operator-stated purpose for audit log")
    p_read.set_defaults(func=cmd_read)

    # attachments
    p_att = subparsers.add_parser("attachments", help="List attachments for a message without downloading")
    p_att.add_argument("message_id", help="Message ID")
    p_att.add_argument("--purpose", default="list_attachments", help="Operator-stated purpose for audit log")
    p_att.set_defaults(func=cmd_attachments)

    # download
    p_dl = subparsers.add_parser("download", help="Download a selected attachment to an explicit path")
    p_dl.add_argument("message_id", help="Message ID")
    p_dl.add_argument("attachment_id", help="Attachment ID from 'attachments' command")
    p_dl.add_argument("--dest", required=True, help="Destination file path (will fail if exists)")
    p_dl.add_argument("--purpose", default="download", help="Operator-stated purpose for audit log")
    p_dl.set_defaults(func=cmd_download)

    # history
    p_hist = subparsers.add_parser("history", help="Incremental mailbox sync since start_history_id")
    p_hist.add_argument("start_history_id", help="History ID checkpoint to check changes from")
    p_hist.add_argument("--purpose", default="sync", help="Operator-stated purpose for audit log")
    p_hist.set_defaults(func=cmd_history)

    # thread
    p_thread = subparsers.add_parser("thread", help="Inspect conversation thread participants and message IDs")
    p_thread.add_argument("thread_id", help="Thread ID")
    p_thread.add_argument("--purpose", default="thread", help="Operator-stated purpose for audit log")
    p_thread.set_defaults(func=cmd_thread)

    # labels
    p_labels = subparsers.add_parser("labels", help="List mailbox labels (INBOX, UNREAD, user categories)")
    p_labels.add_argument("--purpose", default="list_labels", help="Operator-stated purpose for audit log")
    p_labels.set_defaults(func=cmd_labels)

    return parser


def main(argv: List[str] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.subcommand:
        parser.print_help()
        return 0

    retriever = GmailRetriever()
    return args.func(retriever, args)


if __name__ == "__main__":
    sys.exit(main())
