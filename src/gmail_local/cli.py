"""Command-line interface for gmail-local."""

import argparse
import sys
from pathlib import Path
from typing import List

from gmail_local.auth import AuthError, AuthManager
from gmail_local.config import DEFAULT_SEARCH_BOUND
from gmail_local.retrieval import GmailRetriever, RetrievalBoundError


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
        description="Locally operated, read-only Gmail integration with least-privilege security bounds.",
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
