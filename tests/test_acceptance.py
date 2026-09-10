"""Acceptance tests using pytest-bdd scenarios.

Verifies end-to-end user-visible retrieval behaviors and boundary enforcement
specified in tests/features/bounded_retrieval.feature.
"""

import base64
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from pytest_bdd import given, parsers, scenarios, then, when

from gmail_local.audit import AuditLogger
from gmail_local.retrieval import (
    GmailRetriever,
    OverwriteError,
    RetrievalBoundError,
)

# Load all scenarios from the feature file
scenarios("features/bounded_retrieval.feature")


@pytest.fixture
def context(tmp_path: Path):
    """Holds test execution context across scenario steps."""
    audit_file = tmp_path / "acceptance_audit.log"
    audit_logger = AuditLogger(log_path=audit_file)

    mock_auth = MagicMock()
    mock_auth.is_authenticated.return_value = True
    mock_auth.get_status.return_value = {
        "account": "user@example.com",
        "keychain_service": "gmail-local-retrieval",
        "has_client_secret": True,
        "has_keychain_token": True,
        "is_valid": True,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
    }

    mock_service = MagicMock()

    retriever = GmailRetriever(
        auth_manager=mock_auth,
        audit_logger=audit_logger,
        service=mock_service,
    )

    return {
        "tmp_path": tmp_path,
        "audit_file": audit_file,
        "audit_logger": audit_logger,
        "retriever": retriever,
        "service": mock_service,
        "results": None,
        "error": None,
        "target_file": None,
        "attachment_data": None,
    }


# ==========================================
# GIVEN steps
# ==========================================

@given("a configured Gmail retriever with valid credentials")
def setup_retriever(context):
    pass


@given("a configured Gmail retriever with an existing attachment of 1024 bytes")
def setup_retriever_with_attachment(context):
    att_data = b"X" * 1024
    context["attachment_data"] = att_data
    b64_data = base64.urlsafe_b64encode(att_data).decode("ascii")

    # Mock attachment get response
    mock_get = MagicMock()
    mock_get.execute.return_value = {"data": b64_data}
    context["service"].users().messages().attachments().get.return_value = mock_get


# ==========================================
# WHEN steps
# ==========================================

@when(parsers.parse('the operator searches for "{query}" with limit {limit:d}'))
def operator_searches(context, query: str, limit: int):
    # Mock message list response
    msg_ids = [{"id": f"msg_{i}", "threadId": f"th_{i}"} for i in range(min(limit, 5))]
    mock_list = MagicMock()
    mock_list.execute.return_value = {"messages": msg_ids}
    context["service"].users().messages().list.return_value = mock_list

    # Mock candidate get responses
    def mock_get_msg(**kwargs):
        mid = kwargs.get("id", "msg_0")
        mock_req = MagicMock()
        mock_req.execute.return_value = {
            "id": mid,
            "threadId": f"th_{mid}",
            "snippet": f"Court filing snippet for {mid}",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": f"Notice of Hearing {mid}"},
                    {"name": "From", "value": "court@ca.gov"},
                    {"name": "Date", "value": "2026-09-10"},
                ]
            },
        }
        return mock_req

    context["service"].users().messages().get.side_effect = mock_get_msg

    context["results"] = context["retriever"].search_messages(query=query, max_results=limit)


@when(parsers.parse("the operator attempts to search with limit {limit:d}"))
def operator_attempts_invalid_search(context, limit: int):
    try:
        context["retriever"].search_messages(query="test", max_results=limit)
    except RetrievalBoundError as e:
        context["error"] = e


@when(parsers.parse("the operator reads {count:d} selected message IDs"))
def operator_reads_messages(context, count: int):
    mids = [f"read_msg_{i}" for i in range(count)]

    def mock_get_full(**kwargs):
        mid = kwargs.get("id", "read_msg_0")
        mock_req = MagicMock()
        mock_req.execute.return_value = {
            "id": mid,
            "threadId": f"th_{mid}",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": f"Detailed Order {mid}"},
                    {"name": "From", "value": "clerk@court.gov"},
                    {"name": "Date", "value": "2026-09-10"},
                ],
                "mimeType": "text/plain",
                "body": {"data": base64.urlsafe_b64encode(f"Body of {mid}".encode("utf-8")).decode("ascii")},
            },
        }
        return mock_req

    context["service"].users().messages().get.side_effect = mock_get_full
    context["results"] = context["retriever"].get_messages(mids)


@when(parsers.parse("the operator attempts to read {count:d} message IDs"))
def operator_attempts_invalid_read(context, count: int):
    mids = [f"msg_{i}" for i in range(count)]
    try:
        context["retriever"].get_messages(mids)
    except RetrievalBoundError as e:
        context["error"] = e


@when("the operator downloads the attachment to a new destination path")
def operator_downloads_attachment(context):
    target = context["tmp_path"] / "downloaded_order.pdf"
    context["target_file"] = target
    context["retriever"].download_attachments([("msg_1", "att_1", target)])


# ==========================================
# THEN steps
# ==========================================

@then(parsers.parse("the search returns up to {expected_count:d} candidate messages"))
def check_search_results(context, expected_count: int):
    assert len(context["results"]) <= expected_count
    assert len(context["results"]) > 0


@then("each candidate contains an ID, thread ID, sender, and subject")
def check_candidate_fields(context):
    for candidate in context["results"]:
        assert candidate.id.startswith("msg_")
        assert candidate.thread_id.startswith("th_")
        assert candidate.sender == "court@ca.gov"
        assert "Notice of Hearing" in candidate.subject


@then("no full body content is returned in the search results")
def check_no_body_in_candidates(context):
    for candidate in context["results"]:
        assert not hasattr(candidate, "body_text")
        assert not hasattr(candidate, "body_html")


@then("the retriever rejects the request with a boundary error")
def check_boundary_error_occurred(context):
    assert context["error"] is not None
    assert isinstance(context["error"], RetrievalBoundError)


@then(parsers.parse("the error mentions the maximum limit of {limit:d}"))
def check_search_error_message(context, limit: int):
    assert str(limit) in str(context["error"])


@then(parsers.parse("the error mentions the {limit:d} message limit"))
def check_read_error_message(context, limit: int):
    assert str(limit) in str(context["error"])


@then(parsers.parse("all {count:d} full messages are returned"))
def check_read_count(context, count: int):
    assert len(context["results"]) == count


@then("each message contains sanitized plain text body")
def check_message_plain_body(context):
    for msg in context["results"]:
        assert len(msg.body_text) > 0
        assert msg.body_text.startswith("Body of")


@then("an audit log entry is recorded for the read operation")
def check_audit_log_recorded(context):
    content = context["audit_file"].read_text(encoding="utf-8")
    assert "op=get_messages" in content


@then("the file is created with exact content")
def check_file_created(context):
    target = context["target_file"]
    assert target.exists()
    assert target.read_bytes() == context["attachment_data"]


@then("if the operator attempts to download again to the same destination")
def attempt_second_download_to_same_dest(context):
    target = context["target_file"]
    try:
        context["retriever"].download_attachments([("msg_1", "att_1", target)])
        pytest.fail("Expected OverwriteError but download succeeded")
    except OverwriteError as e:
        context["error"] = e


@then("the download is rejected with an overwrite error")
def check_overwrite_rejected(context):
    assert isinstance(context["error"], OverwriteError)
    assert "already exists" in str(context["error"])


@then("the original file remains untouched")
def check_original_file_untouched(context):
    target = context["target_file"]
    assert target.read_bytes() == context["attachment_data"]
