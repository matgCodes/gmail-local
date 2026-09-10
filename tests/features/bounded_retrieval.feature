Feature: Bounded Read-Only Gmail Retrieval Workflow
  As an AI agent operator
  I want to search, preview, read, and download Gmail messages within strict least-privilege bounds
  So that I never leak private credentials, exceed rate limits, or overwrite local files.

  @acceptance
  Scenario: Search messages within bounds
    Given a configured Gmail retriever with valid credentials
    When the operator searches for "from:court is:unread" with limit 5
    Then the search returns up to 5 candidate messages
    And each candidate contains an ID, thread ID, sender, and subject
    And no full body content is returned in the search results

  @acceptance
  Scenario: Operator attempts search exceeding maximum bound
    Given a configured Gmail retriever with valid credentials
    When the operator attempts to search with limit 100
    Then the retriever rejects the request with a boundary error
    And the error mentions the maximum limit of 75

  @acceptance
  Scenario: Read selected messages within 10-message bound
    Given a configured Gmail retriever with valid credentials
    When the operator reads 3 selected message IDs
    Then all 3 full messages are returned
    And each message contains sanitized plain text body
    And an audit log entry is recorded for the read operation

  @acceptance
  Scenario: Operator attempts to read more than 10 messages
    Given a configured Gmail retriever with valid credentials
    When the operator attempts to read 11 message IDs
    Then the retriever rejects the request with a boundary error
    And the error mentions the 10 message limit

  @acceptance
  Scenario: Atomic attachment download with no-overwrite protection
    Given a configured Gmail retriever with an existing attachment of 1024 bytes
    When the operator downloads the attachment to a new destination path
    Then the file is created with exact content
    And if the operator attempts to download again to the same destination
    Then the download is rejected with an overwrite error
    And the original file remains untouched
