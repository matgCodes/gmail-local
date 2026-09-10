"""Tests for MIME utilities: RFC 2047 decoding, filename sanitization, and HTML extraction."""

import pytest

from gmail_local.mime_utils import (
    decode_rfc2047_header,
    html_to_plain_text,
    sanitize_filename,
)


class TestDecodeRFC2047Header:
    def test_empty_or_none(self):
        assert decode_rfc2047_header(None) == ""
        assert decode_rfc2047_header("") == ""
        assert decode_rfc2047_header("   ") == ""

    def test_plain_ascii(self):
        assert decode_rfc2047_header("Simple subject line") == "Simple subject line"

    def test_utf8_base64(self):
        # "Hello World" in UTF-8 Base64: =?UTF-8?B?SGVsbG8gV29ybGQ=?=
        encoded = "=?UTF-8?B?SGVsbG8gV29ybGQ=?="
        assert decode_rfc2047_header(encoded) == "Hello World"

    def test_utf8_quoted_printable(self):
        # "Café" in UTF-8 Quoted-Printable: =?UTF-8?Q?Caf=C3=A9?=
        encoded = "=?UTF-8?Q?Caf=C3=A9?="
        assert decode_rfc2047_header(encoded) == "Café"

    def test_iso8859_1_quoted_printable(self):
        # "Café" in ISO-8859-1 QP: =?ISO-8859-1?Q?Caf=E9?=
        encoded = "=?ISO-8859-1?Q?Caf=E9?="
        assert decode_rfc2047_header(encoded) == "Café"

    def test_multiple_chunks_with_whitespace(self):
        # Two encoded words separated by whitespace per RFC 2047
        encoded = "=?UTF-8?B?U3ViamVjdA==?= =?UTF-8?B?IFRlc3Q=?="
        assert decode_rfc2047_header(encoded) == "Subject Test"

    def test_malformed_header_graceful_fallback(self):
        malformed = "=?INVALID?B?not_valid_base64@@@?="
        result = decode_rfc2047_header(malformed)
        assert isinstance(result, str)
        assert len(result) > 0


class TestSanitizeFilename:
    def test_empty_or_none(self):
        assert sanitize_filename(None) == "attachment.bin"
        assert sanitize_filename("") == "attachment.bin"
        assert sanitize_filename("   ") == "attachment.bin"
        assert sanitize_filename(None, fallback_prefix="file") == "file.bin"

    def test_legitimate_filename(self):
        assert sanitize_filename("report_2026.pdf") == "report_2026.pdf"
        assert sanitize_filename("scan.png") == "scan.png"

    def test_path_traversal_unix(self):
        assert sanitize_filename("../../../etc/passwd") == "passwd"
        assert sanitize_filename("dir/subdir/file.txt") == "file.txt"

    def test_path_traversal_windows(self):
        assert sanitize_filename("..\\..\\Windows\\System32\\cmd.exe") == "cmd.exe"
        assert sanitize_filename("C:\\Users\\admin\\secret.key") == "secret.key"

    def test_forbidden_characters_replaced(self):
        assert sanitize_filename('file:name*with?bad"chars<>.pdf') == "file_name_with_bad_chars__.pdf"

    def test_hidden_file_prevention(self):
        assert sanitize_filename(".bashrc") == "bashrc"
        assert sanitize_filename("...hidden.txt") == "hidden.txt"

    def test_rfc2047_in_filename(self):
        # =?UTF-8?B?dGVzdF9maWxlLnBkZg==?= -> test_file.pdf
        encoded = "=?UTF-8?B?dGVzdF9maWxlLnBkZg==?="
        assert sanitize_filename(encoded) == "test_file.pdf"


class TestHtmlToPlainText:
    def test_empty_or_none(self):
        assert html_to_plain_text("") == ""
        assert html_to_plain_text(None) == ""

    def test_script_and_style_stripping(self):
        html_input = """
        <html>
            <head>
                <style>body { font-size: 12px; } .hidden { display: none; }</style>
                <script>alert("malicious script!");</script>
            </head>
            <body>
                <p>Visible content here.</p>
            </body>
        </html>
        """
        output = html_to_plain_text(html_input)
        assert "font-size" not in output
        assert "malicious" not in output
        assert "Visible content here." in output

    def test_paragraphs_and_breaks(self):
        html_input = "<p>First paragraph.</p><br><p>Second paragraph.</p>"
        output = html_to_plain_text(html_input)
        assert "First paragraph." in output
        assert "Second paragraph." in output
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        assert len(lines) == 2

    def test_links_formatting(self):
        html_input = '<p>Visit <a href="https://example.com/info">Our Website</a> for details.</p>'
        output = html_to_plain_text(html_input)
        assert "Visit Our Website (https://example.com/info) for details." in output

    def test_entity_unescaping(self):
        html_input = "<p>Barnes &amp; Noble &mdash; 25% off &nbsp; pre-orders &#39;now&#39;.</p>"
        output = html_to_plain_text(html_input)
        assert "Barnes & Noble — 25% off pre-orders 'now'." in output

    def test_broken_html_resilience(self):
        broken = "<div><p>Unclosed paragraph <b>bold without end"
        output = html_to_plain_text(broken)
        assert "Unclosed paragraph bold without end" in output
