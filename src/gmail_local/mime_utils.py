"""Robust MIME parsing, RFC 2047 header decoding, and HTML text extraction."""

import html
import re
from email.header import decode_header, make_header
from html.parser import HTMLParser
from typing import List, Optional


def decode_rfc2047_header(value: Optional[str]) -> str:
    """Decodes RFC 2047 encoded-word headers (e.g., =?UTF-8?B?...?=) to clean UTF-8 text."""
    if not value:
        return ""
    try:
        decoded_chunks = decode_header(value)
        # Reconstruct header into unicode string
        return str(make_header(decoded_chunks)).strip()
    except Exception:
        # Fallback to original string if decoding fails
        return value.strip()


def sanitize_filename(filename: Optional[str], fallback_prefix: str = "attachment") -> str:
    """Sanitizes an untrusted attachment filename preventing path traversal and illegal characters."""
    if not filename:
        return f"{fallback_prefix}.bin"

    # Decode any RFC 2047 encoding in filename
    cleaned = decode_rfc2047_header(filename)

    # Strip directory path separators
    cleaned = cleaned.replace("\\", "/").split("/")[-1]

    # Replace illegal filesystem characters
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", cleaned)

    # Strip leading dots and spaces to prevent unintended hidden files
    cleaned = cleaned.lstrip(". ").rstrip(" ")

    if not cleaned:
        return f"{fallback_prefix}.bin"

    return cleaned


def extract_header_map(payload: Optional[dict]) -> dict:
    """Extracts lowercase header name mapping from Gmail payload."""
    if not payload:
        return {}
    return {
        h["name"].lower(): h["value"]
        for h in payload.get("headers", [])
        if isinstance(h, dict) and "name" in h and "value" in h
    }


class _TextExtractingParser(HTMLParser):
    """HTML parser that strips scripts/styles, formats structural whitespace, and unescapes entities."""

    BLOCK_TAGS = {
        "p", "div", "h1", "h2", "h3", "h4", "h5", "h6",
        "li", "tr", "section", "article", "blockquote",
    }
    IGNORE_TAGS = {"script", "style", "head", "meta", "noscript", "svg"}

    def __init__(self):
        super().__init__()
        self._ignore_depth = 0
        self._pieces: List[str] = []
        self._current_href: Optional[str] = None
        self._link_text: List[str] = []

    def handle_starttag(self, tag: str, attrs):
        tag_lower = tag.lower()
        if tag_lower in self.IGNORE_TAGS:
            self._ignore_depth += 1
            return

        if self._ignore_depth > 0:
            return

        if tag_lower in self.BLOCK_TAGS or tag_lower == "br":
            self._pieces.append("\n")
        elif tag_lower == "a":
            # Extract href attribute
            attr_dict = dict(attrs)
            href = attr_dict.get("href")
            if href and href.startswith(("http://", "https://", "mailto:")):
                self._current_href = href
                self._link_text = []

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower in self.IGNORE_TAGS:
            if self._ignore_depth > 0:
                self._ignore_depth -= 1
            return

        if self._ignore_depth > 0:
            return

        if tag_lower in self.BLOCK_TAGS:
            self._pieces.append("\n")
        elif tag_lower == "a" and self._current_href:
            link_str = "".join(self._link_text).strip()
            if link_str:
                self._pieces.append(f" ({self._current_href})")
            self._current_href = None
            self._link_text = []

    def handle_data(self, data: str):
        if self._ignore_depth == 0 and data:
            self._pieces.append(data)
            if self._current_href is not None:
                self._link_text.append(data)

    def get_text(self) -> str:
        raw_text = "".join(self._pieces)
        # Unescape HTML entities (&nbsp;, &mdash;, &amp;, etc.)
        unescaped = html.unescape(raw_text).replace("\xa0", " ")

        # Normalize linebreaks and whitespace
        lines = [re.sub(r"[ \t]+", " ", line).strip() for line in unescaped.splitlines()]
        # Collapse multiple empty lines into at most two newlines
        compact_lines: List[str] = []
        for line in lines:
            if line:
                compact_lines.append(line)
            elif compact_lines and compact_lines[-1] != "":
                compact_lines.append("")

        return "\n".join(compact_lines).strip()


def html_to_plain_text(html_content: str) -> str:
    """Converts HTML email body to clean, structured, readable plain text."""
    if not html_content:
        return ""
    parser = _TextExtractingParser()
    try:
        parser.feed(html_content)
        parser.close()
        return parser.get_text()
    except Exception:
        # Fallback simple strip if HTML is heavily broken
        cleaned = re.sub(r"<[^>]+>", " ", html_content)
        return html.unescape(re.sub(r"\s+", " ", cleaned)).strip()
