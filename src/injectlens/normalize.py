"""Normalization pipeline for injectlens.

Each stage is a pure function so it can be unit-tested in isolation:

  a. decode_entities        - HTML entity decoding (&amp;, &#105; ...).
  b. find_base64_blobs      - detect base64 blobs (>= 24 chars, valid
                              charset, correct padding) and decode them
                              for side-channel analysis.
  c. decode_unicode_tags    - Unicode tag characters U+E0000-U+E007F map
                              to ASCII (U+E0041 -> 'A'); find_zero_width
                              and find_bidi_controls flag invisible
                              characters used to hide or segment text.

No stage performs I/O or network access.
"""

from __future__ import annotations

import base64
import binascii
import html
import re
from dataclasses import dataclass, field
from typing import List, Tuple

# --- character classes -----------------------------------------------------

ZERO_WIDTH_CHARS = frozenset(
    {
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x2060,  # WORD JOINER
        0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BOM
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
    }
)

BIDI_CONTROL_CHARS = frozenset(
    list(range(0x202A, 0x202F))  # LRE/RLE/PDF/LRO/RLO
    + list(range(0x2066, 0x206A))  # LRI/RLI/FSI/PDI
    + [0x061C]  # ARABIC LETTER MARK
)

UNICODE_TAG_START = 0xE0000
UNICODE_TAG_END = 0xE007F  # inclusive

MIN_BASE64_LEN = 24

_ENTITY_RE = re.compile(r"&(?:#[0-9]+|#[xX][0-9a-fA-F]+|[a-zA-Z][a-zA-Z0-9]*);")
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}")


# --- stage (a): HTML entities ---------------------------------------------


def decode_entities(text: str) -> str:
    """Decode HTML entities to their characters (pure)."""
    return html.unescape(text)


def count_entities(text: str) -> int:
    """Count entities in *text* that actually decode to something else."""
    count = 0
    for match in _ENTITY_RE.finditer(text):
        if html.unescape(match.group(0)) != match.group(0):
            count += 1
    return count


# --- stage (b): base64 blobs -----------------------------------------------


@dataclass(frozen=True)
class Base64Blob:
    """A validated base64 candidate and its decoded text."""

    start: int
    end: int
    encoded: str
    decoded: str


def _is_printable_text(text: str) -> bool:
    """False-positive guard for decoded base64.

    Requires printable characters (plus common whitespace) and at least one
    whitespace character. Long identifiers such as 'ThisIsAPlainTextSentence'
    either fail UTF-8 decoding or decode to space-free garbage; both are
    rejected here so plain prose/code identifiers are not mistaken for
    encoded payloads.
    """
    if not text:
        return False
    for ch in text:
        if ch in "\n\r\t ":
            continue
        if not ch.isprintable():
            return False
    return any(ch in "\n\r\t " for ch in text)


def find_base64_blobs(text: str) -> List[Base64Blob]:
    """Return validated base64 blobs in *text* with their decoded content.

    A candidate must be at least MIN_BASE64_LEN characters, use only the
    base64 charset with correct trailing padding, decode without error, be
    valid UTF-8, and pass the printable-text guard.
    """
    blobs: List[Base64Blob] = []
    for match in _BASE64_RE.finditer(text):
        candidate = match.group(0)
        if len(candidate) < MIN_BASE64_LEN:
            continue
        if len(candidate) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            continue
        if not raw:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if not _is_printable_text(decoded):
            continue
        blobs.append(
            Base64Blob(
                start=match.start(),
                end=match.end(),
                encoded=candidate,
                decoded=decoded,
            )
        )
    return blobs


# --- stage (c): unicode tags / zero-width / bidi ---------------------------


def is_unicode_tag(char: str) -> bool:
    code = ord(char)
    return UNICODE_TAG_START <= code <= UNICODE_TAG_END


def decode_unicode_tags(text: str) -> Tuple[str, int]:
    """Map Unicode tag characters to their mirrored ASCII letters.

    U+E0041 decodes to 'A'. Returns (decoded_text, number_of_tags).
    """
    out: List[str] = []
    tags = 0
    for char in text:
        code = ord(char)
        if UNICODE_TAG_START <= code <= UNICODE_TAG_END:
            out.append(chr(code - UNICODE_TAG_START))
            tags += 1
        else:
            out.append(char)
    return "".join(out), tags


def encode_unicode_tags(text: str) -> str:
    """Inverse of decode_unicode_tags (used by tests and the fixture generator)."""
    return "".join(chr(UNICODE_TAG_START + ord(c)) for c in text)


def find_zero_width(text: str) -> List[Tuple[int, str]]:
    """Return (index, char) pairs for zero-width characters in *text*."""
    return [(i, ch) for i, ch in enumerate(text) if ord(ch) in ZERO_WIDTH_CHARS]


def find_bidi_controls(text: str) -> List[Tuple[int, str]]:
    """Return (index, char) pairs for bidi control characters in *text*."""
    return [(i, ch) for i, ch in enumerate(text) if ord(ch) in BIDI_CONTROL_CHARS]


def strip_invisible(text: str) -> Tuple[str, int, int]:
    """Remove zero-width and bidi control characters.

    Returns (stripped_text, zero_width_count, bidi_count).
    """
    out: List[str] = []
    zw = 0
    bidi = 0
    for char in text:
        code = ord(char)
        if code in ZERO_WIDTH_CHARS:
            zw += 1
        elif code in BIDI_CONTROL_CHARS:
            bidi += 1
        else:
            out.append(char)
    return "".join(out), zw, bidi


# --- composite -------------------------------------------------------------


@dataclass
class NormalizedLine:
    """Result of running the full pipeline over a single line."""

    raw: str
    text: str
    entities: int = 0
    tags: int = 0
    zero_width: int = 0
    bidi: int = 0
    blobs: List[Base64Blob] = field(default_factory=list)


def normalize_line(raw: str) -> NormalizedLine:
    """Run stages (a), (b), (c) over one line and return the match text.

    Order: entities -> base64 detection (side channel) -> tag decode ->
    strip zero-width/bidi. The returned ``text`` is what rules match
    against; ``blobs`` carries decoded payloads for separate analysis.
    """
    entity_text = decode_entities(raw)
    blobs = find_base64_blobs(entity_text)
    tag_text, tag_count = decode_unicode_tags(entity_text)
    match_text, zw_count, bidi_count = strip_invisible(tag_text)
    return NormalizedLine(
        raw=raw,
        text=match_text,
        entities=count_entities(raw),
        tags=tag_count,
        zero_width=zw_count,
        bidi=bidi_count,
        blobs=blobs,
    )


def clean_text(raw: str) -> Tuple[str, dict]:
    """Sanitization used by the ``clean`` subcommand.

    Behavior (documented choice):
      * HTML entities are normalized to plain text.
      * Unicode tag characters are DECODED to visible ASCII (U+E0041 -> 'A'),
        never silently dropped, so reviewers can see what was hidden.
      * Zero-width and bidi control characters are removed.

    Returns (cleaned_text, counts) where counts has the keys
    entities, tags, zero_width, bidi.
    """
    entity_text = decode_entities(raw)
    entities = count_entities(raw)
    tag_text, tags = decode_unicode_tags(entity_text)
    stripped, zw, bidi = strip_invisible(tag_text)
    counts = {
        "entities": entities,
        "tags": tags,
        "zero_width": zw,
        "bidi": bidi,
    }
    return stripped, counts
