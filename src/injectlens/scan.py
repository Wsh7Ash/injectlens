"""Scanning engine: walk files, run normalization + rules, collect findings."""

import os
from dataclasses import dataclass
from typing import List

from . import normalize
from .rules import DECODED_CONTENT_RULES, RULES_BY_ID, SEVERITY_ORDER, match_line

DEFAULT_EXTENSIONS = (".md", ".txt", ".html", ".htm", ".eml")
EXCERPT_LEN = 160

# IL-007 structural thresholds (documented heuristics)
MIN_TAG_CHARS = 4
MIN_INVISIBLE = 2


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    message: str
    excerpt: str
    gist_ref: str

    def to_dict(self):
        return {
            "file": self.file.replace("\\", "/"),
            "line": self.line,
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "excerpt": self.excerpt,
            "gist_ref": self.gist_ref,
        }


def _excerpt(text: str) -> str:
    text = text.replace("\t", "\\t")
    out = []
    for ch in text[:EXCERPT_LEN]:
        code = ord(ch)
        if code < 32:
            out.append("\\u%04x" % code)
        elif code > 126:
            if code > 0xFFFF:
                out.append("\\U%08x" % code)
            else:
                out.append("\\u%04x" % code)
        else:
            out.append(ch)
    suffix = "..." if len(text) > EXCERPT_LEN else ""
    return "".join(out) + suffix


def _hidden_excerpt(raw: str, hidden_chars) -> str:
    """Excerpt showing the raw line with hidden characters escaped."""
    marks = ["\\u%04x" % ord(ch) for _, ch in hidden_chars[:12]]
    return "%s  [hidden: %s]" % (_excerpt(raw), ", ".join(marks))


def scan_text(text: str, path: str = "<text>") -> List[Finding]:
    """Scan text content; return findings sorted by (line, rule)."""
    findings: List[Finding] = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        normalized = normalize.normalize_line(raw)

        for rule, matched in match_line(normalized.text):
            findings.append(
                Finding(
                    file=path,
                    line=lineno,
                    rule=rule.id,
                    severity=rule.severity,
                    message="%s: matched %r (%s)" % (rule.name, matched, rule.gist_ref),
                    excerpt=_excerpt(normalized.text),
                    gist_ref=rule.gist_ref,
                )
            )

        for blob in normalized.blobs:
            for rule_id in DECODED_CONTENT_RULES:
                rule = RULES_BY_ID[rule_id]
                for other, matched in match_line(blob.decoded):
                    if other.id != rule_id:
                        continue
                    findings.append(
                        Finding(
                            file=path,
                            line=lineno,
                            rule="IL-006",
                            severity=RULES_BY_ID["IL-006"].severity,
                            message=(
                                "encoded payload decodes to %s content: matched %r"
                                % (rule.name, matched)
                            ),
                            excerpt=_excerpt(blob.decoded),
                            gist_ref=RULES_BY_ID["IL-006"].gist_ref,
                        )
                    )
                    break

        tag_chars = [(i, ch) for i, ch in enumerate(normalized.raw) if normalize.is_unicode_tag(ch)]
        if len(tag_chars) >= MIN_TAG_CHARS:
            tag_str = "".join(ch for _, ch in tag_chars)
            hidden_decoded, _ = normalize.decode_unicode_tags(tag_str)
            findings.append(
                Finding(
                    file=path,
                    line=lineno,
                    rule="IL-007",
                    severity=RULES_BY_ID["IL-007"].severity,
                    message=(
                        "hidden unicode: %d tag characters decode to %r"
                        % (len(tag_chars), hidden_decoded[:120])
                    ),
                    excerpt=_hidden_excerpt(raw, tag_chars),
                    gist_ref=RULES_BY_ID["IL-007"].gist_ref,
                )
            )
        elif normalized.zero_width + normalized.bidi >= MIN_INVISIBLE:
            hidden = normalize.find_zero_width(raw) or normalize.find_bidi_controls(raw)
            findings.append(
                Finding(
                    file=path,
                    line=lineno,
                    rule="IL-007",
                    severity=RULES_BY_ID["IL-007"].severity,
                    message=(
                        "invisible characters: %d zero-width, %d bidi controls"
                        % (normalized.zero_width, normalized.bidi)
                    ),
                    excerpt=_hidden_excerpt(raw, hidden),
                    gist_ref=RULES_BY_ID["IL-007"].gist_ref,
                )
            )

    return _dedupe(findings)


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for finding in findings:
        key = (finding.file, finding.rule, finding.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    out.sort(key=lambda f: (f.file.replace("\\", "/"), f.line, f.rule))
    return out


def scan_file(path: str) -> List[Finding]:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return scan_text(handle.read(), path=path)


def collect_files(paths, extensions=DEFAULT_EXTENSIONS):
    """Expand files/directories into a sorted list of scannable files."""
    found = []
    exts = tuple(e.lower() for e in extensions)
    for path in paths:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for fname in sorted(files):
                    if fname.lower().endswith(exts):
                        found.append(os.path.join(root, fname))
        else:
            found.append(path)
    return sorted(set(found))


def filter_by_severity(findings: List[Finding], min_severity: str) -> List[Finding]:
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER[f.severity] >= threshold]
