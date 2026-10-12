"""Rule definitions for injectlens.

Every payload in this module is a DEFANGED structural skeleton used for
detection and education. Targets are fake ("print the word BANANA").
Taxonomy references come from the Prompt Injection & Jailbreak Techniques
comprehensive reference (kibotu gist) sections noted per rule.
"""

import re
from dataclasses import dataclass, field
from typing import List, Pattern

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str
    patterns: List[Pattern[str]] = field(default_factory=list)
    gist_ref: str = ""
    why: str = ""
    action: str = ""


def _rx(*expressions):
    return [re.compile(expr, re.IGNORECASE) for expr in expressions]


RULES = [
    Rule(
        id="IL-001",
        name="instruction override",
        severity="high",
        patterns=_rx(
            r"\bignore\b[^.\n]{0,60}\b(instructions?|prompts?|rules?|everything|previous|prior|above|earlier)\b",
            r"\bdisregard\b[^.\n]{0,40}\b(the\s+)?(above|previous|system|original)\b",
            r"\bforget\b[^.\n]{0,30}\b(everything|your\s+(instructions?|rules?|programming))\b",
        ),
        gist_ref="gist section 3.3 (instruction override)",
        why="Asserts authority over the developer/system prompt (OWASP LLM01 core pattern).",
        action="Reject the input; never let document text override the system prompt.",
    ),
    Rule(
        id="IL-002",
        name="persona escape",
        severity="high",
        patterns=_rx(
            r"\byou are now\b",
            r"\bact as\b[^.\n]{0,20}\b(dan|an?\s+unrestricted)\b",
            r"\bdeveloper mode\b",
            r"\bunrestricted mode\b",
            r"\bno longer bound by\b",
            r"\bjailbroken?\b",
        ),
        gist_ref="gist sections 3.1-3.2 (DAN / persona family)",
        why="Role-play framing used to instantiate an persona outside safety rules.",
        action="Treat persona-escape text as hostile; keep the real system persona.",
    ),
    Rule(
        id="IL-003",
        name="role or turn spoofing",
        severity="high",
        patterns=_rx(
            r"<\|im_start\|>",
            r"<\|im_end\|>",
            r"\[INST\]",
            r"<\|system\|>",
            r"<\|assistant\|>",
            r"^\s*(system|assistant)\s*:",
        ),
        gist_ref="gist section 3.13 (special-token / ChatML mimicry)",
        why="Chat-template delimiters or fake role markers smuggled into content.",
        action="Strip special tokens server-side before the model sees the text.",
    ),
    Rule(
        id="IL-004",
        name="exfiltration URL",
        severity="critical",
        patterns=_rx(
            r"!\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*(conversation|history|prompt|secret|token|session|api[_-]?key)[^)\s]*\)",
            r"\[[^\]]*\]\(https?://[^)\s]*[?&][^)\s]*(conversation|history|prompt|secret|token|session|api[_-]?key)[^)\s]*\)",
            r"\b(fetch|open|request)\b[^.\n]{0,60}\bhttps?://[^.\s]+[^.\n]{0,80}\b(conversation|history|chat log|context)\b",
        ),
        gist_ref="gist section 4.3 (markdown image/link exfiltration)",
        why="Zero-click exfil channel: auto-rendered images/links leak context via query strings.",
        action="Neutralize or block URLs that try to carry conversation data; disable auto-fetch.",
    ),
    Rule(
        id="IL-005",
        name="tool or agent hijack",
        severity="critical",
        patterns=_rx(
            r"\balways call\b",
            r"\bwithout (asking|confirmation|confirming)\b",
            r"\bauto-?approve\b",
            r"\bbypass\b[^.\n]{0,30}\b(confirmation|safety|guardrail|approval)\b",
            r"\bdisable\b[^.\n]{0,20}\b(your\s+)?(safety|guardrails?|confirmations?)\b",
            r"\brun (this|it) before\b",
            r"\bno need to ask\b",
        ),
        gist_ref="gist section 4.4 (tool / function-call hijacking)",
        why="Confused-deputy pattern: content tries to drive the agent's privileged tools.",
        action="Require human-in-the-loop approval for tool calls triggered by document content.",
    ),
    Rule(
        id="IL-006",
        name="encoded payload instruction",
        severity="medium",
        patterns=_rx(
            r"\b(decode|decipher|base64|rot13|hex)[^.\n]{0,50}\b(and|then)?\s*(follow|obey|execute|perform|run)\b",
            r"\bbase64[- ]decode\b",
            r"\brot13\b[^.\n]{0,30}\b(decode|apply)\b",
        ),
        gist_ref="gist section 5.1 (base64 / ROT13 / hex encoding)",
        why="Encoded payloads defeat keyword filters while the model can still decode them.",
        action="Decode and scan encoded blobs before the model sees them (as this tool does).",
    ),
    Rule(
        id="IL-007",
        name="hidden unicode",
        severity="high",
        patterns=[],  # structural: fires on normalization signals, not regex
        gist_ref="gist section 5.2 (unicode tags / zero-width / bidi)",
        why="Invisible characters hide instructions from human review while models still read them.",
        action="Strip tag/zero-width/bidi characters and NFKC-normalize before analysis.",
    ),
    Rule(
        id="IL-008",
        name="hidden HTML styling",
        severity="high",
        patterns=_rx(
            r"color\s*:\s*(#ffffff|#fff|white)\b",
            r"font-size\s*:\s*0(\.0+)?\b",
            r"visibility\s*:\s*hidden",
            r"display\s*:\s*none",
        ),
        gist_ref="gist section 4.2 (email hidden-text injection)",
        why="White-on-white / zero-size / hidden text is invisible to humans but read by models.",
        action="Strip invisible HTML styling from content before ingesting it.",
    ),
    Rule(
        id="IL-009",
        name="refusal suppression",
        severity="medium",
        patterns=_rx(
            r"\bnever (refuse|apologize|disclaim|hesitate)\b",
            r"\bwithout any (warning|disclaimer|caveat|restriction)\b",
            r"\bdo not (mention|reveal|disclose)\b[^.\n]{0,30}\b(these|the|any|this)\b[^.\n]{0,20}\b(instructions?|rules?|guidance)\b",
        ),
        gist_ref="gist section 3.5 (refusal suppression)",
        why="Constrains output form so trained refusal vocabulary cannot appear.",
        action="Ignore output-format constraints embedded in untrusted content.",
    ),
    Rule(
        id="IL-010",
        name="rules-file backdoor style",
        severity="high",
        patterns=_rx(
            r"\bhide (your|the|this) (changes?|edits?|modifications?|steps?)\b",
            r"\bdo not (record|log|mention|reveal|report)\b[^.\n]{0,30}\b(this|these|the)\b",
            r"\bsuppress\b[^.\n]{0,20}\b(the )?(logs?|audit|history|trail)\b",
        ),
        gist_ref="gist section 4.5 (code-comment / rules-file backdoor)",
        why="Log-suppression and change-hiding instructions aim to keep a compromise invisible.",
        action="Always surface document-triggered actions to the user and the audit log.",
    ),
    Rule(
        id="IL-011",
        name="fake policy override",
        severity="medium",
        patterns=_rx(
            r"\[system policy\]",
            r"^\s*\"?policy\"\s*:",
            r"\bpolicy update\s*:",
            r"\[new (guidelines|policy|rules)\]",
        ),
        gist_ref="gist section 8.1 (policy puppetry)",
        why="Fake policy blocks try to masquerade as authoritative system configuration.",
        action="Only the deployment's real system prompt/config may set policy.",
    ),
    Rule(
        id="IL-012",
        name="escalation framing",
        severity="low",
        patterns=_rx(
            r"\bbased on your (previous|prior) (answers?|responses?|output)\b",
            r"\bnow provide the (concrete )?specifics\b",
            r"\belaborate on the (sub-?aspect|detail)\b[^.\n]{0,20}\b(you )?(mentioned|wrote)\b",
        ),
        gist_ref="gist section 3.10 (crescendo-style escalation, conservative subset)",
        why="Multi-turn escalation phrasing; alone it is often benign, so severity is low.",
        action="Watch for escalation chains across turns, not just single messages.",
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}

# Patterns reused to inspect decoded base64 content for IL-006.
DECODED_CONTENT_RULES = ["IL-001", "IL-002", "IL-003", "IL-005", "IL-009"]


def match_line(text: str):
    """Yield (rule, matched_text) for every rule matching *text*."""
    for rule in RULES:
        for pattern in rule.patterns:
            found = pattern.search(text)
            if found:
                yield rule, found.group(0)
                break
