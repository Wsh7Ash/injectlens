"""Report rendering: text and JSON."""

import json
from collections import Counter

from .rules import SEVERITY_ORDER


def render_text(findings, files_scanned, min_severity="info", fail_on="high"):
    lines = []
    by_file = {}
    for finding in findings:
        by_file.setdefault(finding.file, []).append(finding)

    for path in sorted(by_file):
        lines.append(path.replace("\\", "/"))
        for finding in by_file[path]:
            lines.append(
                "  %s:%d  %s [%s] %s"
                % (
                    finding.file.replace("\\", "/"),
                    finding.line,
                    finding.severity.upper(),
                    finding.rule,
                    finding.message,
                )
            )
            lines.append("      excerpt: %s" % finding.excerpt)
        lines.append("")

    counts = Counter(f.rule for f in findings)
    sev_counts = Counter(f.severity for f in findings)
    lines.append("=== Summary ===")
    lines.append("files scanned: %d" % files_scanned)
    lines.append("findings: %d" % len(findings))
    if counts:
        lines.append("by rule:")
        for rule_id in sorted(counts):
            lines.append("  %-8s %d" % (rule_id, counts[rule_id]))
        lines.append(
            "by severity: %s"
            % ", ".join(
                "%s=%d" % (sev, sev_counts.get(sev, 0))
                for sev in sorted(sev_counts, key=lambda s: SEVERITY_ORDER[s])
            )
        )
    lines.append(
        "display filter: min-severity=%s | fail-on=%s" % (min_severity, fail_on)
    )
    return "\n".join(lines) + "\n"


def render_json(findings, files_scanned, min_severity="info", fail_on="high"):
    by_rule = Counter(f.rule for f in findings)
    payload = {
        "files_scanned": files_scanned,
        "finding_count": len(findings),
        "by_rule": dict(sorted(by_rule.items())),
        "min_severity": min_severity,
        "fail_on": fail_on,
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
