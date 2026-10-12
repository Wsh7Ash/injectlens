"""injectlens command-line interface."""

import argparse
import json
import sys

from . import __version__, clean, report, scan
from .rules import SEVERITY_ORDER

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def cmd_scan(args):
    try:
        paths = scan.collect_files(args.paths, extensions=tuple(args.ext))
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE
    if not paths:
        print("error: no scannable files found", file=sys.stderr)
        return EXIT_USAGE

    all_findings = []
    for path in paths:
        try:
            all_findings.extend(scan.scan_file(path))
        except OSError as exc:
            print("error: cannot read %s: %s" % (path, exc), file=sys.stderr)
            return EXIT_USAGE

    visible = scan.filter_by_severity(all_findings, args.min_severity)
    threshold = SEVERITY_ORDER[args.fail_on]
    failing = [f for f in all_findings if SEVERITY_ORDER[f.severity] >= threshold]

    if args.format == "json":
        sys.stdout.write(
            report.render_json(
                visible, len(paths), min_severity=args.min_severity, fail_on=args.fail_on
            )
        )
    else:
        sys.stdout.write(
            report.render_text(
                visible, len(paths), min_severity=args.min_severity, fail_on=args.fail_on
            )
        )
    return EXIT_FINDINGS if failing else EXIT_OK


def cmd_clean(args):
    try:
        text, counts = clean.clean_file(args.file)
    except OSError as exc:
        print("error: cannot read %s: %s" % (args.file, exc), file=sys.stderr)
        return EXIT_USAGE
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            print("error: cannot write %s: %s" % (args.output, exc), file=sys.stderr)
            return EXIT_USAGE
    else:
        sys.stdout.write(text)
    summary = {
        "file": args.file.replace("\\", "/"),
        "removed_or_normalized": counts,
        "output": args.output.replace("\\", "/") if args.output else None,
    }
    print(json.dumps(summary, sort_keys=True), file=sys.stderr)
    return EXIT_OK


def build_parser():
    parser = argparse.ArgumentParser(
        prog="injectlens",
        description="Offline indirect prompt-injection scanner for documents you own.",
    )
    parser.add_argument("--version", action="version", version="injectlens %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan files or directories for injection patterns")
    p_scan.add_argument("paths", nargs="+", help="files or directories to scan")
    p_scan.add_argument("--format", choices=("text", "json"), default="text")
    p_scan.add_argument(
        "--min-severity",
        choices=tuple(sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get)),
        default="info",
        help="hide findings below this severity (display only)",
    )
    p_scan.add_argument(
        "--fail-on",
        choices=tuple(sorted(SEVERITY_ORDER, key=SEVERITY_ORDER.get)),
        default="high",
        help="exit 1 if any finding is at or above this severity",
    )
    p_scan.add_argument(
        "--ext",
        default=",".join(scan.DEFAULT_EXTENSIONS),
        help="comma-separated extensions for directory scans",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_clean = sub.add_parser("clean", help="strip hidden characters and normalize a document")
    p_clean.add_argument("file", help="file to sanitize")
    p_clean.add_argument("-o", "--output", help="write cleaned text here (default: stdout)")
    p_clean.set_defaults(func=cmd_clean)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        args.ext = [e.strip() for e in args.ext.split(",") if e.strip()]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
