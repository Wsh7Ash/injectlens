# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-10-12

### Added

- Normalization pipeline as pure functions: HTML entity decoding, base64
  blob detection with a printable-text false-positive guard, Unicode tag
  decoding (`U+E0041 → 'A'`), zero-width/bidi stripping.
- 12 detection rules `IL-001`–`IL-012` with stable ids, severities
  (info…critical), rationale, remediation and prompt-injection taxonomy
  (gist section) references.
- Structural hidden-unicode rule `IL-007` (≥4 tag chars, or ≥2
  zero-width/bidi chars per line) with decoded payload surfaced in the
  finding message.
- Decoded-blob analysis: base64 content is matched against the
  instruction-override/persona/role/tool/refusal rules and reported as
  `IL-006` findings.
- CLI: `scan` (text/JSON, `--min-severity`, `--fail-on`, `--ext`) and
  `clean` (stdout or `-o`, JSON summary on stderr); exit codes 0/1/2.
- Defanged six-file example corpus + deterministic `examples/generate_fixtures.py`.
- 68 unittest cases; docs (spec/architecture/usage), SECURITY.md, CI workflow.
- Results captured under `results/` (test log, scan reports, clean outputs).
