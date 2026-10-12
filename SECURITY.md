# Security policy

## Reporting a vulnerability

If you find a security issue in `injectlens` itself (for example a path
handling bug that lets it read outside the directory you passed, or a crash
that can be triggered by a crafted file), please open a **private security
advisory** on this repository (GitHub → Security → Advisories → Report a
vulnerability) rather than a public issue. Include the version, the input
that triggers it, and the expected vs actual behavior. You can also reach
the maintainer through the contact details on the owner's GitHub profile.

## What injectlens is (and is not)

- **Is:** an offline detector and sanitizer for indirect prompt-injection
  content in documents **you own or are authorized to test**.
- **Is not:** a license to scan other people's data, and not a guarantee
  that a document is safe. The rules are heuristic: a clean scan reduces
  risk, it does not prove the absence of an injection.

## Safe handling of findings

- A report may quote hidden or encoded payloads (that is its job). Treat
  `results/report.txt` / `report.json` as potentially sensitive if the
  scanned documents were sensitive.
- The `clean` subcommand deliberately *reveals* hidden instructions as
  visible text. Review cleaned files before sharing them onward.
- Example fixtures in `examples/corpus/` are defanged: their payload target
  is the fake action "print the word BANANA". Do not "weaponize" them; the
  repository intentionally ships no real-world attack content.

## Runtime guarantees

- No network access, ever. The package uses only the Python standard library.
- No execution, rendering or interpretation of scanned content — text is
  matched by regexes and reported as strings.
- Scans are read-only; only the explicit `clean -o <path>` writes files,
  and only where you tell it to.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | ✅ |
