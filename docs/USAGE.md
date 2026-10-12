# Usage — injectlens

All commands run from the repository root. The package lives in `src/`, so either
prefix commands with `PYTHONPATH=src` (Linux/macOS) or
`$env:PYTHONPATH="src"` (PowerShell) before using `python -m injectlens`.

## Scan a corpus

```sh
python -m injectlens scan examples/corpus
```

Text report, grouped by file, with line numbers, severities, rule ids,
gist-section references and excerpts. Ends with a summary block.

Exit codes: `0` = no finding at or above `--fail-on` (default `high`),
`1` = at least one such finding, `2` = usage/read error.

## JSON output (for CI tooling)

```sh
python -m injectlens scan examples/corpus --format json
```

Top-level keys: `files_scanned`, `finding_count`, `by_rule`,
`min_severity`, `fail_on`, `findings[]` (each with `file`, `line`, `rule`,
`severity`, `message`, `excerpt`, `gist_ref`).

## Control the exit gate independently of the display

```sh
# show only criticals, but still fail the build on any high+
python -m injectlens scan docs/ --min-severity critical --fail-on high

# show everything, only fail on criticals
python -m injectlens scan docs/ --fail-on critical
```

`--fail-on` compares each finding's severity against the threshold
(`info` < `low` < `medium` < `high` < `critical`); a finding at or above
the threshold fails the run. `--fail-on critical` is the most permissive gate.

## Limit directory scans to specific extensions

```sh
python -m injectlens scan corpus/ --ext .md,.txt
```

Default extensions: `.md`, `.txt`, `.html`, `.htm`, `.eml`.
Dot-directories (`.git` etc.) are skipped during walks.

## Clean a document (defense output)

```sh
python -m injectlens clean examples/corpus/hidden-unicode.txt            # stdout
python -m injectlens clean examples/corpus/hidden-unicode.txt -o clean.txt
```

A JSON summary of what was removed/normalized is printed to **stderr**;
the cleaned text goes to stdout or `--output`. Unicode tag characters are
decoded to visible ASCII (`U+E0041` → `A`) rather than dropped;
zero-width and bidi controls are removed; HTML entities are normalized.

Re-scan the cleaned file to confirm the hidden payload is now visible:

```sh
python -m injectlens scan clean.txt
```

## Version

```sh
python -m injectlens --version
```
