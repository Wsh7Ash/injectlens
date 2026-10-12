# Architecture — injectlens

```
input file(s)
   │
   ▼
collect_files() ── walk directories, filter by extension (.md .txt .html .htm .eml)
   │
   ▼
scan_file() ── split into lines (1-based line numbers)
   │
   ▼
normalize_line(raw)                       [src/injectlens/normalize.py]
   ├─ (a) decode_entities        &amp; &#105; → characters
   ├─ (b) find_base64_blobs      ≥24 chars, valid charset/padding, valid UTF-8,
   │                             printable + ≥1 whitespace (FP guard) → decoded side channel
   ├─ (c) decode_unicode_tags    U+E0000–U+E007F → ASCII (U+E0041 → 'A')
   └─     strip_invisible        zero-width + bidi controls removed from match text
   │
   ▼
rule matching                             [src/injectlens/rules.py]
   ├─ regex rules IL-001..IL-006, IL-008..IL-012 against normalized text
   ├─ decoded-blob analysis: decoded base64 is matched against
   │  IL-001/002/003/005/009 → reported as IL-006 findings
   └─ structural IL-007: ≥4 tag chars on a line, or ≥2 zero-width/bidi chars
   │
   ▼
dedupe (file, rule, line) → sort → filter_by_severity(--min-severity)
   │
   ├─ render_text / render_json           [src/injectlens/report.py]
   └─ exit gate: any finding ≥ --fail-on severity → exit 1 (else 0; usage errors 2)
```

## Module map

| Module | Responsibility |
| --- | --- |
| `normalize.py` | Pure normalization stages; no I/O. |
| `rules.py` | The 12-rule catalogue: id, severity, patterns, gist reference, rationale, remediation. |
| `scan.py` | File walking, line scanning, IL-007 structural checks, dedupe, severity filter. |
| `report.py` | Text and JSON rendering (pure string builders). |
| `clean.py` / `cli.py` | `clean` subcommand and argparse front end; exit-code policy. |

## Design decisions

1. **Normalize before matching.** Rules see entity-decoded, tag-decoded, invisible-stripped text, so payloads hidden by any of those layers still match. Raw text is kept for excerpts so the report shows what the reviewer would actually see (with hidden characters escaped as `\uXXXX`).
2. **Decoded base64 is a side channel, not a rewrite.** The line displayed to the user keeps the original blob; decoded content only feeds rule matching and is quoted in IL-006 findings.
3. **`clean` makes hidden text visible instead of deleting it.** Tag characters are decoded to their ASCII letters (never dropped), so a reviewer sees the hidden instruction rather than a mysteriously shortened sentence. Zero-width/bidi characters are removed because they carry no content.
4. **Exit-code gate is separate from the display filter.** `--min-severity` controls what you see; `--fail-on` controls what fails CI. This lets a team watch high+ while still failing only on criticals.
