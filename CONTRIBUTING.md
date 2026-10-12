# Contributing to injectlens

Thanks for helping make document ingestion safer.

## Ground rules

1. **Stdlib only.** No third-party runtime or test dependencies.
2. **No network.** Nothing in `src/` may open a socket or resolve a host.
3. **Defanged examples only.** Bundled payloads must target the fake action
   "print the word BANANA" (or equally harmless text). No real-world attack
   content, no weaponization.
4. **Stable rule ids.** `IL-xxx` ids never change meaning; retired rules stay
   documented as deprecated. New rules get the next free number.

## Adding or changing a rule

1. Edit `src/injectlens/rules.py`: id, severity, patterns, `gist_ref`,
   `why`, `action`.
2. Add a positive case in `tests/test_rules.py::TestPositives` **and** a
   negative case proving prose does not false-positive.
3. If the rule needs new normalization signals, add them to
   `normalize.py` as a pure function with its own unit tests.
4. Make sure the example corpus still exercises the rule (or add a fixture
   line and regenerate with `python examples/generate_fixtures.py`).
5. Update `README.md`, `docs/PROJECT_SPEC.md` and `CHANGELOG.md`.

## Running the suite

```sh
python -m unittest discover -s tests -t . -v
```

All tests must pass with exit code 0. CLI changes must keep the documented
exit-code contract (0 = under gate, 1 = findings at/above `--fail-on`,
2 = usage/read error).

## Pull requests

- One behavioral change per PR.
- Include observed output for anything that changes reports or exit codes
  (paste the actual command and output; do not hand-write expected output).
- Keep excerpts in reports free of non-ASCII escapes unless the escape is
  the point (hidden-character findings intentionally show `\uXXXX`).
