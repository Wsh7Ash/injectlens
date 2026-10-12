"""clean subcommand: sanitize a document (defense output)."""

from .normalize import clean_text


def clean_file(path):
    """Return (cleaned_text, counts) for the file at *path*."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()
    return clean_text(raw)
