"""Strict JSON parsing (format spec §4.4 JSON-text rules).

Python's ``json`` module is lenient in ways the format forbids: it keeps the last of
duplicate member names, accepts ``NaN``/``Infinity``, turns ``20.0`` into a float,
accepts ``-0``, auto-detects UTF-16/32 when given bytes, and lets ``"\\ud800"`` escapes
through as unpaired surrogates.

Since phase 2, strict parsing is exactly ``strictify(parse_tolerant(data))`` under a
64 KiB limit, so it shares one implementation of the rules with block extraction.
"""

from __future__ import annotations

from .tolerant import (
    MAX_SAFE_INTEGER,
    StrictJSONError,
    TolerantJSONError,
    parse_tolerant,
    strictify,
)

__all__ = ["MAX_INPUT_BYTES", "MAX_SAFE_INTEGER", "StrictJSONError", "parse_strict_json"]

MAX_INPUT_BYTES = 64 * 1024


def parse_strict_json(data: str | bytes) -> object:
    """Parse JSON text under the format spec's strict rules.

    Returns the parsed value (dicts, lists, strings, ints, bools and None) or raises
    ``StrictJSONError``. Raises ``TypeError`` if ``data`` is not ``str`` or ``bytes``.
    """
    try:
        tree = parse_tolerant(data, max_bytes=MAX_INPUT_BYTES)
    except TolerantJSONError as exc:
        detail = "input larger than 64 KiB" if exc.detail == "too_large" else exc.detail
        raise StrictJSONError(detail) from None
    return strictify(tree)
