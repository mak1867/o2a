"""Tolerant parsing and ``strictify``.

``parse_tolerant`` parses any JSON text while losing nothing: objects keep every member
in order (duplicates included), and numbers keep their raw token text. ``strictify``
then applies the format spec's JSON-text rules (§4.4) to one subtree. ``parse_strict_json``
is exactly ``strictify(parse_tolerant(...))`` under the 64 KiB limit, so the two paths
share one implementation of the rules and cannot disagree.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

DEFAULT_MAX_TOLERANT_BYTES = 8 * 1024 * 1024
MAX_SAFE_INTEGER = 2**53 - 1
# 2**53 - 1 has 16 digits. Longer tokens are rejected before int() sees them, which also
# avoids Python's ValueError for integers over 4300 digits.
_MAX_INT_DIGITS = 16
_INT_TOKEN = re.compile(r"-?(?:0|[1-9][0-9]*)")
_SURROGATE = re.compile("[" + chr(0xD800) + "-" + chr(0xDFFF) + "]")
_BOM = chr(0xFEFF)


class StrictJSONError(Exception):
    """Input breaks the format spec's JSON-text rules. Internal to the library."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


class TolerantJSONError(Exception):
    """Input is not JSON at all (or is too large or too deeply nested to parse)."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True, slots=True)
class RawNumber:
    """A number token exactly as written: ``20``, ``20.0``, ``2e1``, ``-0``, ``NaN``."""

    token: str


@dataclass(frozen=True, slots=True)
class TObject:
    """A JSON object as an ordered tuple of ``(key, value)`` pairs, duplicates kept."""

    pairs: tuple[tuple[str, TolerantValue], ...]

    def get_all(self, key: str) -> list[TolerantValue]:
        """Every value stored under ``key``, in order."""
        return [value for name, value in self.pairs if name == key]


TolerantValue = TObject | tuple["TolerantValue", ...] | RawNumber | str | bool | None


def parse_tolerant(
    data: str | bytes, *, max_bytes: int = DEFAULT_MAX_TOLERANT_BYTES
) -> TolerantValue:
    """Parse JSON text without losing information. Raises ``TolerantJSONError``.

    Bytes must be strict UTF-8 without a byte order mark. Input over ``max_bytes``
    raises ``TolerantJSONError("too_large")``.
    """
    text = _decode(data, max_bytes)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_tobject,
            parse_int=RawNumber,
            parse_float=RawNumber,
            parse_constant=RawNumber,
        )
        return _freeze(value)
    except RecursionError:
        raise TolerantJSONError("nesting too deep") from None
    except ValueError as exc:
        raise TolerantJSONError(f"invalid JSON: {exc}") from None


def strictify(value: TolerantValue) -> object:
    """Apply the format spec §4.4 JSON-text rules to a tolerant subtree.

    Returns plain values (``dict``, ``list``, ``str``, ``int``, ``bool``, ``None``)
    exactly as ``parse_strict_json`` would, or raises ``StrictJSONError``.
    """
    try:
        return _strictify(value)
    except RecursionError:
        raise StrictJSONError("nesting too deep") from None


def strict_int(token: str) -> int:
    """The integer-token rules: no fraction or exponent, no ``-0``, within ±(2**53 - 1)."""
    if token in {"NaN", "Infinity", "-Infinity"}:
        raise StrictJSONError(f"{token} is not allowed")
    if _INT_TOKEN.fullmatch(token) is None:
        raise StrictJSONError("number with a fraction or exponent")
    if token == "-0":
        raise StrictJSONError("-0 is not allowed")
    if len(token.lstrip("-")) > _MAX_INT_DIGITS or abs(int(token)) > MAX_SAFE_INTEGER:
        raise StrictJSONError("integer out of range")
    return int(token)


def _strictify(value: TolerantValue) -> object:
    if isinstance(value, TObject):
        result: dict[str, object] = {}
        for key, child in value.pairs:
            if key in result:
                raise StrictJSONError("duplicate member name")
            if _SURROGATE.search(key):
                raise StrictJSONError("unpaired surrogate in member name")
            result[key] = _strictify(child)
        return result
    if isinstance(value, tuple):
        return [_strictify(item) for item in value]
    if isinstance(value, RawNumber):
        return strict_int(value.token)
    if isinstance(value, str):
        if _SURROGATE.search(value):
            raise StrictJSONError("unpaired surrogate in string")
        return value
    if value is None or isinstance(value, bool):
        return value
    raise TypeError(f"not a tolerant JSON value: {type(value).__name__}")


def _decode(data: str | bytes, max_bytes: int) -> str:
    if isinstance(data, bytes):
        if len(data) > max_bytes:
            raise TolerantJSONError("too_large")
        if data.startswith(_BOM.encode()):
            raise TolerantJSONError("input starts with a byte order mark")
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise TolerantJSONError("input is not valid UTF-8") from None
    if isinstance(data, str):
        # Each code point is at least one UTF-8 byte, so the cheap length check comes first.
        if len(data) > max_bytes or len(data.encode("utf-8", "surrogatepass")) > max_bytes:
            raise TolerantJSONError("too_large")
        if data.startswith(_BOM):
            raise TolerantJSONError("input starts with a byte order mark")
        return data
    raise TypeError(f"expected str or bytes, got {type(data).__name__}")


def _tobject(pairs: list[tuple[str, object]]) -> TObject:
    return TObject(tuple((key, _freeze(value)) for key, value in pairs))


def _freeze(value: object) -> TolerantValue:
    """Turn the lists ``json`` builds into tuples. Objects are already ``TObject``."""
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    assert value is None or isinstance(value, TObject | RawNumber | str | bool)
    return value
