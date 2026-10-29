"""Strict parsing: bytes input, nesting and size limits, and the JSON-text rules."""

from __future__ import annotations

import json

import pytest

from o2a_protocol import Outcome, parse_strict_json
from o2a_protocol.strictjson import MAX_INPUT_BYTES, StrictJSONError
from o2a_protocol.testing import TEST_NOW, test_verifier

BS = chr(92)
BLOCK_TEXT = json.dumps({"typ": "o2a-sponsored-offer/v0"})


def rejected(data: str | bytes) -> str:
    with pytest.raises(StrictJSONError) as info:
        parse_strict_json(data)
    result = test_verifier().verify(data, now=TEST_NOW)
    assert result.outcome is Outcome.MALFORMED
    assert result.detail == info.value.detail
    return info.value.detail


# Bytes input.
def test_invalid_utf8_bytes() -> None:
    assert "UTF-8" in rejected(b'{"typ":"\xff"}')


def test_utf8_bom_bytes() -> None:
    assert "byte order mark" in rejected(b"\xef\xbb\xbf" + BLOCK_TEXT.encode())


def test_bom_in_str() -> None:
    assert "byte order mark" in rejected(chr(0xFEFF) + BLOCK_TEXT)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be", "utf-32"])
def test_utf16_and_utf32_bytes(codec: str) -> None:
    rejected(BLOCK_TEXT.encode(codec))


# Deep nesting.
def test_deep_nesting() -> None:
    assert rejected("[" * 10_000 + "]" * 10_000) == "nesting too deep"
    rejected('{"a":' * 10_000 + "1" + "}" * 10_000)


# Size limit.
def test_over_64_kib() -> None:
    big = '"' + "a" * MAX_INPUT_BYTES + '"'
    assert rejected(big) == "input larger than 64 KiB"
    assert rejected(big.encode()) == "input larger than 64 KiB"


def test_over_64_kib_in_utf8_bytes_only() -> None:
    # Fewer than 64 Ki code points, but more than 64 KiB once encoded.
    text = '"' + "é" * (MAX_INPUT_BYTES // 2) + '"'
    assert len(text) < MAX_INPUT_BYTES
    assert rejected(text) == "input larger than 64 KiB"


def test_exactly_64_kib_is_parsed() -> None:
    text = '"' + "a" * (MAX_INPUT_BYTES - 2) + '"'
    assert parse_strict_json(text) == "a" * (MAX_INPUT_BYTES - 2)
    assert parse_strict_json(text.encode()) == "a" * (MAX_INPUT_BYTES - 2)


def test_wrong_input_type_is_a_programmer_error() -> None:
    with pytest.raises(TypeError):
        parse_strict_json(42)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":1}',
        '{"a":1,"' + BS + 'u0061":1}',
        "20.0",
        "2e1",
        "2E1",
        "-0",
        "NaN",
        "Infinity",
        "-Infinity",
        "9007199254740992",
        "-9007199254740992",
        "12345678901234567",
        "1" * 5000,
        '"' + BS + 'ud800"',
        '"' + BS + 'udfff"',
        '{"' + BS + 'ud800":1}',
        '["' + BS + 'ud800"]',
        "{",
        "",
        "[1,]",
    ],
)
def test_rejected_texts(text: str) -> None:
    rejected(text)


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("9007199254740991", 2**53 - 1),
        ("-9007199254740991", -(2**53 - 1)),
        ("0", 0),
        (' { "a" : [1, "b", {"c": null, "d": true}] } ', {"a": [1, "b", {"c": None, "d": True}]}),
        ('"' + BS + "ud83d" + BS + 'ude00"', chr(0x1F600)),
        ('"' + BS + 'u0041"', "A"),
    ],
)
def test_accepted_texts(text: str, value: object) -> None:
    assert parse_strict_json(text) == value
    assert parse_strict_json(text.encode()) == value


def test_literal_surrogate_in_str_input() -> None:
    rejected('"' + chr(0xD800) + '"')
