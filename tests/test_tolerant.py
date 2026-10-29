"""Tolerant parsing and strictify, including the property that both parsers agree."""

from __future__ import annotations

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from o2a_protocol import RawNumber, TObject, parse_strict_json, parse_tolerant, strictify
from o2a_protocol.strictjson import StrictJSONError
from o2a_protocol.tolerant import TolerantJSONError, TolerantValue

BS = chr(92)


def test_objects_keep_every_member_in_order() -> None:
    tree = parse_tolerant('{"b":1,"a":2,"b":3}')
    assert tree == TObject((("b", RawNumber("1")), ("a", RawNumber("2")), ("b", RawNumber("3"))))
    assert isinstance(tree, TObject)
    assert tree.get_all("b") == [RawNumber("1"), RawNumber("3")]
    assert tree.get_all("missing") == []


@pytest.mark.parametrize(
    "token", ["20", "20.0", "2e1", "2E1", "-0", "NaN", "Infinity", "-Infinity", "1" * 5000]
)
def test_numbers_keep_their_raw_token(token: str) -> None:
    assert parse_tolerant(f"[{token}]") == (RawNumber(token),)


def test_arrays_become_tuples_at_every_level() -> None:
    tree = parse_tolerant('[[1,[2]],{"a":[{"b":[]}]}]')
    assert tree == (
        (RawNumber("1"), (RawNumber("2"),)),
        TObject((("a", (TObject((("b", ()),)),)),)),
    )


def test_strings_are_unescaped_and_may_hold_surrogates() -> None:
    assert parse_tolerant('"' + BS + 'u0041"') == "A"
    assert parse_tolerant('"' + BS + 'ud800"') == chr(0xD800)
    assert parse_tolerant("[true,false,null]") == (True, False, None)


@pytest.mark.parametrize(
    ("data", "detail"),
    [
        (b'"\xff"', "input is not valid UTF-8"),
        (b"\xef\xbb\xbf{}", "input starts with a byte order mark"),
        (chr(0xFEFF) + "{}", "input starts with a byte order mark"),
        ("[" * 100_000 + "]" * 100_000, "nesting too deep"),
    ],
)
def test_parse_errors(data: str | bytes, detail: str) -> None:
    with pytest.raises(TolerantJSONError) as info:
        parse_tolerant(data)
    assert info.value.detail == detail


@pytest.mark.parametrize("data", ["{", "", "[1,]", "Service unavailable"])
def test_not_json(data: str) -> None:
    with pytest.raises(TolerantJSONError, match="invalid JSON"):
        parse_tolerant(data)


def test_size_limit_is_configurable() -> None:
    assert parse_tolerant('"' + "a" * 8 + '"', max_bytes=10) == "a" * 8
    samples: list[str | bytes] = [
        '"' + "a" * 9 + '"',
        ('"' + "a" * 9 + '"').encode(),
        '"' + "é" * 5 + '"',
    ]
    for data in samples:
        with pytest.raises(TolerantJSONError) as info:
            parse_tolerant(data, max_bytes=10)
        assert info.value.detail == "too_large"


def test_default_limit_is_8_mib() -> None:
    with pytest.raises(TolerantJSONError, match="too_large"):
        parse_tolerant(b" " * (8 * 1024 * 1024 + 1))


def test_wrong_input_type() -> None:
    with pytest.raises(TypeError):
        parse_tolerant(42)  # type: ignore[arg-type]


# strictify ------------------------------------------------------------------------------


def test_strictify_returns_plain_values() -> None:
    tree = parse_tolerant('{"a":[1,{"b":"x"}],"c":true,"d":null}')
    assert strictify(tree) == {"a": [1, {"b": "x"}], "c": True, "d": None}


@pytest.mark.parametrize(
    ("text", "detail"),
    [
        ('{"a":1,"a":1}', "duplicate member name"),
        ('[{"a":1,"' + BS + 'u0061":2}]', "duplicate member name"),
        ("[1.5]", "number with a fraction or exponent"),
        ("[[2e1]]", "number with a fraction or exponent"),
        ("[-0]", "-0 is not allowed"),
        ("[NaN]", "NaN is not allowed"),
        ("[-Infinity]", "-Infinity is not allowed"),
        ("[9007199254740992]", "integer out of range"),
        ("[" + "1" * 17 + "]", "integer out of range"),
        ('["' + BS + 'ud800"]', "unpaired surrogate in string"),
        ('{"' + BS + 'udc00":1}', "unpaired surrogate in member name"),
    ],
)
def test_strictify_rejects(text: str, detail: str) -> None:
    with pytest.raises(StrictJSONError) as info:
        strictify(parse_tolerant(text))
    assert info.value.detail == detail


def test_strictify_rejects_plain_python_values() -> None:
    for value in [{"a": 1}, [1], 1, 1.5]:
        with pytest.raises(TypeError):
            strictify(value)  # type: ignore[arg-type]


def test_strictify_too_deep() -> None:
    tree: TolerantValue = ()
    for _ in range(100_000):
        tree = (tree,)
    with pytest.raises(StrictJSONError, match="nesting too deep"):
        strictify(tree)


# Property 0: the two parsers agree -----------------------------------------------------

_numbers = st.sampled_from(
    [
        "0",
        "-0",
        "1",
        "-1",
        "20",
        "20.0",
        "-0.0",
        "2e1",
        "2E1",
        "1.5",
        "NaN",
        "Infinity",
        "-Infinity",
        "9007199254740991",
        "-9007199254740991",
        "9007199254740992",
        "12345678901234567",
        "1" * 5000,
    ]
) | st.integers(-(2**60), 2**60).map(str)
_strings = st.text(max_size=6).map(json.dumps) | st.sampled_from(
    [
        '"' + BS + 'ud800"',
        '"x' + BS + 'udc00"',
        '"' + BS + "ud83d" + BS + 'ude00"',
        '"' + BS + 'u0061"',
    ]
)
_keys = st.sampled_from(['"a"', '"b"', '"typ"', '"' + BS + 'u0061"', '"' + BS + 'ud800"'])
_scalars = _numbers | _strings | st.sampled_from(["true", "false", "null"])
json_texts = st.recursive(
    _scalars,
    lambda children: (
        st.lists(children, max_size=4).map(lambda items: "[" + ",".join(items) + "]")
        | st.lists(st.tuples(_keys, children), max_size=4).map(
            lambda members: "{" + ",".join(f"{k}:{v}" for k, v in members) + "}"
        )
    ),
    max_leaves=30,
)


def _assert_identical(a: object, b: object) -> None:
    assert type(a) is type(b)
    if isinstance(a, dict):
        assert isinstance(b, dict) and list(a) == list(b)
        for key in a:
            _assert_identical(a[key], b[key])
    elif isinstance(a, list):
        assert isinstance(b, list) and len(a) == len(b)
        for x, y in zip(a, b, strict=True):
            _assert_identical(x, y)
    else:
        assert a == b


@settings(max_examples=500, deadline=None)
@given(json_texts)
def test_property_0_the_two_parsers_agree(text: str) -> None:
    try:
        strict: object = parse_strict_json(text)
        strict_ok = True
    except StrictJSONError:
        strict_ok = False
    try:
        tolerant: object = strictify(parse_tolerant(text))
        tolerant_ok = True
    except StrictJSONError:
        tolerant_ok = False
    assert strict_ok == tolerant_ok
    if strict_ok:
        _assert_identical(strict, tolerant)
