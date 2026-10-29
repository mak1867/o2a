"""Validation rules not already pinned down by a vector (format spec §4, §5)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest

from o2a_protocol import Outcome
from o2a_protocol.testing import (
    TEST_NOW,
    make_body,
    test_signer,
    test_verifier,
    with_field,
    without_field,
)
from o2a_protocol.validate import (
    format_timestamp,
    is_hostname,
    is_url,
    parse_timestamp,
    validate_block,
    validate_body,
)

BLOCK = test_signer().sign(make_body(), now=TEST_NOW)


def check(block: Any) -> tuple[Outcome, str]:
    result = test_verifier().verify_parsed(block, now=TEST_NOW)
    return result.outcome, result.detail


@pytest.mark.parametrize(
    ("path", "value", "detail"),
    [
        ("kid", "bad kid", "kid: expected"),
        ("campaign", "", "campaign: expected"),
        ("campaign", "c" * 65, "campaign: expected"),
        ("publisher", "DevDocs", "publisher: expected an object"),
        ("publisher.name", "", "publisher.name: expected"),
        ("publisher.logo", "x", "publisher: unexpected member logo"),
        ("merchant", "Acme", "merchant: expected an object"),
        ("merchant.logo", "x", "merchant: unexpected member logo"),
        ("merchant.name", "m" * 81, "merchant.name: expected"),
        ("product", "p" * 81, "product: expected"),
        ("terms", "20%", "terms: expected an object"),
        ("terms", {}, "terms.kind: missing member"),
        ("terms", {"kind": 5}, "terms.kind: expected a string"),
        ("terms", {"kind": "percent_off"}, "terms: missing member percent"),
        ("terms", {"kind": "percent_off", "percent": 5, "x": 1}, "terms: unexpected member x"),
        ("terms.percent", 0, "terms.percent: expected"),
        ("terms.percent", 101, "terms.percent: expected"),
        ("terms.duration_months", 0, "terms.duration_months: expected"),
        ("terms.duration_months", 37, "terms.duration_months: expected"),
        ("terms", {"kind": "amount_off", "amount_minor": 0, "currency": "USD"}, "amount_minor"),
        (
            "terms",
            {"kind": "amount_off", "amount_minor": 1_000_000_001, "currency": "USD"},
            "amount_minor",
        ),
        ("terms", {"kind": "amount_off", "amount_minor": 5, "currency": "US"}, "currency"),
        ("terms", {"kind": "free_units", "units": 2**60}, "integer out of range"),
        ("terms.percent", 1.5, "non-integer number is not allowed"),
        ("terms.percent", None, "null is not allowed"),
        ("terms.percent", True, "boolean is not allowed"),
        ("terms.percent", (20,), "array is not allowed"),
        ("terms.percent", object(), "value of type object is not allowed"),
        ("sig", 5, "sig: expected"),
        ("exp", 5, "exp: expected"),
        ("claim", 5, "claim: expected"),
    ],
)
def test_malformed_fields(path: str, value: object, detail: str) -> None:
    outcome, message = check(with_field(BLOCK, path, value))
    assert outcome is Outcome.MALFORMED
    assert detail in message


def test_missing_nested_member() -> None:
    assert check(without_field(BLOCK, "publisher.domain")) == (
        Outcome.MALFORMED,
        "publisher: missing member domain",
    )


def test_non_string_member_name() -> None:
    block: dict[Any, Any] = dict(BLOCK)
    block[1] = "x"
    assert check(block) == (Outcome.MALFORMED, "block: member names must be strings")


def test_member_name_breaking_string_rules() -> None:
    outcome, detail = check(with_field(BLOCK, "terms", {"kind": "free_units", " units": 1}))
    assert outcome is Outcome.MALFORMED
    assert detail == "terms: member name begins or ends with white space"


def test_unknown_names_are_escaped_and_truncated_in_details() -> None:
    name = "bad name " + "x" * 40
    outcome, detail = check({**BLOCK, name: "x"})
    assert outcome is Outcome.MALFORMED
    assert "…" in detail and name not in detail
    outcome, detail = check(with_field(BLOCK, "terms", {"kind": "Free Units"}))
    assert outcome is Outcome.UNSUPPORTED
    assert detail == "terms.kind: unsupported kind 'Free Units'"


def test_paths_with_unusual_keys_are_escaped() -> None:
    terms = {"kind": "free_units", "odd key": {"inner": None}}
    outcome, detail = check(with_field(BLOCK, "terms", terms))
    assert outcome is Outcome.MALFORMED
    assert detail == "terms.'odd key'.inner: null is not allowed"


@pytest.mark.parametrize(
    ("value", "detail"),
    [
        ([], "not a JSON object"),
        ("{}", "not a JSON object"),
        ({}, "typ: missing or not a string"),
        ({"typ": 0}, "typ: missing or not a string"),
        ({"typ": "o2a-sponsored-offer/v1"}, "typ: unsupported block type"),
    ],
)
def test_unsupported(value: object, detail: str) -> None:
    assert check(value) == (Outcome.UNSUPPORTED, detail)


def test_validate_body_and_block_differ_only_in_sig() -> None:
    body = make_body()
    assert validate_body(body) is None
    assert validate_block(body) == (Outcome.MALFORMED, "block: missing member sig")
    assert validate_block(BLOCK) is None
    assert validate_body(BLOCK) == (Outcome.MALFORMED, "block: unexpected member sig")


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("a.b", True),
        ("xn--bcher-kva.example", True),
        ("a1.b2c", True),
        ("a.123", False),
        (5, False),
        ("", False),
        ("a." + "b" * 63 + "." + "c" * 63 + "." + "d" * 63 + "." + "e" * 61, False),
        ("a.B", False),
    ],
)
def test_is_hostname(value: object, ok: bool) -> None:
    assert is_hostname(value) is ok


def test_hostname_length_limit() -> None:
    labels = ["a" * 63] * 3 + ["b" * 61]
    assert len(".".join(labels)) == 253 and is_hostname(".".join(labels))
    assert not is_hostname(".".join(labels) + "b")


@pytest.mark.parametrize(
    ("value", "ok"),
    [
        ("https://a.example", True),
        ("https://a.example?q=1", True),
        ("https://a.example#top", True),
        ("https://a.example/%20x", True),
        ("https://a.example/%2", False),
        ("https://", False),
        ("https://a.example/<x>", False),
        (5, False),
    ],
)
def test_is_url(value: object, ok: bool) -> None:
    assert is_url(value) is ok


@pytest.mark.parametrize(
    "value",
    [
        5,
        "0000-01-01T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-1-01T00:00:00Z",
        "2026-01-01T00:00:00Z\n",
    ],
)
def test_parse_timestamp_rejects(value: object) -> None:
    assert parse_timestamp(value) is None


def test_parse_timestamp_rejects_non_ascii_digits() -> None:
    arabic_three = chr(0x663)
    assert parse_timestamp("202" + arabic_three + "-01-01T00:00:00Z") is None


def test_parse_timestamp_accepts_leap_day() -> None:
    assert parse_timestamp("2028-02-29T23:59:59Z") == datetime(2028, 2, 29, 23, 59, 59, tzinfo=UTC)


def test_format_timestamp() -> None:
    assert format_timestamp(TEST_NOW) == "2026-10-27T12:00:00Z"
    plus_two = TEST_NOW.astimezone(timezone(timedelta(hours=2)))
    assert format_timestamp(plus_two) == "2026-10-27T12:00:00Z"
    assert format_timestamp(datetime(5, 1, 2, 3, 4, 5, tzinfo=UTC)) == "0005-01-02T03:04:05Z"
    with pytest.raises(ValueError, match="timezone-aware"):
        format_timestamp(datetime(2026, 1, 1))
    with pytest.raises(ValueError, match="whole seconds"):
        format_timestamp(TEST_NOW.replace(microsecond=1))
