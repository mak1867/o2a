"""The Signer (format spec §6.4) and the Python-type traps it must refuse."""

from __future__ import annotations

import copy
from collections import OrderedDict
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import IntEnum, StrEnum
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from o2a_protocol import Outcome, Signer, SigningError, parse_jwks
from o2a_protocol.testing import (
    TEST_ISSUER,
    TEST_KID,
    TEST_NOW,
    TEST_SEED,
    make_body,
    test_signer,
    test_verifier,
    with_field,
    without_field,
)
from o2a_protocol.validate import format_timestamp


class Percent(IntEnum):
    TWENTY = 20


class Currency(StrEnum):
    USD = "USD"


class MyStr(str):
    pass


class MyInt(int):
    pass


def sign(body: dict[str, Any]) -> dict[str, object]:
    return test_signer().sign(body, now=TEST_NOW)


def test_sign_then_verify() -> None:
    block = sign(make_body())
    assert test_verifier().verify_parsed(block, now=TEST_NOW).outcome is Outcome.VALID


# bool is an int in Python.
@pytest.mark.parametrize("path", ["terms.percent", "terms.duration_months"])
@pytest.mark.parametrize("value", [True, False])
def test_bool_for_int(path: str, value: bool) -> None:
    with pytest.raises(SigningError):
        sign(with_field(make_body(), path, value))
    block = sign(make_body())
    tampered = with_field(block, path, value)
    assert test_verifier().verify_parsed(tampered, now=TEST_NOW).outcome is Outcome.MALFORMED


# Enums and subclasses.
@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("terms.percent", Percent.TWENTY),
        ("terms.percent", MyInt(20)),
        ("product", MyStr("Transactional email API, paid plans")),
        ("typ", MyStr("o2a-sponsored-offer/v0")),
        ("publisher", OrderedDict(name="DevDocs API", domain="devdocs.example")),
    ],
)
def test_enum_and_subclass_values(path: str, value: object) -> None:
    with pytest.raises(SigningError):
        sign(with_field(make_body(), path, value))


def test_str_enum_currency() -> None:
    body = make_body(terms={"kind": "amount_off", "amount_minor": 500, "currency": Currency.USD})
    with pytest.raises(SigningError):
        sign(body)


# None, arrays, float, Decimal, datetime.
@pytest.mark.parametrize(
    ("path", "value"),
    [
        ("terms.duration_months", None),
        ("campaign", ["cmp_9x2a"]),
        ("campaign", ("cmp_9x2a",)),
        ("terms.percent", 20.0),
        ("terms.percent", Decimal(20)),
        ("exp", TEST_NOW + timedelta(days=1)),
    ],
)
def test_non_json_types(path: str, value: object) -> None:
    with pytest.raises(SigningError):
        sign(with_field(make_body(), path, value))


def test_non_string_member_name() -> None:
    body: dict[Any, Any] = make_body()
    body[1] = "x"
    with pytest.raises(SigningError, match="member names"):
        sign(body)


# A naive now.
def test_naive_now_is_a_programmer_error() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        test_signer().sign(make_body(), now=datetime(2026, 10, 27, 12))
    with pytest.raises(TypeError):
        test_signer().sign(make_body(), now="2026-10-27T12:00:00Z")  # type: ignore[arg-type]


# No mutation.
def test_sign_does_not_mutate_input() -> None:
    body = make_body()
    before = copy.deepcopy(body)
    block = sign(body)
    assert body == before
    assert "sig" not in body
    publisher = block["publisher"]
    assert isinstance(publisher, dict)
    publisher["name"] = "Changed"
    assert body == before


def test_sign_accepts_any_mapping_at_top_level() -> None:
    from types import MappingProxyType

    assert "sig" in test_signer().sign(MappingProxyType(make_body()), now=TEST_NOW)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        (make_body(sig="A" * 86), "must not contain sig"),
        (make_body(iss="other.example"), "iss and kid"),
        (make_body(kid="test-2"), "iss and kid"),
        (make_body(terms={"kind": "free_units", "units": 1}), "unsupported"),
        (without_field(make_body(), "product"), "malformed"),
        (make_body(exp=format_timestamp(TEST_NOW)), "after now"),
        (make_body(exp=format_timestamp(TEST_NOW - timedelta(days=1))), "after now"),
        (
            make_body(exp=format_timestamp(TEST_NOW + timedelta(days=30, seconds=1))),
            "30 days",
        ),
    ],
)
def test_sign_refuses(body: dict[str, Any], message: str) -> None:
    with pytest.raises(SigningError, match=message):
        sign(body)


def test_sign_refuses_non_mapping() -> None:
    with pytest.raises(SigningError, match="mapping"):
        test_signer().sign([("typ", "x")], now=TEST_NOW)  # type: ignore[arg-type]


def test_exp_exactly_30_days_is_allowed() -> None:
    sign(make_body(exp=format_timestamp(TEST_NOW + timedelta(days=30))))


def test_default_now_is_current_time() -> None:
    soon = datetime.now(UTC).replace(microsecond=0) + timedelta(days=1)
    block = test_signer().sign(make_body(exp=format_timestamp(soon)))
    assert test_verifier().verify_parsed(block).outcome is Outcome.VALID


@pytest.mark.parametrize(
    ("iss", "kid", "error"),
    [
        ("Offers.Example", TEST_KID, ValueError),
        ("offers", TEST_KID, ValueError),
        (TEST_ISSUER, "", ValueError),
        (TEST_ISSUER, "a" * 65, ValueError),
    ],
)
def test_signer_constructor_validates(iss: str, kid: str, error: type[Exception]) -> None:
    with pytest.raises(error):
        Signer(iss, kid, Ed25519PrivateKey.from_private_bytes(TEST_SEED))


def test_signer_rejects_wrong_key_type() -> None:
    with pytest.raises(TypeError):
        Signer(TEST_ISSUER, TEST_KID, TEST_SEED)  # type: ignore[arg-type]


@pytest.mark.parametrize("seed", [TEST_SEED[:31], TEST_SEED + b"\x00", TEST_SEED.hex()])
def test_from_seed_requires_32_bytes(seed: object) -> None:
    with pytest.raises(ValueError):
        Signer.from_seed(TEST_ISSUER, TEST_KID, seed)  # type: ignore[arg-type]


def test_public_jwk_round_trips() -> None:
    jwk = test_signer().public_jwk()
    assert jwk["kid"] == TEST_KID and jwk["use"] == "sig" and jwk["alg"] == "EdDSA"
    keys = parse_jwks({"keys": [jwk]})
    assert keys[TEST_KID].public_bytes_raw() == test_signer().public_key().public_bytes_raw()
