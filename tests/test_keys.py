"""JWK Sets (format spec §8)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from o2a_protocol import make_jwks, parse_jwks
from o2a_protocol.keys import b64url
from o2a_protocol.testing import TEST_KID, test_signer


def good_entry(**overrides: Any) -> dict[str, Any]:
    entry = test_signer().public_jwk()
    entry.update(overrides)
    return entry


def test_round_trip_through_text_and_bytes() -> None:
    document = make_jwks({TEST_KID: test_signer().public_key()})
    raw = test_signer().public_key().public_bytes_raw()
    for data in (document, json.dumps(document), json.dumps(document).encode()):
        keys = parse_jwks(data)
        assert list(keys) == [TEST_KID]
        assert keys[TEST_KID].public_bytes_raw() == raw


def test_minimal_entry_without_use_and_alg() -> None:
    entry = {k: v for k, v in good_entry().items() if k not in {"use", "alg"}}
    assert TEST_KID in parse_jwks({"keys": [entry]})


# Malformed key sets.
def test_non_canonical_x_raises() -> None:
    x = good_entry()["x"]
    # The last character must leave its 2 unused bits zero; "B" doesn't.
    with pytest.raises(ValueError, match="x must be"):
        parse_jwks({"keys": [good_entry(x=x[:-1] + "B")]})


def test_31_byte_x_raises() -> None:
    with pytest.raises(ValueError, match="x must be"):
        parse_jwks({"keys": [good_entry(x=b64url(bytes(31)))]})


def test_duplicate_kid_raises() -> None:
    with pytest.raises(ValueError, match="duplicate kid"):
        parse_jwks({"keys": [good_entry(), good_entry()]})


def test_non_ed25519_keys_are_ignored() -> None:
    keys = parse_jwks(
        {
            "keys": [
                {"kty": "EC", "crv": "P-256", "kid": "ec-1", "x": "a", "y": "b"},
                {"kty": "OKP", "crv": "X25519", "kid": "x-1", "x": "a"},
                {"kty": "RSA", "kid": "rsa-1", "n": "a", "e": "AQAB"},
                good_entry(),
            ]
        }
    )
    assert list(keys) == [TEST_KID]


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ("{", "not valid JSON"),
        (b"[]", "must be a JSON object"),
        ({"keys": {}}, "'keys' array"),
        ({}, "'keys' array"),
        ({"keys": ["x"]}, "expected an object"),
        ({"keys": [good_entry(kid=None)]}, "kid"),
        ({"keys": [good_entry(kid="bad kid")]}, "kid"),
        ({"keys": [good_entry(d="secret")]}, "private key"),
        ({"keys": [good_entry(use="enc")]}, "use must be"),
        ({"keys": [good_entry(alg="ES256")]}, "use must be"),
        ({"keys": [good_entry(x=None)]}, "x must be"),
        ({"keys": [good_entry(x=good_entry()["x"] + "=")]}, "x must be"),
    ],
)
def test_malformed_sets_raise(document: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        parse_jwks(document)


def test_make_jwks_rejects_bad_kid() -> None:
    with pytest.raises(ValueError):
        make_jwks({"bad kid": test_signer().public_key()})
