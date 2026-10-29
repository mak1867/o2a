"""Test support: the public test key and a mock-block builder.

WARNING: the test key is the RFC 8032 §7.1 Test 1 key. Its private seed is published
in the RFC, so anyone can sign with it. Never trust ``offers.example`` or this key
outside tests.
"""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize
from .keys import StaticKeyResolver, b64url
from .sign import Signer
from .validate import TYP_V0, format_timestamp
from .verify import Verifier

TEST_SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
TEST_PUBLIC_KEY_HEX = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
TEST_ISSUER = "offers.example"
TEST_KID = "test-1"
TEST_NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=UTC)
TEST_CLAIM = "clm_3KQ2M9XR4TBV8HNE3WPA6CJD0F"


def test_signer() -> Signer:
    return Signer.from_seed(TEST_ISSUER, TEST_KID, TEST_SEED)


def test_resolver() -> StaticKeyResolver:
    return StaticKeyResolver({TEST_ISSUER: {TEST_KID: test_signer().public_key()}})


def test_verifier() -> Verifier:
    return Verifier([TEST_ISSUER], test_resolver())


# These are helpers, not tests: keep pytest from collecting them when imported.
test_signer.__test__ = False  # type: ignore[attr-defined]
test_resolver.__test__ = False  # type: ignore[attr-defined]
test_verifier.__test__ = False  # type: ignore[attr-defined]


def make_body(**overrides: Any) -> dict[str, Any]:
    """A valid unsigned body. Keyword overrides replace top-level members, unvalidated."""
    body: dict[str, Any] = {
        "typ": TYP_V0,
        "iss": TEST_ISSUER,
        "kid": TEST_KID,
        "campaign": "cmp_9x2a",
        "publisher": {"name": "DevDocs API", "domain": "devdocs.example"},
        "merchant": {"name": "Acme Mail", "url": "https://acmemail.example/pricing"},
        "product": "Transactional email API, paid plans",
        "terms": {"kind": "percent_off", "percent": 20, "duration_months": 3},
        "claim": TEST_CLAIM,
        "exp": format_timestamp(TEST_NOW + timedelta(days=14)),
    }
    body.update(copy.deepcopy(overrides))
    return body


def with_field(body: Mapping[str, Any], path: str, value: Any) -> dict[str, Any]:
    """A deep copy of ``body`` with the member at a dotted path set to ``value``."""
    result = copy.deepcopy(dict(body))
    parent, name = _parent(result, path)
    parent[name] = copy.deepcopy(value)
    return result


def without_field(body: Mapping[str, Any], path: str) -> dict[str, Any]:
    """A deep copy of ``body`` with the member at a dotted path removed."""
    result = copy.deepcopy(dict(body))
    parent, name = _parent(result, path)
    del parent[name]
    return result


def sign_unchecked(body: Mapping[str, Any]) -> dict[str, Any]:
    """Sign with the test key **without validation** (any existing ``sig`` is replaced).

    Only for building blocks that are invalid but correctly signed, to prove that
    ``malformed`` takes priority over the signature check.
    """
    unsigned = {name: value for name, value in body.items() if name != "sig"}
    signature = Ed25519PrivateKey.from_private_bytes(TEST_SEED).sign(canonicalize(unsigned))
    block = copy.deepcopy(unsigned)
    block["sig"] = b64url(signature)
    return block


def _parent(body: dict[str, Any], path: str) -> tuple[dict[str, Any], str]:
    *parents, name = path.split(".")
    node = body
    for part in parents:
        node = node[part]
    return node, name
