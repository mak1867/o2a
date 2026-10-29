"""The Verifier, VerificationResult and Offer (format spec §7)."""

from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
import rfc8785

import o2a_protocol.verify as verify_module
from o2a_protocol import (
    AmountOff,
    Merchant,
    Offer,
    Outcome,
    PercentOff,
    Publisher,
    StaticKeyResolver,
    Verifier,
)
from o2a_protocol.testing import (
    TEST_CLAIM,
    TEST_ISSUER,
    TEST_NOW,
    make_body,
    sign_unchecked,
    test_resolver,
    test_signer,
    test_verifier,
    with_field,
)


def signed(**overrides: Any) -> dict[str, object]:
    return test_signer().sign(make_body(**overrides), now=TEST_NOW)


def test_valid_offer_fields() -> None:
    result = test_verifier().verify(json.dumps(signed()), now=TEST_NOW)
    offer = result.offer
    assert offer is not None
    assert offer.typ == "o2a-sponsored-offer/v0"
    assert offer.iss == TEST_ISSUER
    assert offer.publisher == Publisher("DevDocs API", "devdocs.example")
    assert offer.merchant == Merchant("Acme Mail", "https://acmemail.example/pricing")
    assert offer.terms == PercentOff(20, 3)
    assert offer.claim == TEST_CLAIM
    assert offer.exp == datetime(2026, 11, 10, 12, tzinfo=UTC)
    assert offer.offer_id == result.offer_id == "off_a33e5dd43a75be430b008d47"
    assert result.detail == "valid"


def test_amount_off_without_duration() -> None:
    block = signed(terms={"kind": "amount_off", "amount_minor": 500, "currency": "USD"})
    offer = test_verifier().verify_parsed(block, now=TEST_NOW).offer
    assert offer is not None
    assert offer.terms == AmountOff(500, "USD", None)


def test_offer_repr_masks_claim() -> None:
    offer = test_verifier().verify_parsed(signed(), now=TEST_NOW).offer
    assert TEST_CLAIM not in repr(offer)
    assert "clm_3K…" in repr(offer)


def test_offers_are_created_only_by_the_verifier() -> None:
    offer = test_verifier().verify_parsed(signed(), now=TEST_NOW).offer
    assert offer is not None
    fields = {f.name: getattr(offer, f.name) for f in dataclasses.fields(offer)}
    fields.pop("_origin")
    with pytest.raises(TypeError, match="Verifier"):
        Offer(**fields)


# to_block is a deep copy.
def test_to_block_is_a_deep_copy() -> None:
    block = signed()
    offer = test_verifier().verify_parsed(block, now=TEST_NOW).offer
    assert offer is not None
    first = offer.to_block()
    assert first == block
    publisher = first["publisher"]
    assert isinstance(publisher, dict)
    publisher["name"] = "Changed"
    block["product"] = "Changed"
    assert offer.to_block() == signed()
    assert test_verifier().verify_parsed(offer.to_block(), now=TEST_NOW).outcome is Outcome.VALID


def test_offers_compare_and_hash() -> None:
    a = test_verifier().verify_parsed(signed(), now=TEST_NOW).offer
    b = test_verifier().verify_parsed(signed(), now=TEST_NOW).offer
    assert a == b and hash(a) == hash(b)


def test_offer_id_reported_on_failure() -> None:
    block = with_field(signed(), "terms.percent", 25)
    result = test_verifier().verify_parsed(block, now=TEST_NOW)
    assert result.outcome is Outcome.BAD_SIGNATURE
    assert result.offer_id == "off_a33e5dd43a75be430b008d47"
    assert result.offer is None


@pytest.mark.parametrize("value", [None, [], "text", {"claim": "clm_bad"}, {"claim": 5}])
def test_offer_id_absent_without_well_formed_claim(value: object) -> None:
    assert test_verifier().verify_parsed(value, now=TEST_NOW).offer_id is None


def test_canonicalization_failure_is_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(body: object) -> bytes:
        raise rfc8785.CanonicalizationError("boom")

    monkeypatch.setattr(verify_module, "canonicalize", fail)
    result = test_verifier().verify_parsed(signed(), now=TEST_NOW)
    assert result.outcome is Outcome.MALFORMED


def test_default_now_uses_current_time() -> None:
    soon = datetime.now(UTC).replace(microsecond=0) + timedelta(hours=1)
    block = sign_unchecked(make_body(exp=soon.strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert test_verifier().verify(json.dumps(block)).outcome is Outcome.VALID


# A naive now and wrong argument types are programmer errors.
def test_naive_now_raises() -> None:
    naive = datetime(2026, 10, 27, 12)
    with pytest.raises(ValueError):
        test_verifier().verify("{}", now=naive)
    with pytest.raises(ValueError):
        test_verifier().verify_parsed({}, now=naive)
    with pytest.raises(TypeError):
        test_verifier().verify("{}", now=1)  # type: ignore[arg-type]


@pytest.mark.parametrize("block", [{}, None, 42, bytearray(b"{}")])
def test_verify_rejects_non_text(block: object) -> None:
    with pytest.raises(TypeError):
        test_verifier().verify(block, now=TEST_NOW)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("kwargs", "error"),
    [
        ({"trusted_issuers": TEST_ISSUER}, TypeError),
        ({"trusted_issuers": ["Offers.Example"]}, ValueError),
        ({"trusted_issuers": ["localhost"]}, ValueError),
        ({"skew": timedelta(seconds=61)}, ValueError),
        ({"skew": timedelta(seconds=-1)}, ValueError),
        ({"skew": 60}, ValueError),
        ({"max_lifetime": timedelta(0)}, ValueError),
        ({"max_lifetime": timedelta(days=31)}, ValueError),
        ({"max_lifetime": 30}, ValueError),
    ],
)
def test_verifier_constructor_validates(kwargs: dict[str, Any], error: type[Exception]) -> None:
    args: dict[str, Any] = {"trusted_issuers": [TEST_ISSUER], "keys": test_resolver(), **kwargs}
    with pytest.raises(error):
        Verifier(**args)


def test_shorter_max_lifetime() -> None:
    verifier = Verifier([TEST_ISSUER], test_resolver(), max_lifetime=timedelta(days=7))
    assert verifier.verify_parsed(signed(), now=TEST_NOW).outcome is Outcome.MALFORMED


def test_zero_skew() -> None:
    verifier = Verifier([TEST_ISSUER], test_resolver(), skew=timedelta(0))
    exp = datetime(2026, 11, 10, 12, tzinfo=UTC)
    block = signed()
    assert verifier.verify_parsed(block, now=exp - timedelta(seconds=1)).outcome is Outcome.VALID
    assert verifier.verify_parsed(block, now=exp).outcome is Outcome.EXPIRED


def test_static_resolver_unknown_issuer_and_kid() -> None:
    resolver = test_resolver()
    assert resolver.get("other.example", "test-1") is None
    assert resolver.get(TEST_ISSUER, "test-2") is None
    assert resolver.get(TEST_ISSUER, "test-1") is not None


def test_static_resolver_copies_its_input() -> None:
    keys = {TEST_ISSUER: {"test-1": test_signer().public_key()}}
    resolver = StaticKeyResolver(keys)
    keys[TEST_ISSUER].clear()
    assert resolver.get(TEST_ISSUER, "test-1") is not None
