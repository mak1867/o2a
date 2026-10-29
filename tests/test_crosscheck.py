"""Cross-checks against independent sources (format spec §12)."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from nacl.signing import SigningKey, VerifyKey

from o2a_protocol import canonicalize, new_claim_token, offer_id
from o2a_protocol.ids import CLAIM_RE
from o2a_protocol.testing import (
    TEST_CLAIM,
    TEST_PUBLIC_KEY_HEX,
    TEST_SEED,
    make_body,
    test_signer,
)

from .vectors import VECTORS, VECTORS_BY_NAME, Vector

VALID_VECTORS = [v for v in VECTORS if v["expected"]["outcome"] == "valid"]

# JCS(make_body()), written out by hand: members sorted at every depth, no whitespace.
HAND_WRITTEN_CANONICAL = (
    b'{"campaign":"cmp_9x2a",'
    b'"claim":"clm_3KQ2M9XR4TBV8HNE3WPA6CJD0F",'
    b'"exp":"2026-11-10T12:00:00Z",'
    b'"iss":"offers.example",'
    b'"kid":"test-1",'
    b'"merchant":{"name":"Acme Mail","url":"https://acmemail.example/pricing"},'
    b'"product":"Transactional email API, paid plans",'
    b'"publisher":{"domain":"devdocs.example","name":"DevDocs API"},'
    b'"terms":{"duration_months":3,"kind":"percent_off","percent":20},'
    b'"typ":"o2a-sponsored-offer/v0"}'
)


@pytest.mark.parametrize("vector", VALID_VECTORS, ids=lambda vector: vector["name"])
def test_pynacl_verifies_every_valid_vector(vector: Vector) -> None:
    """libsodium (PyNaCl) must agree with OpenSSL (cryptography) on every valid vector."""
    message = bytes.fromhex(vector["expected"]["canonical_hex"])
    signature = base64.urlsafe_b64decode(vector["expected"]["sig"] + "==")
    VerifyKey(bytes.fromhex(TEST_PUBLIC_KEY_HEX)).verify(message, signature)
    # Ed25519 is deterministic, so libsodium must also produce the identical signature.
    assert SigningKey(TEST_SEED).sign(message).signature == signature


def test_canonical_bytes_match_hand_written_literal() -> None:
    assert canonicalize(make_body()) == HAND_WRITTEN_CANONICAL
    vector = VECTORS_BY_NAME["valid-percent-off"]
    assert bytes.fromhex(vector["expected"]["canonical_hex"]) == HAND_WRITTEN_CANONICAL


def test_test_seed_produces_test_public_key() -> None:
    public = test_signer().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    assert public.hex() == TEST_PUBLIC_KEY_HEX
    assert bytes(SigningKey(TEST_SEED).verify_key).hex() == TEST_PUBLIC_KEY_HEX


def test_new_claim_tokens_match_regex_and_are_distinct() -> None:
    tokens = [new_claim_token() for _ in range(10_000)]
    assert all(CLAIM_RE.fullmatch(token) for token in tokens)
    assert len(set(tokens)) == len(tokens)


def test_offer_id_hand_computed() -> None:
    # printf '%s' clm_3KQ2M9XR4TBV8HNE3WPA6CJD0F | shasum -a 256 | cut -c1-24
    assert offer_id(TEST_CLAIM) == "off_a33e5dd43a75be430b008d47"


@pytest.mark.parametrize("claim", ["clm_bad", TEST_CLAIM.lower(), 42, None])
def test_offer_id_rejects_malformed_claims(claim: object) -> None:
    with pytest.raises(ValueError):
        offer_id(claim)  # type: ignore[arg-type]
