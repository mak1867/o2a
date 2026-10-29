"""Run every committed vector (format spec §12)."""

from __future__ import annotations

import socket

import pytest

from o2a_protocol import Outcome, VerificationResult, canonicalize
from o2a_protocol.extract import Mode

from .vectors import VECTORS, VECTORS_BY_NAME, Vector, load_vectors, vector_now, vector_verifier

# Format spec §12.3.
REQUIRED_CASES = [
    "valid-percent-off",
    "valid-amount-off",
    "valid-non-ascii",
    "valid-reformatted",
    "valid-embedded",
    "tampered-terms",
    "tampered-publisher",
    "extra-member",
    "missing-member",
    "float-number",
    "control-char",
    "checkout-shaped-url",
    "expired",
    "exp-too-far",
    "unknown-typ",
    "unknown-kind",
    "untrusted-issuer",
    "unknown-kid",
    "duplicate-member",
    "escaped-duplicate-member",
    "duplicate-sponsored",
    "exponent-number",
    "negative-zero",
    "nan-number",
    "unpaired-surrogate",
    "leading-whitespace",
    "ip-hostname",
    "uppercase-scheme",
    "impossible-date",
    "escaped-equivalent",
    "decomposed-unicode",
    "noncanonical-sig-encoding",
    "unknown-version-float-in-array",
    "dup-key-in-array",
    # Locating cases (§4.1.1).
    "duplicate-sponsored-identical",
    "gateway-wrapped",
    "wrapped-in-array",
    "shallowest-wins",
    "same-depth-conflict",
    "sponsored-flags-ignored",
    "sponsored-flags-only",
    "plain-sponsored-member",
    "sponsored-object-without-typ",
    "sponsored-not-object",
    "unknown-version-candidate",
    "too-deep",
    "noise-outside-block",
    "dup-key-inside-block",
    "no-block",
    "not-json",
    "mcp-structured",
    "mcp-text",
    "mcp-both-identical",
    "mcp-mismatch",
    "mcp-jsonrpc-wrapped",
    "mcp-prose-text",
]


def run_vector(vector: Vector, data: str | bytes) -> VerificationResult | None:
    """Verify a vector's input the way its input_kind requires; None means no block."""
    verifier = vector_verifier(vector)
    kind = vector.get("input_kind", "block")
    if kind == "block":
        return verifier.verify(data, now=vector_now(vector))
    mode: Mode = "json" if kind == "response" else "mcp"
    return verifier.verify_response(data, mode=mode, now=vector_now(vector)).result


@pytest.mark.parametrize("as_bytes", [False, True], ids=["str", "bytes"])
@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_vector(vector: Vector, as_bytes: bool) -> None:
    data = vector["input"].encode("utf-8") if as_bytes else vector["input"]
    result = run_vector(vector, data)
    expected = vector["expected"]
    if expected["outcome"] == "none":
        assert result is None
        return
    assert result is not None
    assert result.outcome == expected["outcome"], result.detail
    if result.outcome is Outcome.VALID:
        assert result.offer is not None
        assert result.offer_id == expected["offer_id"]
        block = result.offer.to_block()
        body = {name: value for name, value in block.items() if name != "sig"}
        assert canonicalize(body).hex() == expected["canonical_hex"]
        assert block["sig"] == expected["sig"]
    else:
        assert result.offer is None


@pytest.mark.parametrize("vector", VECTORS, ids=lambda vector: vector["name"])
def test_detail_never_contains_claim_token(vector: Vector) -> None:
    result = run_vector(vector, vector["input"])
    assert result is None or "clm_" not in result.detail


def test_required_cases_present() -> None:
    assert sorted(set(REQUIRED_CASES) - set(VECTORS_BY_NAME)) == []


def test_vector_files_follow_the_format() -> None:
    for path, vector in load_vectors():
        assert vector["name"] == path.stem
        kind = vector.get("input_kind", "block")
        assert kind in {"block", "response", "mcp_result"}
        outcomes = set(Outcome) if kind == "block" else {*Outcome, "none"}
        assert vector["expected"]["outcome"] in outcomes
        assert 0 <= vector["skew_seconds"] <= 60
        assert kind == ("mcp_result" if vector["name"].startswith("mcp-") else kind)
        if vector["expected"]["outcome"] == "valid":
            assert {"offer_id", "canonical_hex", "sig"} <= set(vector["expected"])


def test_network_is_disabled() -> None:
    with pytest.raises(RuntimeError, match="network access is disabled"):
        socket.create_connection(("example.com", 443))
