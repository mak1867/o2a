"""Claim tokens and offer IDs (format spec §4.5)."""

from __future__ import annotations

import hashlib
import re
import secrets

CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
CLAIM_RE = re.compile(r"clm_[0-7][0-9A-HJKMNP-TV-Z]{25}")


def new_claim_token() -> str:
    """Generate a claim token from 128 bits of secure randomness."""
    n = int.from_bytes(secrets.token_bytes(16), "big")
    # 26 characters x 5 bits = 130 bits; the 2 leading bits are zero, so the
    # first character is always 0-7.
    chars = []
    for _ in range(26):
        chars.append(CROCKFORD_ALPHABET[n & 31])
        n >>= 5
    return "clm_" + "".join(reversed(chars))


def offer_id(claim: str) -> str:
    """Derive the offer ID for a claim token. Raises ``ValueError`` for a malformed token."""
    if not isinstance(claim, str) or not CLAIM_RE.fullmatch(claim):
        raise ValueError("not a well-formed claim token")
    return "off_" + hashlib.sha256(claim.encode("ascii")).hexdigest()[:24]
