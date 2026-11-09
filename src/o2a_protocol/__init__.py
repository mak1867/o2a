"""Reference implementation of O2A (Offers to Agents) Format v0.

See ``docs/o2a-format-v0.md``. Everything not listed in ``__all__`` is private.
"""

from .canonical import canonicalize
from .extract import ExtractionReport, extract, get_path
from .hint import parse_hint
from .ids import new_claim_token, offer_id
from .keys import ChainedKeyResolver, KeyResolver, StaticKeyResolver, make_jwks, parse_jwks
from .model import AmountOff, Merchant, Offer, PercentOff, Publisher
from .outcomes import Outcome
from .sign import Signer, SigningError
from .strictjson import parse_strict_json
from .tolerant import (
    RawNumber,
    TObject,
    TolerantJSONError,
    TolerantValue,
    parse_tolerant,
    strictify,
)
from .verify import ResponseReport, VerificationResult, Verifier

__all__ = [
    "AmountOff",
    "ChainedKeyResolver",
    "ExtractionReport",
    "KeyResolver",
    "Merchant",
    "Offer",
    "Outcome",
    "PercentOff",
    "Publisher",
    "RawNumber",
    "ResponseReport",
    "Signer",
    "SigningError",
    "StaticKeyResolver",
    "TObject",
    "TolerantJSONError",
    "TolerantValue",
    "VerificationResult",
    "Verifier",
    "canonicalize",
    "extract",
    "get_path",
    "make_jwks",
    "new_claim_token",
    "offer_id",
    "parse_hint",
    "parse_jwks",
    "parse_strict_json",
    "parse_tolerant",
    "strictify",
]
