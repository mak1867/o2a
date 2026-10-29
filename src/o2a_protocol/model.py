"""Typed, read-only view of a verified block."""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime

from . import ids

# Guards Offer construction: only the verifier builds Offer objects.
_FROM_VERIFIER = object()


@dataclass(frozen=True, slots=True)
class Publisher:
    name: str
    domain: str


@dataclass(frozen=True, slots=True)
class Merchant:
    name: str
    url: str


@dataclass(frozen=True, slots=True)
class PercentOff:
    percent: int
    duration_months: int | None = None


@dataclass(frozen=True, slots=True)
class AmountOff:
    amount_minor: int
    currency: str
    duration_months: int | None = None


Terms = PercentOff | AmountOff


@dataclass(frozen=True)
class Offer:
    """A block that verified as ``valid``. Create one with ``Verifier.verify``."""

    typ: str
    iss: str
    kid: str
    campaign: str
    publisher: Publisher
    merchant: Merchant
    product: str
    terms: Terms
    claim: str
    exp: datetime
    sig: str
    _block: dict[str, object] = field(repr=False, compare=False)
    _origin: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._origin is not _FROM_VERIFIER:
            raise TypeError("Offer objects are created by Verifier.verify(), not directly")

    @property
    def offer_id(self) -> str:
        return ids.offer_id(self.claim)

    def to_block(self) -> dict[str, object]:
        """A deep copy of the exact block that verified, for storing and re-verifying later."""
        return copy.deepcopy(self._block)

    def __repr__(self) -> str:
        # The claim token is a bearer secret, so it is masked.
        return (
            f"Offer(offer_id={self.offer_id!r}, iss={self.iss!r}, kid={self.kid!r}, "
            f"campaign={self.campaign!r}, publisher={self.publisher!r}, "
            f"merchant={self.merchant!r}, product={self.product!r}, terms={self.terms!r}, "
            f"claim='{self.claim[:6]}…', exp={self.exp.isoformat()!r})"
        )


def offer_from_block(block: dict[str, object], exp: datetime) -> Offer:
    """Build an Offer from a block that has passed every verification step."""
    publisher = block["publisher"]
    merchant = block["merchant"]
    terms = block["terms"]
    assert isinstance(publisher, dict) and isinstance(merchant, dict) and isinstance(terms, dict)
    typed_terms: Terms
    if terms["kind"] == "percent_off":
        typed_terms = PercentOff(terms["percent"], terms.get("duration_months"))
    else:
        typed_terms = AmountOff(
            terms["amount_minor"], terms["currency"], terms.get("duration_months")
        )
    return Offer(
        typ=str(block["typ"]),
        iss=str(block["iss"]),
        kid=str(block["kid"]),
        campaign=str(block["campaign"]),
        publisher=Publisher(publisher["name"], publisher["domain"]),
        merchant=Merchant(merchant["name"], merchant["url"]),
        product=str(block["product"]),
        terms=typed_terms,
        claim=str(block["claim"]),
        exp=exp,
        sig=str(block["sig"]),
        _block=copy.deepcopy(block),
        _origin=_FROM_VERIFIER,
    )
