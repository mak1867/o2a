"""Verification (format spec §7)."""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta

import rfc8785
from cryptography.exceptions import InvalidSignature

from .canonical import canonicalize
from .extract import Mode, Status, extract
from .ids import CLAIM_RE, offer_id
from .keys import KeyResolver
from .model import Offer, offer_from_block
from .outcomes import Outcome
from .sign import MAX_LIFETIME, resolve_now
from .strictjson import StrictJSONError, parse_strict_json
from .tolerant import TolerantValue
from .validate import is_hostname, parse_timestamp, validate_block

MAX_SKEW = timedelta(seconds=60)


@dataclass(frozen=True)
class VerificationResult:
    """The outcome of verifying one block.

    ``detail`` is safe to log and never contains the claim token. ``offer`` is set only
    when the outcome is ``VALID``. ``offer_id`` is set whenever the input had a
    well-formed claim token, whatever the outcome, so failures can be logged by ID.
    """

    outcome: Outcome
    detail: str
    offer: Offer | None = None
    offer_id: str | None = None


@dataclass(frozen=True)
class ResponseReport:
    """The result of ``Verifier.verify_response``.

    ``result`` is ``None`` when the response carries no block (status ``none``) or isn't
    JSON (``not_json``). ``status`` and ``locations`` come from ``extract``.
    """

    result: VerificationResult | None
    status: Status
    locations: tuple[str, ...]


class Verifier:
    """Runs format spec §7 against a fixed set of trusted issuers."""

    def __init__(
        self,
        trusted_issuers: Iterable[str],
        keys: KeyResolver,
        *,
        skew: timedelta = MAX_SKEW,
        max_lifetime: timedelta = MAX_LIFETIME,
    ) -> None:
        if isinstance(trusted_issuers, str):
            raise TypeError("trusted_issuers must be a collection of hostnames, not one string")
        issuers = frozenset(trusted_issuers)
        for iss in issuers:
            if not is_hostname(iss):
                raise ValueError(f"trusted issuer {iss!r} is not a hostname")
        if not isinstance(skew, timedelta) or not timedelta(0) <= skew <= MAX_SKEW:
            raise ValueError("skew must be a timedelta between 0 and 60 seconds")
        if (
            not isinstance(max_lifetime, timedelta)
            or not timedelta(0) < max_lifetime <= MAX_LIFETIME
        ):
            raise ValueError("max_lifetime must be a timedelta above 0 and at most 30 days")
        self._trusted = issuers
        self._keys = keys
        self._skew = skew
        self._max_lifetime = max_lifetime

    def verify(self, block: str | bytes, *, now: datetime | None = None) -> VerificationResult:
        """Verify a block given as raw JSON text. Never raises for invalid input."""
        now = resolve_now(now)
        if not isinstance(block, str | bytes):
            raise TypeError(f"block must be str or bytes, got {type(block).__name__}")
        try:
            value = parse_strict_json(block)
        except StrictJSONError as exc:
            return VerificationResult(Outcome.MALFORMED, exc.detail)
        return self._verify_value(value, now)

    def verify_parsed(self, block: object, *, now: datetime | None = None) -> VerificationResult:
        """Verify a block that was already parsed **with** ``parse_strict_json``.

        Warning: a value parsed any other way (for example with ``json.loads``) may
        already have lost duplicate member names or ``-0``, so a block that should be
        ``malformed`` could pass. Always parse with ``parse_strict_json`` first.
        """
        return self._verify_value(block, resolve_now(now))

    def verify_response(
        self,
        data: str | bytes | TolerantValue,
        *,
        mode: Mode = "auto",
        now: datetime | None = None,
    ) -> ResponseReport:
        """Locate the block in a whole response or MCP result (format spec §4.1.1), then verify it.

        Never raises on bad content. See ``extract`` for ``mode`` and accepted inputs.
        """
        now = resolve_now(now)
        report = extract(data, mode=mode)
        result: VerificationResult | None = None
        if report.status == "conflict":
            result = VerificationResult(
                Outcome.MALFORMED, f"multiple distinct blocks at depth {report.depth}"
            )
        elif report.status == "found":
            if report.error is not None:
                result = VerificationResult(Outcome.MALFORMED, report.error)
            else:
                result = self._verify_value(report.value, now)
        return ResponseReport(result, report.status, report.locations)

    def _verify_value(self, value: object, now: datetime) -> VerificationResult:
        oid = _offer_id_if_present(value)

        # Steps 1-3: type, structure and values.
        problem = validate_block(value)
        if problem is not None:
            return VerificationResult(problem[0], problem[1], offer_id=oid)
        assert isinstance(value, dict)
        iss, kid, sig, exp_text = value["iss"], value["kid"], value["sig"], value["exp"]
        assert isinstance(iss, str) and isinstance(kid, str) and isinstance(sig, str)

        # Step 4: trusted issuer.
        if iss not in self._trusted:
            return VerificationResult(Outcome.UNTRUSTED_ISSUER, "iss is not trusted", offer_id=oid)

        # Step 5: key.
        key = self._keys.get(iss, kid)
        if key is None:
            return VerificationResult(
                Outcome.UNKNOWN_KEY, "no key with this kid for the issuer", offer_id=oid
            )

        # Step 6: signature over JCS(body).
        body = {name: member for name, member in value.items() if name != "sig"}
        try:
            message = canonicalize(body)
        except rfc8785.CanonicalizationError:
            return VerificationResult(
                Outcome.MALFORMED, "body cannot be canonicalized", offer_id=oid
            )
        try:
            key.verify(base64.urlsafe_b64decode(sig + "=="), message)
        except InvalidSignature:
            return VerificationResult(
                Outcome.BAD_SIGNATURE, "signature does not verify", offer_id=oid
            )

        # Step 7: expiry. Equality counts as expired.
        exp = parse_timestamp(exp_text)
        assert exp is not None
        if now - self._skew >= exp:
            return VerificationResult(Outcome.EXPIRED, "block has expired", offer_id=oid)

        # Step 8: lifetime cap.
        if exp > now + self._max_lifetime + self._skew:
            return VerificationResult(
                Outcome.MALFORMED, "exp is more than 30 days in the future", offer_id=oid
            )

        return VerificationResult(
            Outcome.VALID, "valid", offer=offer_from_block(value, exp), offer_id=oid
        )


def _offer_id_if_present(value: object) -> str | None:
    if type(value) is not dict:
        return None
    claim = value.get("claim")
    if type(claim) is str and CLAIM_RE.fullmatch(claim):
        return offer_id(claim)
    return None
