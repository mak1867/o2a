"""The claim client (format spec §9).

Needs the ``[http]`` extra: ``pip install 'o2a-protocol[http]'``.

The claim token and the promo code are secrets: neither ever appears in an exception
message or a ``repr``.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from importlib import metadata

try:
    import httpx
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "o2a_protocol.claims needs the [http] extra: pip install 'o2a-protocol[http]'"
    ) from exc

from .model import Offer
from .sign import resolve_now
from .strictjson import StrictJSONError, parse_strict_json
from .validate import is_hostname, parse_timestamp

__all__ = ["ClaimClient", "ClaimError", "ClaimErrorKind", "ClaimResult"]

_BACKOFF = (0.5, 1.0)
_EMAIL_FORBIDDEN = re.compile(r"[\s\x00-\x1f\x7f-\x9f]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SUCCESS_MEMBERS = frozenset({"offer_id", "code", "exp"})


class ClaimErrorKind(StrEnum):
    # Format spec §9.4 error codes.
    MALFORMED_REQUEST = "malformed_request"
    BUYER_REQUIRED = "buyer_required"
    UNKNOWN_CLAIM = "unknown_claim"
    CAMPAIGN_LIMIT_REACHED = "campaign_limit_reached"
    EXPIRED = "expired"
    ALREADY_CLAIMED = "already_claimed"
    OFFER_UNAVAILABLE = "offer_unavailable"
    RATE_LIMITED = "rate_limited"
    # Client-side kinds.
    UNTRUSTED_ISSUER = "untrusted_issuer"
    NETWORK_ERROR = "network_error"
    PROTOCOL_ERROR = "protocol_error"


# The documented (status, error) pairs.
_DOCUMENTED: dict[int, frozenset[ClaimErrorKind]] = {
    400: frozenset({ClaimErrorKind.MALFORMED_REQUEST, ClaimErrorKind.BUYER_REQUIRED}),
    404: frozenset({ClaimErrorKind.UNKNOWN_CLAIM}),
    409: frozenset({ClaimErrorKind.CAMPAIGN_LIMIT_REACHED}),
    410: frozenset(
        {ClaimErrorKind.EXPIRED, ClaimErrorKind.ALREADY_CLAIMED, ClaimErrorKind.OFFER_UNAVAILABLE}
    ),
    429: frozenset({ClaimErrorKind.RATE_LIMITED}),
}


class ClaimError(Exception):
    """A claim that didn't produce a code. ``kind`` says why; ``detail`` is safe to log."""

    def __init__(
        self,
        kind: ClaimErrorKind,
        detail: str,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail
        self.status = status
        self.retry_after = retry_after


@dataclass(frozen=True)
class ClaimResult:
    """A promo code for an offer. ``code`` is opaque: enter it at checkout exactly as given."""

    offer_id: str
    code: str = field(repr=False)
    exp: datetime

    def __repr__(self) -> str:
        return (
            f"ClaimResult(offer_id={self.offer_id!r}, code=<masked>, exp={self.exp.isoformat()!r})"
        )


class ClaimClient:
    """Exchanges a verified offer's claim token for a promo code (``POST /v0/claims``)."""

    def __init__(
        self,
        trusted_issuers: Iterable[str],
        *,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
        max_retries: int = 2,
        max_retry_after: timedelta = timedelta(seconds=30),
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if isinstance(trusted_issuers, str):
            raise TypeError("trusted_issuers must be a collection of hostnames, not one string")
        self._trusted = frozenset(trusted_issuers)
        for iss in self._trusted:
            if not is_hostname(iss):
                raise ValueError(f"trusted issuer {iss!r} is not a hostname")
        if type(max_retries) is not int or max_retries < 0:
            raise ValueError("max_retries must be a non-negative int")
        if not isinstance(max_retry_after, timedelta) or max_retry_after < timedelta(0):
            raise ValueError("max_retry_after must be a non-negative timedelta")
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)
        self._max_retries = max_retries
        self._max_retry_after = max_retry_after.total_seconds()
        self._sleep = sleep
        self._clock = clock
        try:
            version = metadata.version("o2a-protocol")
        except metadata.PackageNotFoundError:  # pragma: no cover - only in an uninstalled tree
            version = "0"
        self._user_agent = f"o2a-protocol-python/{version}"

    def claim(
        self, offer: Offer, *, buyer_email: str | None = None, now: datetime | None = None
    ) -> ClaimResult:
        """Claim a verified offer. Raises ``ClaimError`` if no code was issued.

        Call this only once a purchase has been decided (format spec §9.3).
        """
        if not isinstance(offer, Offer):
            raise TypeError("claim() takes a verified Offer from Verifier.verify()")
        if offer.iss not in self._trusted:
            raise ClaimError(ClaimErrorKind.UNTRUSTED_ISSUER, "the offer's issuer is not trusted")
        now = resolve_now(self._clock() if now is None else now)
        if now >= offer.exp:
            raise ClaimError(ClaimErrorKind.EXPIRED, "the offer has expired")
        body: dict[str, object] = {"claim": offer.claim}
        if buyer_email is not None:
            if not _plausible_email(buyer_email):
                raise ClaimError(ClaimErrorKind.MALFORMED_REQUEST, "buyer_email is not an email")
            body["buyer"] = {"email": buyer_email}
        return self._send(offer, json.dumps(body).encode())

    def close(self) -> None:
        """Close the HTTP client if this claim client created it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> ClaimClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _send(self, offer: Offer, content: bytes) -> ClaimResult:
        url = f"https://{offer.iss}/v0/claims"
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": self._user_agent,
        }
        attempt = 0
        while True:
            try:
                response = self._client.post(
                    url, content=content, headers=headers, follow_redirects=False
                )
            except httpx.TransportError:
                if attempt < self._max_retries:
                    self._sleep(_BACKOFF[min(attempt, len(_BACKOFF) - 1)])
                    attempt += 1
                    continue
                raise ClaimError(
                    ClaimErrorKind.NETWORK_ERROR, "could not reach the issuer"
                ) from None

            status = response.status_code
            if status >= 500:
                if attempt < self._max_retries:
                    self._sleep(_BACKOFF[min(attempt, len(_BACKOFF) - 1)])
                    attempt += 1
                    continue
                raise ClaimError(ClaimErrorKind.PROTOCOL_ERROR, "issuer server error", status)
            if status == 429:
                retry_after = _retry_after(response.headers.get("retry-after"))
                if (
                    retry_after is not None
                    and retry_after <= self._max_retry_after
                    and attempt < self._max_retries
                ):
                    self._sleep(retry_after)
                    attempt += 1
                    continue
                raise ClaimError(ClaimErrorKind.RATE_LIMITED, "rate limited", status, retry_after)
            if status == 200:
                return _success(offer, response.content)
            if 300 <= status < 400:
                raise ClaimError(ClaimErrorKind.PROTOCOL_ERROR, "unexpected redirect", status)
            raise _error(offer, status, response.content)


def _plausible_email(email: object) -> bool:
    return (
        isinstance(email, str)
        and len(email) <= 254
        and email.count("@") == 1
        and _EMAIL_FORBIDDEN.search(email) is None
    )


def _retry_after(value: str | None) -> float | None:
    """Retry-After as a whole number of seconds; anything else (including HTTP dates) is ignored."""
    if value is None or not value.strip().isascii() or not value.strip().isdigit():
        return None
    return float(value.strip())


def _success(offer: Offer, content: bytes) -> ClaimResult:
    try:
        document = parse_strict_json(content)
    except StrictJSONError:
        raise ClaimError(
            ClaimErrorKind.PROTOCOL_ERROR, "response is not strict JSON", 200
        ) from None
    if not isinstance(document, dict) or set(document) != _SUCCESS_MEMBERS:
        raise ClaimError(
            ClaimErrorKind.PROTOCOL_ERROR, "response must have exactly offer_id, code, exp", 200
        )
    if document["offer_id"] != offer.offer_id:
        raise ClaimError(ClaimErrorKind.PROTOCOL_ERROR, "response is for a different offer", 200)
    code = document["code"]
    if type(code) is not str or not 1 <= len(code) <= 128 or _CONTROL.search(code):
        raise ClaimError(ClaimErrorKind.PROTOCOL_ERROR, "code must be 1-128 characters", 200)
    exp = parse_timestamp(document["exp"])
    if exp is None:
        raise ClaimError(ClaimErrorKind.PROTOCOL_ERROR, "exp is not a valid timestamp", 200)
    return ClaimResult(offer.offer_id, code, exp)


def _error(offer: Offer, status: int, content: bytes) -> ClaimError:
    try:
        document = parse_strict_json(content)
    except StrictJSONError:
        document = None
    error = document.get("error") if isinstance(document, dict) else None
    message = document.get("message") if isinstance(document, dict) else None
    documented = _DOCUMENTED.get(status, frozenset())
    if isinstance(error, str) and error in documented:
        kind = ClaimErrorKind(error)
    else:
        kind = ClaimErrorKind.PROTOCOL_ERROR
    detail = f"issuer returned {status}"
    if kind is ClaimErrorKind.PROTOCOL_ERROR:
        detail += " with an undocumented error"
    if isinstance(message, str):
        detail += f": {_safe_message(message, offer.claim)}"
    return ClaimError(kind, detail, status)


def _safe_message(message: str, claim: str) -> str:
    """The server's message, with the claim token removed, escaped and truncated."""
    cleaned = message.replace(claim, "clm_…")[:200]
    return repr(cleaned)[1:-1]
