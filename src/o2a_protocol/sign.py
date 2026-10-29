"""Signing (format spec §6.4)."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonicalize
from .keys import b64url, make_jwks
from .validate import is_hostname, is_id, parse_timestamp, validate_body

MAX_LIFETIME = timedelta(days=30)


class SigningError(Exception):
    """Raised by ``Signer.sign`` for any body it must not sign."""


class Signer:
    """Validates bodies and signs them with one issuer key."""

    def __init__(self, iss: str, kid: str, private_key: Ed25519PrivateKey) -> None:
        if not is_hostname(iss):
            raise ValueError("iss must be a hostname (format spec §4.4.1)")
        if not is_id(kid):
            raise ValueError("kid must be 1-64 characters of [A-Za-z0-9._-]")
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519PrivateKey")
        self.iss = iss
        self.kid = kid
        self._private_key = private_key

    @classmethod
    def from_seed(cls, iss: str, kid: str, seed: bytes) -> Signer:
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValueError("seed must be exactly 32 bytes")
        return cls(iss, kid, Ed25519PrivateKey.from_private_bytes(seed))

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key.public_key()

    def public_jwk(self) -> dict[str, object]:
        entries = make_jwks({self.kid: self.public_key()})["keys"]
        assert isinstance(entries, list)
        entry: dict[str, object] = entries[0]
        return entry

    def sign(self, body: Mapping[str, object], *, now: datetime | None = None) -> dict[str, object]:
        """Validate ``body`` and return a new dict: the body plus ``sig``.

        Raises ``SigningError`` for any invalid body, including an unknown
        ``terms.kind`` or an ``exp`` that isn't within 30 days after ``now``.
        """
        now = resolve_now(now)
        if not isinstance(body, Mapping):
            raise SigningError("body must be a mapping")
        body = dict(body)
        detail = _plain_types(body)
        if detail is not None:
            raise SigningError(detail)
        if "sig" in body:
            raise SigningError("body must not contain sig")
        if body.get("iss") != self.iss or body.get("kid") != self.kid:
            raise SigningError("iss and kid must match the signer")
        problem = validate_body(body)
        if problem is not None:
            raise SigningError(f"{problem[0]}: {problem[1]}")
        exp = parse_timestamp(body["exp"])
        assert exp is not None
        if exp <= now:
            raise SigningError("exp must be after now")
        if exp > now + MAX_LIFETIME:
            raise SigningError("exp must be no more than 30 days after now")
        signature = self._private_key.sign(canonicalize(body))
        block = copy.deepcopy(body)
        block["sig"] = b64url(signature)
        return block


def resolve_now(now: datetime | None) -> datetime:
    """Default to the current UTC time; reject naive datetimes (a programmer error)."""
    if now is None:
        return datetime.now(UTC)
    if not isinstance(now, datetime):
        raise TypeError("now must be a datetime")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")
    return now


def _plain_types(root: object) -> str | None:
    """Only exact built-in dict, str and int values may be signed (no bool, enums, subclasses)."""
    stack: list[tuple[str, object]] = [("body", root)]
    while stack:
        path, value = stack.pop()
        kind = type(value)
        if kind is dict:
            assert isinstance(value, dict)
            for key, child in value.items():
                if type(key) is not str:
                    return f"{path}: member names must be str"
                stack.append((f"{path}.{key}", child))
        elif kind is not str and kind is not int:
            return f"{path}: {kind.__name__} values cannot be signed"
    return None
