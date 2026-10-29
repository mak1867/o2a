"""Key sets and key resolvers (format spec §8). No network access."""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .strictjson import StrictJSONError, parse_strict_json
from .validate import is_id

# 32 bytes as unpadded base64url: 43 characters, with the last one's 2 unused bits zero.
_X_RE = re.compile(r"[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]")


class KeyResolver(Protocol):
    """Looks up an issuer's verification key by ``kid``."""

    def get(self, iss: str, kid: str) -> Ed25519PublicKey | None: ...


class StaticKeyResolver:
    """An in-memory resolver: ``iss -> kid -> key``."""

    def __init__(self, keys: Mapping[str, Mapping[str, Ed25519PublicKey]]) -> None:
        self._keys = {iss: dict(by_kid) for iss, by_kid in keys.items()}

    def get(self, iss: str, kid: str) -> Ed25519PublicKey | None:
        return self._keys.get(iss, {}).get(kid)


class ChainedKeyResolver:
    """Asks each resolver in turn and returns the first non-``None`` key.

    Typical use: a ``StaticKeyResolver`` with the issuer's pinned key, then an
    ``HttpKeyResolver`` for keys published after the pin.
    """

    def __init__(self, *resolvers: KeyResolver) -> None:
        self._resolvers = resolvers

    def get(self, iss: str, kid: str) -> Ed25519PublicKey | None:
        for resolver in self._resolvers:
            key = resolver.get(iss, kid)
            if key is not None:
                return key
        return None


def parse_jwks(data: str | bytes | Mapping[str, object]) -> dict[str, Ed25519PublicKey]:
    """Parse one issuer's JWK Set into ``{kid: key}``.

    Keys that aren't ``OKP`` / ``Ed25519`` are ignored. Any malformed Ed25519 entry,
    or a duplicate ``kid``, rejects the whole set with ``ValueError``: a corrupted
    key set should fail loudly, not partially.
    """
    if isinstance(data, str | bytes):
        try:
            document: object = parse_strict_json(data)
        except StrictJSONError as exc:
            raise ValueError(f"key set is not valid JSON: {exc.detail}") from None
    else:
        document = data
    if not isinstance(document, Mapping):
        raise ValueError("key set must be a JSON object")
    entries = document.get("keys")
    if not isinstance(entries, list):
        raise ValueError("key set must have a 'keys' array")

    result: dict[str, Ed25519PublicKey] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise ValueError(f"keys[{index}]: expected an object")
        if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
            continue
        kid = entry.get("kid")
        if not is_id(kid):
            raise ValueError(f"keys[{index}]: kid must be 1-64 characters of [A-Za-z0-9._-]")
        assert isinstance(kid, str)
        if kid in result:
            raise ValueError(f"keys[{index}]: duplicate kid {kid}")
        if "d" in entry:
            raise ValueError(f"keys[{index}]: contains a private key")
        if entry.get("use", "sig") != "sig" or entry.get("alg", "EdDSA") != "EdDSA":
            raise ValueError(f"keys[{index}]: use must be 'sig' and alg must be 'EdDSA'")
        x = entry.get("x")
        if not isinstance(x, str) or _X_RE.fullmatch(x) is None:
            raise ValueError(f"keys[{index}]: x must be 43 characters of canonical base64url")
        raw = base64.urlsafe_b64decode(x + "=")
        result[kid] = Ed25519PublicKey.from_public_bytes(raw)
    return result


def make_jwks(keys: Mapping[str, Ed25519PublicKey]) -> dict[str, object]:
    """Build the §8.1 key set document for ``{kid: public key}``."""
    entries: list[dict[str, str]] = []
    for kid, key in keys.items():
        if not is_id(kid):
            raise ValueError(f"invalid kid {kid!r}")
        entries.append(
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": kid,
                "x": b64url(key.public_bytes(Encoding.Raw, PublicFormat.Raw)),
                "use": "sig",
                "alg": "EdDSA",
            }
        )
    return {"keys": entries}


def b64url(data: bytes) -> str:
    """Unpadded base64url (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
