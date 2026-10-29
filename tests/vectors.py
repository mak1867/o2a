"""Load the committed test vectors. Tests only ever read these files; they never regenerate them."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from o2a_protocol import StaticKeyResolver, Verifier, parse_jwks

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors"

Vector = dict[str, Any]


def load_vectors() -> list[tuple[Path, Vector]]:
    return [
        (p, json.loads(p.read_text(encoding="utf-8"))) for p in sorted(VECTORS_DIR.glob("*.json"))
    ]


VECTORS: list[Vector] = [vector for _, vector in load_vectors()]
VECTORS_BY_NAME: dict[str, Vector] = {vector["name"]: vector for vector in VECTORS}


def vector_now(vector: Vector) -> datetime:
    return datetime.strptime(vector["now"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def vector_verifier(vector: Vector) -> Verifier:
    keys = {iss: parse_jwks(jwks) for iss, jwks in vector["keys"].items()}
    return Verifier(
        vector["trusted_issuers"],
        StaticKeyResolver(keys),
        skew=timedelta(seconds=vector["skew_seconds"]),
    )
