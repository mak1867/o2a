"""JCS canonicalization (RFC 8785; format spec §6.2)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, cast

import rfc8785


def canonicalize(body: Mapping[str, object]) -> bytes:
    """Return ``JCS(body)`` as UTF-8 bytes. Pass only validated bodies with ``sig`` removed."""
    return rfc8785.dumps(cast(dict[str, Any], dict(body)))
