"""The optional hint (format spec §4.7): `o2a_sponsored_hint`, a short line next to a block.

A hint is untrusted. It is not a block and not an offer: the most a reader may do with one is
resolve its claim token with a trusted issuer (§9.5) and verify the block that comes back (§7).
"""

from __future__ import annotations

import re

from .ids import CLAIM_RE
from .validate import is_hostname

HINT_MAX_CHARS = 125
_HINT_RE = re.compile(rf"Sponsored offer ref ({CLAIM_RE.pattern}), issued by (\S+)")


def parse_hint(value: str) -> tuple[str, str] | None:
    """``(claim, iss)`` from a hint value in exactly the §4.7 form, else ``None``. Never raises.

    ``iss`` is only a routing suggestion: never trust an issuer because a hint names it (§8.3).
    """
    if not isinstance(value, str) or len(value) > HINT_MAX_CHARS:
        return None
    match = _HINT_RE.fullmatch(value)
    if match is None or not is_hostname(match.group(2)):
        return None
    return match.group(1), match.group(2)
