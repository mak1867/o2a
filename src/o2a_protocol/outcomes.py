"""Verification outcomes (format spec §7)."""

from enum import StrEnum


class Outcome(StrEnum):
    """The result of verifying a block. Values are the exact strings from the format spec."""

    VALID = "valid"
    UNSUPPORTED = "unsupported"
    MALFORMED = "malformed"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    UNKNOWN_KEY = "unknown_key"
    BAD_SIGNATURE = "bad_signature"
    EXPIRED = "expired"
