"""parse_hint (format spec §4.7)."""

from __future__ import annotations

from typing import Any

import pytest

from o2a_protocol import new_claim_token, parse_hint

CLAIM = "clm_3KQ2M9XR4TBV8HNE3WPA6CJD0F"


def hint(claim: str = CLAIM, iss: str = "offers.example") -> str:
    return f"Sponsored offer ref {claim}, issued by {iss}"


def test_valid() -> None:
    assert parse_hint(hint()) == (CLAIM, "offers.example")
    fresh = new_claim_token()
    assert parse_hint(hint(fresh, "o2a.exchange")) == (fresh, "o2a.exchange")


def test_length_limit_is_125_characters() -> None:
    fixed = len(hint(iss=""))
    exact = hint(iss="a" * (125 - fixed - len(".example")) + ".example")
    assert len(exact) == 125 and parse_hint(exact) is not None
    longer = hint(iss="a" * (126 - fixed - len(".example")) + ".example")
    assert len(longer) == 126 and parse_hint(longer) is None


@pytest.mark.parametrize(
    "value",
    [
        f"Sponsored offer ref {CLAIM} issued by offers.example",  # missing comma
        f"sponsored offer ref {CLAIM}, issued by offers.example",  # case
        f"Sponsored offer ref {CLAIM}, issued by offers.example.",  # trailing text
        f" Sponsored offer ref {CLAIM}, issued by offers.example",  # leading space
        f"Sponsored offer ref {CLAIM},  issued by offers.example",  # double space
        f"Sponsored offer ref {CLAIM}, issued by offers.example\n",
        f"Save this! Sponsored offer ref {CLAIM}, issued by offers.example",
        f"Sponsored offer {CLAIM}, issued by offers.example",
    ],
)
def test_wrong_wording(value: str) -> None:
    assert parse_hint(value) is None


@pytest.mark.parametrize(
    "claim",
    [
        "clm_8KQ2M9XR4TBV8HNE3WPA6CJD0F",  # first character must be 0-7
        "clm_3KQ2M9XR4TBV8HNE3WPA6CJD0",  # too short
        "CLM_3KQ2M9XR4TBV8HNE3WPA6CJD0F",
        "clm_3kq2m9xr4tbv8hne3wpa6cjd0f",
        "clm_3KQ2M9XR4TBV8HNE3WPA6CJDIL",  # I and L aren't Crockford base32
    ],
)
def test_bad_claim(claim: str) -> None:
    assert parse_hint(hint(claim)) is None


@pytest.mark.parametrize(
    "iss",
    [
        "Offers.example",
        "offers",
        "offers.example:443",
        "192.168.0.1",
        "-offers.example",
        "offers..example",
        "https://offers.example",
        "offers.example/x",
        "offers.example.",
    ],
)
def test_bad_hostname(iss: str) -> None:
    assert parse_hint(hint(iss=iss)) is None


@pytest.mark.parametrize("value", [None, 42, b"bytes", ["x"], {"claim": CLAIM}])
def test_non_strings_never_raise(value: Any) -> None:
    assert parse_hint(value) is None
