"""Property tests: reformatting, tampering, totality and signing round-trips."""

from __future__ import annotations

import json
import random
from datetime import timedelta
from typing import Any

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from o2a_protocol import Outcome, VerificationResult
from o2a_protocol.testing import TEST_NOW, make_body, test_signer, test_verifier
from o2a_protocol.validate import format_timestamp, string_problem

SETTINGS = settings(max_examples=200, deadline=None, suppress_health_check=[HealthCheck.too_slow])

# --- Strategies for valid field values -----------------------------------------------------

_label = st.from_regex(r"[a-z0-9]([a-z0-9-]{0,8}[a-z0-9])?", fullmatch=True)
hostnames = st.lists(_label, min_size=1, max_size=3).map(lambda ls: ".".join([*ls, "example"]))
ids = st.from_regex(r"[A-Za-z0-9._-]{1,64}", fullmatch=True)
texts = st.text(
    alphabet=st.characters(codec="utf-8", exclude_categories=("Cs", "Cc", "Cf", "Zl", "Zp")),
    min_size=1,
    max_size=80,
).filter(lambda s: string_problem(s) is None)
urls = st.builds(
    lambda host, path: f"https://{host}{path}",
    hostnames,
    st.from_regex(r"(/[A-Za-z0-9._~%-]{0,12}){0,3}(\?[a-z]=[0-9]{1,4})?", fullmatch=True).filter(
        lambda p: "%" not in p
    ),
)
durations = st.none() | st.integers(1, 36)


def _with_duration(terms: dict[str, Any], months: int | None) -> dict[str, Any]:
    return terms if months is None else {**terms, "duration_months": months}


terms = st.one_of(
    st.builds(
        lambda p, d: _with_duration({"kind": "percent_off", "percent": p}, d),
        st.integers(1, 100),
        durations,
    ),
    st.builds(
        lambda a, c, d: _with_duration({"kind": "amount_off", "amount_minor": a, "currency": c}, d),
        st.integers(1, 1_000_000_000),
        st.from_regex(r"[A-Z]{3}", fullmatch=True),
        durations,
    ),
)
claims = st.from_regex(r"clm_[0-7][0-9A-HJKMNP-TV-Z]{25}", fullmatch=True)
exps = st.integers(1, 30 * 86400).map(lambda s: format_timestamp(TEST_NOW + timedelta(seconds=s)))

bodies = st.builds(
    lambda campaign, pub_name, pub_domain, m_name, m_url, product, t, claim, exp: make_body(
        campaign=campaign,
        publisher={"name": pub_name, "domain": pub_domain},
        merchant={"name": m_name, "url": m_url},
        product=product,
        terms=t,
        claim=claim,
        exp=exp,
    ),
    ids,
    texts,
    hostnames,
    texts,
    urls,
    texts,
    terms,
    claims,
    exps,
)

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(), children, max_size=4)
    ),
    max_leaves=20,
)


def verify_text(text: str | bytes) -> VerificationResult:
    return test_verifier().verify(text, now=TEST_NOW)


# --- 4. Signing round-trips ----------------------------------------------------------------


@SETTINGS
@given(bodies)
def test_signing_round_trips(body: dict[str, Any]) -> None:
    block = test_signer().sign(body, now=TEST_NOW)
    result = verify_text(json.dumps(block))
    assert result.outcome is Outcome.VALID, result.detail
    assert result.offer is not None and result.offer.to_block() == block


# --- 1. Reformatting doesn't matter --------------------------------------------------------


def _shuffled(value: object, rng: random.Random) -> object:
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {key: _shuffled(value[key], rng) for key in keys}
    return value


@SETTINGS
@given(
    bodies,
    st.randoms(use_true_random=False),
    st.sampled_from([None, 0, 2, "\t", " \n "]),
    st.sampled_from([(",", ":"), (", ", ": "), (" ,\n", " :\t")]),
    st.booleans(),
)
def test_reformatting_does_not_matter(
    body: dict[str, Any],
    rng: random.Random,
    indent: int | str | None,
    separators: tuple[str, str],
    ascii_only: bool,
) -> None:
    block = test_signer().sign(body, now=TEST_NOW)
    text = json.dumps(
        _shuffled(block, rng), indent=indent, separators=separators, ensure_ascii=ascii_only
    )
    assert verify_text(text).outcome is Outcome.VALID


# --- 2. Tampering is caught ----------------------------------------------------------------


def _leaf_paths(value: object, prefix: tuple[str, ...] = ()) -> list[tuple[str, ...]]:
    if isinstance(value, dict):
        return [path for key in value for path in _leaf_paths(value[key], (*prefix, key))]
    return [prefix]


@SETTINGS
@given(bodies, st.data())
def test_tampering_is_caught(body: dict[str, Any], data: st.DataObject) -> None:
    block = test_signer().sign(body, now=TEST_NOW)
    path = data.draw(st.sampled_from(_leaf_paths(block)))
    parent: Any = block
    for key in path[:-1]:
        parent = parent[key]
    old = parent[path[-1]]
    replacement = st.integers() if isinstance(old, int) else st.text()
    parent[path[-1]] = data.draw(replacement.filter(lambda new: new != old))
    # Anything but valid: bad_signature, malformed, or (for typ, kind, iss, kid)
    # unsupported, untrusted_issuer or unknown_key.
    assert verify_text(json.dumps(block)).outcome is not Outcome.VALID


# --- 3. Totality ---------------------------------------------------------------------------


@SETTINGS
@given(st.text())
def test_verify_never_raises_on_text(text: str) -> None:
    assert isinstance(verify_text(text), VerificationResult)


@SETTINGS
@given(st.binary())
def test_verify_never_raises_on_bytes(data: bytes) -> None:
    assert isinstance(verify_text(data), VerificationResult)


@SETTINGS
@given(json_values)
def test_verify_never_raises_on_json_values(value: object) -> None:
    assert isinstance(test_verifier().verify_parsed(value, now=TEST_NOW), VerificationResult)
    assert isinstance(verify_text(json.dumps(value)), VerificationResult)


@SETTINGS
@given(st.dictionaries(st.sampled_from([*sorted(make_body()), "sig"]), json_values))
def test_verify_never_raises_on_block_shaped_values(value: dict[str, Any]) -> None:
    value["typ"] = "o2a-sponsored-offer/v0"
    assert isinstance(test_verifier().verify_parsed(value, now=TEST_NOW), VerificationResult)


@SETTINGS
@given(bodies, st.data())
def test_verify_never_raises_on_mutated_text(body: dict[str, Any], data: st.DataObject) -> None:
    text = json.dumps(test_signer().sign(body, now=TEST_NOW))
    start = data.draw(st.integers(0, len(text)))
    end = data.draw(st.integers(start, min(len(text), start + 8)))
    mutated = text[:start] + data.draw(st.text(max_size=8)) + text[end:]
    assert isinstance(verify_text(mutated), VerificationResult)
