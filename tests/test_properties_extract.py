"""Extraction property tests (format spec §4.1.1)."""

from __future__ import annotations

import json

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from o2a_protocol import Outcome, RawNumber, TObject, extract, parse_tolerant
from o2a_protocol.testing import TEST_NOW, make_body, sign_unchecked, test_signer, test_verifier
from o2a_protocol.tolerant import TolerantJSONError

from .vectors import VECTORS, Vector, vector_now, vector_verifier

SETTINGS = settings(max_examples=150, deadline=None, suppress_health_check=[HealthCheck.too_slow])
BS = chr(92)

BLOCK = test_signer().sign(make_body(), now=TEST_NOW)
BLOCK_TEXT = json.dumps(BLOCK)
BLOCK_ID = "off_a33e5dd43a75be430b008d47"

# --- Noise: raw JSON text with floats, NaN, huge integers and duplicate keys -------------

_scalars = (
    st.sampled_from(
        ["9.99", "1e3", "-0", "NaN", "Infinity", "1" * 50, "true", "false", "null", '"x"']
    )
    | st.integers().map(str)
    | st.text(max_size=5).map(json.dumps)
    | st.just('"' + BS + 'ud800"')
)


def _noise(keys: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
    return st.recursive(
        _scalars,
        lambda children: (
            st.lists(children, max_size=3).map(lambda xs: "[" + ",".join(xs) + "]")
            | st.lists(st.tuples(keys, children), max_size=3).map(
                lambda ms: "{" + ",".join(f"{json.dumps(k)}:{v}" for k, v in ms) + "}"
            )
        ),
        max_leaves=12,
    )


# Anything at all: plain "sponsored" flags, "o2a_sponsored" junk, objects with typ, real blocks.
_any_key = st.sampled_from(["a", "a", "price", "typ", "sponsored", "o2a_sponsored", "results"])
_candidate_like = st.sampled_from(
    [
        '{"o2a_sponsored":' + BLOCK_TEXT + "}",
        '{"o2a_sponsored":{"typ":"o2a-sponsored-offer/v0"}}',
        '{"o2a_sponsored":{"typ":1,"typ":2}}',
    ]
)
noise_any = _noise(_any_key) | _candidate_like.map(lambda c: "[" + c + "]")
# Noise with no candidate anywhere: no "o2a_sponsored" keys (plain "sponsored" is fine).
noise_clean = _noise(st.sampled_from(["a", "a", "price", "typ", "sponsored", "results"]))
_sibling_keys = st.sampled_from(["data", "price", "items", "meta", "meta"])


def members(keys: st.SearchStrategy[str], values: st.SearchStrategy[str]) -> st.SearchStrategy[str]:
    """Zero or more ``"key":value,`` members (duplicates possible), as raw text."""
    return st.lists(st.tuples(keys, values), max_size=4).map(
        lambda ms: "".join(f"{json.dumps(k)}:{v}," for k, v in ms)
    )


def response_outcome(text: str) -> tuple[Outcome | None, str | None]:
    result = test_verifier().verify_response(text, mode="json", now=TEST_NOW).result
    return (None, None) if result is None else (result.outcome, result.offer_id)


# --- 1. Strictness is the same on both paths ---------------------------------------------


def _is_block_object(vector: Vector) -> bool:
    if vector.get("input_kind", "block") != "block":
        return False
    try:
        tree = parse_tolerant(vector["input"])
    except TolerantJSONError:
        return False
    return isinstance(tree, TObject) and bool(tree.get_all("typ"))


BLOCK_VECTORS = [v for v in VECTORS if _is_block_object(v)]


def test_property_1_covers_the_array_vectors() -> None:
    names = {v["name"] for v in BLOCK_VECTORS}
    assert {"unknown-version-float-in-array", "dup-key-in-array"} <= names
    assert len(BLOCK_VECTORS) > 90


@SETTINGS
@given(st.sampled_from(BLOCK_VECTORS), members(_sibling_keys, noise_any))
def test_property_1_both_paths_are_equally_strict(vector: Vector, siblings: str) -> None:
    verifier, now = vector_verifier(vector), vector_now(vector)
    bare = verifier.verify(vector["input"], now=now)
    response = "{" + siblings + '"o2a_sponsored":' + vector["input"] + "}"
    report = verifier.verify_response(response, mode="json", now=now)
    assert report.result is not None
    assert report.result.outcome == bare.outcome, (report.result.detail, bare.detail)
    if bare.outcome is Outcome.VALID:
        assert report.result.offer_id == bare.offer_id


# --- 2. Extraction never raises ----------------------------------------------------------

_tolerant_keys = st.sampled_from(
    ["o2a_sponsored", "typ", "content", "structuredContent", "jsonrpc", "result", "type", "text"]
) | st.text(max_size=4)
tolerant_trees = st.recursive(
    st.none() | st.booleans() | st.text(max_size=8) | st.builds(RawNumber, st.text(max_size=6)),
    lambda children: (
        st.lists(children, max_size=4).map(tuple)
        | st.lists(st.tuples(_tolerant_keys, children), max_size=4).map(
            lambda pairs: TObject(tuple(pairs))
        )
    ),
    max_leaves=25,
)
_modes = st.sampled_from(["auto", "json", "mcp"])


@SETTINGS
@given(st.text() | st.binary() | noise_any, _modes)
def test_property_2_extraction_never_raises_on_text(data: str | bytes, mode: str) -> None:
    extract(data, mode=mode)  # type: ignore[arg-type]
    test_verifier().verify_response(data, mode=mode, now=TEST_NOW)  # type: ignore[arg-type]


@SETTINGS
@given(tolerant_trees, _modes)
def test_property_2_extraction_never_raises_on_trees(tree: object, mode: str) -> None:
    extract(tree, mode=mode)  # type: ignore[arg-type]
    test_verifier().verify_response(tree, mode=mode, now=TEST_NOW)  # type: ignore[arg-type]


@SETTINGS
@given(noise_any, st.text(max_size=8), _modes)
def test_property_2_never_raises_on_mcp_shaped_input(noise: str, prose: str, mode: str) -> None:
    items = [
        {"type": "text", "text": prose},
        {"type": "text", "text": "{" + prose},
        {"type": "resource", "resource": {"text": '{"o2a_sponsored":' + noise + "}"}},
    ]
    payload = (
        '{"jsonrpc":"2.0","result":{"content":'
        + json.dumps(items)
        + ',"structuredContent":{"o2a_sponsored":'
        + noise
        + "}}}"
    )
    test_verifier().verify_response(payload, mode=mode, now=TEST_NOW)  # type: ignore[arg-type]


# --- 3. Noise doesn't matter -------------------------------------------------------------


@SETTINGS
@given(members(_sibling_keys, noise_any), members(_sibling_keys, noise_any))
def test_property_3_noise_outside_the_block_does_not_matter(before: str, after: str) -> None:
    response = "{" + before + '"o2a_sponsored":' + BLOCK_TEXT + "," + after + '"end":0}'
    assert response_outcome(response) == (Outcome.VALID, BLOCK_ID)


# --- 4. Wrapping doesn't matter ----------------------------------------------------------


@SETTINGS
@given(
    st.lists(
        st.tuples(st.booleans(), members(_sibling_keys, noise_clean), noise_clean),
        max_size=8,
    ),
    members(_sibling_keys, noise_clean),
)
def test_property_4_wrapping_does_not_matter(
    wrappers: list[tuple[bool, str, str]], siblings: str
) -> None:
    text = "{" + siblings + '"o2a_sponsored":' + BLOCK_TEXT + "}"
    for as_array, object_noise, array_noise in wrappers:
        if as_array:
            text = "[" + array_noise + "," + text + "," + array_noise + "]"
        else:
            text = "{" + object_noise + '"payload":' + text + "}"
    assert response_outcome(text) == (Outcome.VALID, BLOCK_ID)


# --- 5. Griefing doesn't work ------------------------------------------------------------

_claims = st.from_regex(r"clm_[0-7][0-9A-HJKMNP-TV-Z]{25}", fullmatch=True)
_genuine = _claims.map(lambda c: json.dumps(test_signer().sign(make_body(claim=c), now=TEST_NOW)))
_forged = _claims.map(lambda c: json.dumps(sign_unchecked(make_body(claim=c, product="FREE!!"))))
_tampered = st.just(BLOCK_TEXT.replace('"percent": 20', '"percent": 90'))
_junk = st.sampled_from(
    ['{"typ":"o2a-sponsored-offer/v0"}', '{"typ":1,"typ":2}', '{"typ":"x","a":NaN}']
)
other_blocks = _genuine | _forged | _tampered | _junk


def _bury(block_text: str, path: list[bool]) -> str:
    """Place ``"o2a_sponsored": block`` at least one level deeper than the top level."""
    text = '{"o2a_sponsored":' + block_text + "}"
    for as_array in [True, *path]:
        text = "[" + text + "]" if as_array else '{"nested":' + text + "}"
    return text


@SETTINGS
@given(st.lists(st.tuples(other_blocks, st.lists(st.booleans(), max_size=6)), max_size=4))
def test_property_5_deeper_blocks_cannot_displace_the_publishers(
    others: list[tuple[str, list[bool]]],
) -> None:
    siblings = "".join(f'"g{i}":{_bury(block, path)},' for i, (block, path) in enumerate(others))
    response = "{" + siblings + '"o2a_sponsored":' + BLOCK_TEXT + "}"
    assert response_outcome(response) == (Outcome.VALID, BLOCK_ID)
    assert extract(response, mode="json").locations == ("/o2a_sponsored",)
