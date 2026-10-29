"""Extraction (format spec §4.1.1)."""

from __future__ import annotations

import json
from typing import Any

import pytest

from o2a_protocol import (
    Outcome,
    RawNumber,
    TObject,
    extract,
    get_path,
    parse_tolerant,
)
from o2a_protocol.testing import TEST_NOW, make_body, test_signer, test_verifier

BLOCK = test_signer().sign(make_body(), now=TEST_NOW)
OTHER = test_signer().sign(make_body(claim="clm_1AAAAAAAAAAAAAAAAAAAAAAAAA"), now=TEST_NOW)
BLOCK_TEXT = json.dumps(BLOCK)


def text(value: object) -> str:
    return json.dumps(value)


def wrap(value: object, levels: int) -> object:
    """Put ``value``'s holding object ``levels`` objects deeper."""
    for _ in range(levels):
        value = {"w": value}
    return value


# Locations -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "mode", "location", "depth"),
    [
        ({"o2a_sponsored": BLOCK}, "json", "/o2a_sponsored", 0),
        ({"data": {"o2a_sponsored": BLOCK}}, "json", "/data/o2a_sponsored", 1),
        ({"results": [{"o2a_sponsored": BLOCK}]}, "json", "/results/0/o2a_sponsored", 2),
        ({"a/b": {"o2a_sponsored": BLOCK}}, "json", "/a~1b/o2a_sponsored", 1),
        ({"a~b": {"o2a_sponsored": BLOCK}}, "json", "/a~0b/o2a_sponsored", 1),
        (
            {"structuredContent": {"o2a_sponsored": BLOCK}},
            "mcp",
            "/structuredContent/o2a_sponsored",
            0,
        ),
        (
            {"content": [{"type": "text", "text": text({"x": {"o2a_sponsored": BLOCK}})}]},
            "mcp",
            "/content/0/text#/x/o2a_sponsored",
            1,
        ),
        (
            {
                "content": [
                    {
                        "type": "resource",
                        "resource": {"uri": "r", "text": text({"o2a_sponsored": BLOCK})},
                    }
                ]
            },
            "mcp",
            "/content/0/resource/text#/o2a_sponsored",
            0,
        ),
        (
            {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"content": [{"type": "text", "text": text({"o2a_sponsored": BLOCK})}]},
            },
            "mcp",
            "/result/content/0/text#/o2a_sponsored",
            0,
        ),
    ],
)
def test_locations(response: object, mode: Any, location: str, depth: int) -> None:
    report = extract(text(response), mode=mode)
    assert report.status == "found"
    assert report.locations == (location,)
    assert report.depth == depth
    assert report.value == BLOCK


def test_depth_counting() -> None:
    assert extract(text(wrap({"o2a_sponsored": BLOCK}, 8))).status == "found"
    assert extract(text(wrap({"o2a_sponsored": BLOCK}, 9))).status == "none"
    # Arrays count too: [ { "o2a_sponsored": ... } ] puts the member at depth 1.
    assert extract(text([{"o2a_sponsored": BLOCK}])).depth == 1


class _Untouchable(TObject):
    """A subtree that fails the test if the search ever looks inside it."""

    def __getattribute__(self, name: str) -> Any:
        if name == "pairs":
            raise AssertionError("a deeper level was visited")
        return super().__getattribute__(name)


def test_search_stops_at_the_first_depth_with_a_candidate() -> None:
    block = parse_tolerant(BLOCK_TEXT)
    deeper = _Untouchable((("o2a_sponsored", parse_tolerant(json.dumps(OTHER))),))
    tree = TObject((("o2a_sponsored", block), ("comments", deeper), ("list", (deeper,))))
    report = extract(tree)
    assert report.status == "found" and report.locations == ("/o2a_sponsored",)


def test_identical_candidates_collapse_ignoring_member_order() -> None:
    reordered = dict(reversed(list(BLOCK.items())))
    report = extract(text({"a": {"o2a_sponsored": BLOCK}, "b": {"o2a_sponsored": reordered}}))
    assert report.status == "found"
    assert report.locations == ("/a/o2a_sponsored", "/b/o2a_sponsored")


def test_number_tokens_are_compared_as_written() -> None:
    as_float = BLOCK_TEXT.replace('"percent": 20', '"percent": 20.0')
    response = '{"a":{"o2a_sponsored":' + BLOCK_TEXT + '},"b":{"o2a_sponsored":' + as_float + "}}"
    report = extract(response)
    assert report.status == "conflict"


def test_conflict_reports_every_location_and_is_malformed_without_offer_id() -> None:
    response = text({"a": {"o2a_sponsored": BLOCK}, "b": [{"x": 1}], "c": {"o2a_sponsored": OTHER}})
    report = extract(response)
    assert report.status == "conflict"
    assert report.locations == ("/a/o2a_sponsored", "/c/o2a_sponsored")
    verified = test_verifier().verify_response(response, now=TEST_NOW)
    assert verified.status == "conflict"
    assert verified.locations == report.locations
    assert verified.result is not None
    assert verified.result.outcome is Outcome.MALFORMED
    assert verified.result.detail == "multiple distinct blocks at depth 1"
    assert verified.result.offer_id is None


def test_too_deep_to_compare_is_a_conflict() -> None:
    deep: Any = ()
    for _ in range(50_000):
        deep = (deep,)
    a = TObject((("typ", "x"), ("junk", deep)))
    b = TObject((("typ", "x"), ("junk", deep)))
    report = extract(
        TObject((("p", TObject((("o2a_sponsored", a),))), ("q", TObject((("o2a_sponsored", b),)))))
    )
    assert report.status == "conflict"


def test_strictness_error_in_the_block_is_malformed_without_verification() -> None:
    response = '{"price":9.99,"o2a_sponsored":' + BLOCK_TEXT[:-1] + ',"campaign":"cmp_9x2a"}}'
    report = extract(response)
    assert report.status == "found" and report.error == "duplicate member name"
    verified = test_verifier().verify_response(response, now=TEST_NOW)
    assert verified.result is not None
    assert verified.result.outcome is Outcome.MALFORMED
    assert verified.result.detail == "duplicate member name"


# Modes -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        {"content": [{"type": "text", "text": "hi"}], "o2a_sponsored": BLOCK},
        {"structuredContent": {}, "o2a_sponsored": BLOCK},
        {"jsonrpc": "2.0", "result": {}, "o2a_sponsored": BLOCK},
    ],
)
def test_auto_picks_mcp_for_mcp_shaped_input_never_both(response: object) -> None:
    # In MCP mode the top-level o2a_sponsored member is not a document, so it isn't found.
    assert extract(text(response)).status == "none"
    assert extract(text(response), mode="json").status == "found"


@pytest.mark.parametrize(
    "response",
    [
        {"content": [], "o2a_sponsored": BLOCK},
        {"content": [{"type": 1}], "o2a_sponsored": BLOCK},
        {"content": ["text"], "o2a_sponsored": BLOCK},
        {"content": "text", "o2a_sponsored": BLOCK},
        {"structuredContent": [], "o2a_sponsored": BLOCK},
        {"jsonrpc": "2.0", "result": "x", "o2a_sponsored": BLOCK},
    ],
)
def test_auto_picks_json_otherwise(response: object) -> None:
    assert extract(text(response)).status == "found"


def test_duplicated_jsonrpc_member_is_not_an_envelope() -> None:
    inner = text({"o2a_sponsored": BLOCK})
    response = (
        '{"jsonrpc":"2.0","jsonrpc":"2.0","result":{"content":[{"type":"text","text":'
        + json.dumps(inner)
        + "}]}}"
    )
    assert extract(response, mode="mcp").status == "none"


def test_mcp_ignores_other_items_and_non_text() -> None:
    response = {
        "content": [
            {"type": "image", "data": "..."},
            {"type": "text", "text": 5},
            {"type": "resource", "resource": {"uri": "r"}},
            "not an object",
            {"type": "text", "text": text({"o2a_sponsored": BLOCK})},
        ]
    }
    assert extract(text(response), mode="mcp").locations == ("/content/4/text#/o2a_sponsored",)


def test_mcp_mode_on_non_objects_finds_nothing() -> None:
    assert extract("[1,2]", mode="mcp").status == "none"
    assert extract(text({"structuredContent": "x"}), mode="mcp").status == "none"


def test_mcp_text_items_over_1_mib_are_skipped() -> None:
    padded = text({"pad": "x" * (1024 * 1024), "o2a_sponsored": BLOCK})
    small = text({"o2a_sponsored": BLOCK})
    response = {"content": [{"type": "text", "text": padded}]}
    assert extract(text(response)).status == "none"
    response = {"content": [{"type": "text", "text": padded}, {"type": "text", "text": small}]}
    assert extract(text(response)).locations == ("/content/1/text#/o2a_sponsored",)


def test_mcp_items_beyond_the_32nd_are_skipped() -> None:
    filler = [{"type": "text", "text": "prose"}] * 32
    item = {"type": "text", "text": text({"o2a_sponsored": BLOCK})}
    assert extract(text({"content": [*filler, item]})).status == "none"
    assert extract(text({"content": [*filler[:31], item]})).status == "found"


def test_mcp_text_with_leading_whitespace_is_parsed() -> None:
    response = {"content": [{"type": "text", "text": "\n  " + text({"o2a_sponsored": BLOCK})}]}
    assert extract(text(response)).status == "found"


# Inputs ----------------------------------------------------------------------------------


def test_inputs_over_8_mib_are_not_json() -> None:
    report = extract(b" " * (8 * 1024 * 1024 + 1))
    assert report.status == "not_json" and report.error == "too_large"
    assert extract("x" * 20, max_bytes=10).error == "too_large"


def test_not_json_and_none_give_no_result() -> None:
    verifier = test_verifier()
    for data, status in [("Service unavailable", "not_json"), ('{"data":1}', "none")]:
        report = verifier.verify_response(data, now=TEST_NOW)
        assert report.status == status and report.result is None and report.locations == ()


@pytest.mark.parametrize("value", [{"o2a_sponsored": BLOCK}, [BLOCK], 5, 1.5, object()])
def test_plain_python_values_are_rejected(value: object) -> None:
    with pytest.raises(TypeError):
        extract(value)  # type: ignore[arg-type]


def test_invalid_mode() -> None:
    with pytest.raises(ValueError):
        extract("{}", mode="xml")  # type: ignore[arg-type]


def test_tolerant_nodes_are_accepted() -> None:
    payload = parse_tolerant(text({"hook": {"tool_response": {"o2a_sponsored": BLOCK}}}))
    node = get_path(payload, "hook", "tool_response")
    assert node is not None
    assert extract(node).locations == ("/o2a_sponsored",)
    for scalar in [None, True, RawNumber("1"), ()]:
        assert extract(scalar).status == "none"
    assert extract("5").status == "none"


def test_verify_response_returns_the_verified_offer() -> None:
    report = test_verifier().verify_response(text({"data": {"o2a_sponsored": BLOCK}}), now=TEST_NOW)
    assert report.result is not None and report.result.outcome is Outcome.VALID
    assert report.result.offer_id == "off_a33e5dd43a75be430b008d47"


# get_path --------------------------------------------------------------------------------


def test_get_path() -> None:
    tree = parse_tolerant('{"a":[{"b":1}],"dup":1,"dup":2}')
    assert get_path(tree, "a", 0, "b") == RawNumber("1")
    assert get_path(tree) == tree
    assert get_path(tree, "dup") is None
    assert get_path(tree, "missing") is None
    assert get_path(tree, "a", 1) is None
    assert get_path(tree, "a", -1) is None
    assert get_path(tree, 0) is None
    assert get_path(tree, "a", "b") is None
    with pytest.raises(TypeError):
        get_path(tree, "a", True)
