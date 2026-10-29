"""Finding the block in a publisher response or MCP tool result.

Implements format spec §4.1.1. The response is parsed
tolerantly, so floats, ``NaN`` and duplicate keys *outside* the block never matter.
Only the chosen block's own subtree goes through ``strictify``, which applies exactly
the rules ``parse_strict_json`` applies to a bare block.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Literal

from .tolerant import (
    DEFAULT_MAX_TOLERANT_BYTES,
    RawNumber,
    StrictJSONError,
    TObject,
    TolerantJSONError,
    TolerantValue,
    parse_tolerant,
    strictify,
)

Mode = Literal["auto", "json", "mcp"]
Status = Literal["found", "none", "conflict", "not_json"]

MEMBER = "o2a_sponsored"
MAX_DEPTH = 8
MAX_MCP_ITEMS = 32
MAX_MCP_TEXT_BYTES = 1024 * 1024
_MODES = frozenset({"auto", "json", "mcp"})


@dataclass(frozen=True)
class ExtractionReport:
    """Where the block is, and its strict value.

    - ``found``: ``locations`` lists every place the block appears (identical copies
      collapse into one block). Either ``value`` (the strict value, ready for
      ``Verifier.verify_parsed``) or ``error`` (why the block breaks the JSON-text rules)
      is set.
    - ``conflict``: different blocks at the shallowest depth; ``locations`` lists them all.
    - ``none``: no block. ``not_json``: the input isn't JSON; ``error`` says why.
    """

    status: Status
    locations: tuple[str, ...] = ()
    value: object = None
    error: str | None = None
    depth: int | None = None


@dataclass(frozen=True)
class _Candidate:
    depth: int
    location: str
    tree: TObject


def extract(
    data: str | bytes | TolerantValue,
    *,
    mode: Mode = "auto",
    max_bytes: int = DEFAULT_MAX_TOLERANT_BYTES,
) -> ExtractionReport:
    """Locate the block in a response (raw text, or a node from ``parse_tolerant``).

    Never raises on bad content. Raises ``TypeError`` for plain ``dict``/``list``
    input, which has already lost duplicate members and number tokens.
    """
    if mode not in _MODES:
        raise ValueError(f"mode must be 'auto', 'json' or 'mcp', not {mode!r}")
    if isinstance(data, str | bytes):
        try:
            tree: TolerantValue = parse_tolerant(data, max_bytes=max_bytes)
        except TolerantJSONError as exc:
            return ExtractionReport("not_json", error=exc.detail)
    elif isinstance(data, dict | list):
        raise TypeError(
            "pass raw JSON text or a parse_tolerant() node: a plain dict or list has "
            "already lost duplicate members and number tokens"
        )
    elif data is None or isinstance(data, TObject | tuple | RawNumber | bool):
        tree = data
    else:
        raise TypeError(f"cannot extract from {type(data).__name__}")

    if mode == "auto":
        mode = "mcp" if _looks_like_mcp(tree) else "json"
    documents = _mcp_documents(tree) if mode == "mcp" else [(tree, "")]
    candidates = [c for document, prefix in documents for c in _shallowest(document, prefix)]
    return _decide(candidates)


def get_path(value: TolerantValue, *keys: str | int) -> TolerantValue | None:
    """Walk a tolerant tree by object keys and array indexes.

    Returns ``None`` if any step is missing, has the wrong container type, or names a
    key that appears more than once: ambiguity is never resolved by guessing.
    """
    for key in keys:
        if type(key) is str:
            if not isinstance(value, TObject):
                return None
            matches = value.get_all(key)
            if len(matches) != 1:
                return None
            value = matches[0]
        elif type(key) is int:
            if not isinstance(value, tuple) or not 0 <= key < len(value):
                return None
            value = value[key]
        else:
            raise TypeError("keys must be str or int")
    return value


# Locating -------------------------------------------------------------------------------


def _shallowest(document: TolerantValue, prefix: str) -> list[_Candidate]:
    """Format spec §4.1.1 steps 2-3 for one document: breadth-first by depth.

    Stops at the first depth that has a candidate, so deeper levels are never visited.
    """
    level: list[tuple[TolerantValue, str]] = [(document, "")]
    depth = 0
    while True:
        found = [
            _Candidate(depth, f"{prefix}{pointer}/{MEMBER}", child)
            for node, pointer in level
            if isinstance(node, TObject)
            for key, child in node.pairs
            if key == MEMBER and isinstance(child, TObject) and child.get_all("typ")
        ]
        if found:
            return found
        if depth == MAX_DEPTH:
            return []
        level = [
            (child, f"{pointer}/{step}")
            for node, pointer in level
            for step, child in _children(node)
            if isinstance(child, TObject | tuple)
        ]
        depth += 1


def _children(node: TolerantValue) -> list[tuple[str, TolerantValue]]:
    if isinstance(node, TObject):
        return [(key.replace("~", "~0").replace("/", "~1"), child) for key, child in node.pairs]
    if isinstance(node, tuple):
        return [(str(index), child) for index, child in enumerate(node)]
    return []


def _decide(candidates: list[_Candidate]) -> ExtractionReport:
    """Format spec §4.1.1 steps 4-5: collapse identical candidates, then decide."""
    if not candidates:
        return ExtractionReport("none")
    locations = tuple(c.location for c in candidates)
    depth = min(c.depth for c in candidates)
    if len(candidates) > 1:
        try:
            distinct = len({_identity(c.tree) for c in candidates})
        except RecursionError:
            # Too deep to compare: never guess which one is the publisher's.
            distinct = len(candidates)
        if distinct > 1:
            return ExtractionReport("conflict", locations, depth=depth)
    try:
        value = strictify(candidates[0].tree)
    except StrictJSONError as exc:
        return ExtractionReport("found", locations, error=exc.detail, depth=depth)
    return ExtractionReport("found", locations, value=value, depth=depth)


def _identity(value: TolerantValue) -> str:
    """A canonical text for equality: member order ignored (duplicates kept), numbers as written."""
    if isinstance(value, TObject):
        members = sorted(f"{json.dumps(key)}:{_identity(child)}" for key, child in value.pairs)
        return "{" + ",".join(members) + "}"
    if isinstance(value, tuple):
        return "[" + ",".join(_identity(item) for item in value) + "]"
    if isinstance(value, RawNumber):
        return "#" + value.token
    return json.dumps(value)


# MCP ------------------------------------------------------------------------------------


def _looks_like_mcp(tree: TolerantValue) -> bool:
    if not isinstance(tree, TObject):
        return False
    if _is_jsonrpc_envelope(tree) or isinstance(get_path(tree, "structuredContent"), TObject):
        return True
    content = get_path(tree, "content")
    return (
        isinstance(content, tuple)
        and len(content) > 0
        and all(isinstance(get_path(item, "type"), str) for item in content)
    )


def _is_jsonrpc_envelope(tree: TObject) -> bool:
    return len(tree.get_all("jsonrpc")) == 1 and isinstance(get_path(tree, "result"), TObject)


def _mcp_documents(tree: TolerantValue) -> list[tuple[TolerantValue, str]]:
    root, prefix = tree, ""
    if isinstance(tree, TObject) and _is_jsonrpc_envelope(tree):
        root, prefix = get_path(tree, "result"), "/result"

    documents: list[tuple[TolerantValue, str]] = []
    structured = get_path(root, "structuredContent")
    if isinstance(structured, TObject):
        documents.append((structured, f"{prefix}/structuredContent"))

    content = get_path(root, "content")
    if isinstance(content, tuple):
        for index, item in enumerate(content[:MAX_MCP_ITEMS]):
            kind = get_path(item, "type")
            if kind == "text":
                text, where = get_path(item, "text"), f"{prefix}/content/{index}/text"
            elif kind == "resource":
                text, where = (
                    get_path(item, "resource", "text"),
                    f"{prefix}/content/{index}/resource/text",
                )
            else:
                continue
            document = _parse_text_item(text)
            if document is not None:
                documents.append((document, where + "#"))
    return documents


def _parse_text_item(text: TolerantValue) -> TolerantValue | None:
    """A text item counts only if it is a JSON object of at most 1 MiB; prose is ignored."""
    if not isinstance(text, str) or not text.lstrip().startswith("{"):
        return None
    try:
        return parse_tolerant(text, max_bytes=MAX_MCP_TEXT_BYTES)
    except TolerantJSONError:
        return None
