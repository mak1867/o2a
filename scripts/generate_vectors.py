"""Generate the committed test vectors (format spec §12).

    uv run python scripts/generate_vectors.py           # write vectors/*.json
    uv run python scripts/generate_vectors.py --check   # fail if vectors/ is out of date

Every vector is built deterministically from ``o2a_protocol.testing`` plus text-level
edits. Expected outcomes are written out by hand here, never computed by the verifier.

Two habits make the vectors sharper:

- Invalid blocks are signed correctly where possible (``sign_unchecked``), so a reader
  that skips a format rule gets ``valid`` instead of ``malformed``, not ``bad_signature``.
- Parser traps are placed where a lenient reader would get a *different* outcome:
  duplicate members repeat the same value, and number traps sit inside an unknown
  ``terms.kind`` (where a lenient parser would answer ``unsupported``).

Files are written with ``ensure_ascii`` so no editor can silently normalize them.
"""

from __future__ import annotations

import argparse
import json
import sys
import unicodedata
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from o2a_protocol import canonicalize, make_jwks, offer_id
from o2a_protocol.testing import (
    TEST_ISSUER,
    TEST_KID,
    TEST_NOW,
    make_body,
    sign_unchecked,
    test_signer,
    with_field,
    without_field,
)
from o2a_protocol.validate import format_timestamp

VECTORS_DIR = Path(__file__).resolve().parent.parent / "vectors"
OTHER_ISSUER = "other-offers.example"
OTHER_CLAIM = "clm_1AAAAAAAAAAAAAAAAAAAAAAAAA"
MEMBER = "o2a_sponsored"  # where publishers put the block
PLAIN = "sponsored"  # a common key in publishers' own JSON, never a block
BS = chr(92)  # a backslash, for writing JSON escapes into raw input text

Block = dict[str, Any]


def dumps(value: object) -> str:
    """Compact JSON text, with non-ASCII characters written literally."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"expected exactly one {old!r} in {text!r}")
    return text.replace(old, new)


def signed(body: Block) -> Block:
    """Sign a valid body with the validating signer."""
    return test_signer().sign(body, now=TEST_NOW)


def ts(moment: datetime) -> str:
    return format_timestamp(moment)


class Vectors:
    def __init__(self) -> None:
        self.items: dict[str, dict[str, Any]] = {}

    def add(
        self,
        name: str,
        description: str,
        input_text: str,
        outcome: str,
        *,
        expected_block: Block | None = None,
        now: datetime = TEST_NOW,
        skew_seconds: int = 60,
        trusted: tuple[str, ...] = (TEST_ISSUER,),
        key_issuers: tuple[str, ...] = (TEST_ISSUER,),
        input_kind: str = "block",
    ) -> None:
        if name in self.items:
            raise AssertionError(f"duplicate vector name {name}")
        public_key = test_signer().public_key()
        vector: dict[str, Any] = {
            "name": name,
            "description": description,
            "now": ts(now),
            "skew_seconds": skew_seconds,
            "trusted_issuers": list(trusted),
            "keys": {iss: make_jwks({TEST_KID: public_key}) for iss in key_issuers},
        }
        if input_kind != "block":
            vector["input_kind"] = input_kind
        vector["input"] = input_text
        expected: dict[str, Any] = {"outcome": outcome}
        if outcome == "valid":
            if expected_block is None:
                raise AssertionError(f"{name}: valid vectors need expected_block")
            body = {k: v for k, v in expected_block.items() if k != "sig"}
            expected["offer_id"] = offer_id(expected_block["claim"])
            expected["canonical_hex"] = canonicalize(body).hex()
            expected["sig"] = expected_block["sig"]
        vector["expected"] = expected
        self.items[name] = vector

    def valid(self, name: str, description: str, block: Block, **kwargs: Any) -> None:
        self.add(name, description, dumps(block), "valid", expected_block=block, **kwargs)

    def text(self, name: str, description: str, text: str, outcome: str, **kw: Any) -> None:
        self.add(name, description, text, outcome, **kw)

    def field(
        self, name: str, description: str, path: str, value: object, outcome: str = "malformed"
    ) -> None:
        """A correctly signed block with one field changed before signing."""
        self.add(
            name, description, dumps(sign_unchecked(with_field(make_body(), path, value))), outcome
        )


def build() -> dict[str, dict[str, Any]]:
    v = Vectors()
    base = signed(make_body())
    base_text = dumps(base)
    exp = TEST_NOW + timedelta(days=14)
    unknown_kind = {"kind": "free_units", "units": 7}

    # --- Format spec §12.3 required cases ---------------------------------------------------
    v.valid("valid-percent-off", "percent_off with duration_months.", base)
    v.valid(
        "valid-amount-off",
        "amount_off without duration_months.",
        signed(make_body(terms={"kind": "amount_off", "amount_minor": 500, "currency": "USD"})),
    )
    v.valid(
        "valid-non-ascii",
        "Merchant name with non-ASCII characters (precomposed).",
        signed(with_field(make_body(), "merchant.name", "Café Zürich Mail 東京")),
    )

    def reorder(value: object) -> object:
        if isinstance(value, dict):
            return {k: reorder(value[k]) for k in reversed(list(value))}
        return value

    v.add(
        "valid-reformatted",
        "Members reordered and whitespace added after signing.",
        json.dumps(reorder(base), ensure_ascii=False, indent="\t", separators=(" ,  ", " :  "))
        + "\n",
        "valid",
        expected_block=base,
    )
    response = {
        "data": {"results": [{"title": "Sending email", "path": "/guides/email"}], "total": 1},
        "o2a_sponsored": base,
    }
    v.add(
        "valid-embedded",
        "Block nested in a full publisher response at top-level o2a_sponsored.",
        dumps(response),
        "valid",
        expected_block=base,
        input_kind="response",
    )
    v.text(
        "tampered-terms",
        "terms.percent changed from 20 to 25 after signing.",
        replace_once(base_text, '"percent":20', '"percent":25'),
        "bad_signature",
    )
    v.text(
        "tampered-publisher",
        "publisher.domain changed after signing.",
        replace_once(base_text, '"devdocs.example"', '"devdocs2.example"'),
        "bad_signature",
    )
    v.text(
        "extra-member",
        "an extra member added after signing is malformed, not bad_signature.",
        dumps({**base, "note": "hello"}),
        "malformed",
    )
    v.text(
        "missing-member",
        "campaign removed; correctly signed without it.",
        dumps(sign_unchecked(without_field(make_body(), "campaign"))),
        "malformed",
    )
    v.text(
        "float-number",
        "percent written as 20.0 (a lenient parser would read 20 and say valid).",
        replace_once(base_text, '"percent":20', '"percent":20.0'),
        "malformed",
    )
    v.field(
        "control-char",
        "escaped newline in product.",
        "product",
        "Transactional email API\npaid plans",
    )
    v.valid(
        "checkout-shaped-url",
        "Valid at format level: the no-checkout-URL rule is enforced by the issuer, "
        "and cannot be checked offline.",
        signed(
            with_field(make_body(), "merchant.url", "https://acmemail.example/checkout?plan=pro")
        ),
    )
    v.text(
        "expired", "now is one day after exp.", base_text, "expired", now=exp + timedelta(days=1)
    )
    v.field("exp-too-far", "exp is 45 days after now.", "exp", ts(TEST_NOW + timedelta(days=45)))
    v.field(
        "unknown-typ", "typ o2a-sponsored-offer/v1.", "typ", "o2a-sponsored-offer/v1", "unsupported"
    )
    v.field("unknown-kind", "terms.kind free_units.", "terms", unknown_kind, "unsupported")
    other = sign_unchecked(make_body(iss=OTHER_ISSUER))
    v.text(
        "untrusted-issuer",
        "Signed by a key the reader has, but the issuer isn't in the trusted list.",
        dumps(other),
        "untrusted_issuer",
        key_issuers=(TEST_ISSUER, OTHER_ISSUER),
    )
    v.text(
        "unknown-kid",
        "kid test-2, which the issuer's key set doesn't contain.",
        dumps(sign_unchecked(make_body(kid="test-2"))),
        "unknown_key",
    )
    v.text(
        "duplicate-member",
        "campaign appears twice with the same value.",
        base_text[:-1] + ',"campaign":"cmp_9x2a"}',
        "malformed",
    )
    v.text(
        "escaped-duplicate-member",
        "t" + BS + "u0079p duplicates typ once unescaped.",
        base_text[:-1] + ',"t' + BS + 'u0079p":"o2a-sponsored-offer/v0"}',
        "malformed",
    )
    v.text(
        "exponent-number",
        "percent written as 2e1.",
        replace_once(base_text, '"percent":20', '"percent":2e1'),
        "malformed",
    )
    unknown_text = dumps(sign_unchecked(make_body(terms=unknown_kind)))
    v.text(
        "negative-zero",
        "-0 inside an unknown kind (a lenient parser would say unsupported).",
        replace_once(unknown_text, '"units":7', '"units":-0'),
        "malformed",
    )
    v.text(
        "nan-number",
        "percent written as NaN.",
        replace_once(base_text, '"percent":20', '"percent":NaN'),
        "malformed",
    )
    v.text(
        "unpaired-surrogate",
        "escaped unpaired surrogate in product.",
        replace_once(base_text, "email API,", "email API" + BS + "ud800,"),
        "malformed",
    )
    v.field(
        "leading-whitespace",
        "product begins with a space.",
        "product",
        " Transactional email API, paid plans",
    )
    v.field(
        "ip-hostname",
        "publisher.domain is an IPv4 address.",
        "publisher.domain",
        "192.0.2.1",
    )
    v.field(
        "uppercase-scheme",
        "merchant.url starts with HTTPS://.",
        "merchant.url",
        "HTTPS://acmemail.example/pricing",
    )
    v.field("impossible-date", "exp on 2026-02-30.", "exp", "2026-02-30T12:00:00Z")
    v.text(
        "escaped-equivalent",
        "" + BS + "u0041 in place of A in merchant.name; same signature.",
        replace_once(base_text, '"Acme Mail"', '"' + BS + 'u0041cme Mail"'),
        "valid",
        expected_block=base,
    )
    decomposed = signed(with_field(make_body(), "merchant.name", "Cafe" + chr(0x301) + " Mail"))
    v.valid(
        "decomposed-unicode",
        "decomposed e + U+0301 verifies exactly as received.",
        decomposed,
    )
    v.text(
        "noncanonical-sig-encoding",
        "last sig character has non-zero unused bits (lenient decoders accept it).",
        _swap_sig(base, lambda s: s[:-1] + {"A": "B", "Q": "R", "g": "h", "w": "x"}[s[-1]]),
        "malformed",
    )

    # --- Further traps for readers in any language ------------------------------------------
    v.text(
        "infinity-number",
        "percent written as Infinity.",
        replace_once(base_text, '"percent":20', '"percent":Infinity'),
        "malformed",
    )
    v.text(
        "negative-infinity-number",
        "percent written as -Infinity.",
        replace_once(base_text, '"percent":20', '"percent":-Infinity'),
        "malformed",
    )
    v.text(
        "exponent-number-uppercase",
        "percent written as 2E1.",
        replace_once(base_text, '"percent":20', '"percent":2E1'),
        "malformed",
    )
    v.text(
        "huge-integer",
        "a 5000-digit integer inside an unknown kind.",
        replace_once(unknown_text, '"units":7', '"units":' + "1" * 5000),
        "malformed",
    )
    v.text(
        "integer-above-safe-range",
        "2^53 inside an unknown kind is out of range.",
        replace_once(unknown_text, '"units":7', '"units":9007199254740992'),
        "malformed",
    )
    v.field(
        "integer-at-safe-limit",
        "2^53-1 inside an unknown kind is in range, so the block is just unsupported.",
        "terms",
        {"kind": "free_units", "units": 2**53 - 1},
        "unsupported",
    )
    with_note = dumps(sign_unchecked(make_body(terms={**unknown_kind, "note": 1})))
    v.text(
        "unpaired-surrogate-key",
        "escaped unpaired surrogate in a member name inside an unknown kind.",
        replace_once(with_note, '"note"', '"' + BS + 'ud800"'),
        "malformed",
    )
    v.field("null-duration", "duration_months is null.", "terms.duration_months", None)
    v.field("array-value", "campaign is an array.", "campaign", ["cmp_9x2a"])
    v.field("boolean-value", "duration_months is true.", "terms.duration_months", True)

    # lengths in code points. U+1D11E is 4 bytes in UTF-8 and 2 units in UTF-16.
    name_80 = ("é" + chr(0x1D11E)) * 40
    v.valid(
        "name-80-codepoints",
        "merchant.name of 80 multi-byte code points.",
        signed(with_field(make_body(), "merchant.name", name_80)),
    )
    v.field(
        "name-81-codepoints",
        "merchant.name of 81 code points.",
        "merchant.name",
        name_80 + "é",
    )
    v.text(
        "decomposed-unicode-normalized",
        "the decomposed-unicode block with its name NFC-normalized after signing.",
        replace_once(
            dumps(decomposed),
            "Cafe" + chr(0x301),
            unicodedata.normalize("NFC", "Cafe" + chr(0x301)),
        ),
        "bad_signature",
    )

    # character boundaries inside a string.
    for code, outcome in [
        (0x1F, "malformed"),
        (0x20, "valid"),
        (0x7E, "valid"),
        (0x7F, "malformed"),
        (0x9F, "malformed"),
        (0xA0, "valid"),
        (0x2028, "malformed"),
        (0x202E, "malformed"),
        (0x2066, "malformed"),
    ]:
        product = "Email" + chr(code) + "API"
        name = f"char-u{code:04x}-{'allowed' if outcome == 'valid' else 'rejected'}"
        description = f"U+{code:04X} inside product."
        if outcome == "valid":
            v.valid(name, description, signed(with_field(make_body(), "product", product)))
        else:
            v.field(name, description, "product", product)

    # edge white space in any string.
    v.field(
        "trailing-whitespace",
        "publisher.name ends with a space.",
        "publisher.name",
        "DevDocs API ",
    )
    v.field(
        "leading-nbsp",
        "merchant.name begins with U+00A0.",
        "merchant.name",
        chr(0xA0) + "Acme Mail",
    )
    v.field(
        "trailing-ideographic-space",
        "product ends with U+3000.",
        "product",
        "Transactional email API" + chr(0x3000),
    )

    # No case folding.
    v.text(
        "uppercase-issuer",
        "iss Offers.Example.",
        dumps(sign_unchecked(make_body(iss="Offers.Example"))),
        "malformed",
    )
    v.field(
        "lowercase-currency",
        "currency usd.",
        "terms",
        {"kind": "amount_off", "amount_minor": 500, "currency": "usd"},
    )
    v.field(
        "kind-wrong-case",
        "kind Percent_Off is just an unknown kind.",
        "terms",
        {"kind": "Percent_Off", "percent": 20},
        "unsupported",
    )

    # Hostnames, in publisher.domain.
    for name, host in [
        ("hostname-unicode-idn", "bücher.example"),
        ("hostname-port", "devdocs.example:443"),
        ("hostname-scheme", "https://devdocs.example"),
        ("hostname-trailing-dot", "devdocs.example."),
        ("hostname-empty-label", "devdocs..example"),
        ("hostname-leading-hyphen", "-devdocs.example"),
        ("hostname-single-label", "devdocs"),
        ("hostname-label-64", "a" * 64 + ".example"),
    ]:
        v.field(name, f"publisher.domain {host}.", "publisher.domain", host)
    v.valid(
        "hostname-punycode",
        "punycode publisher.domain xn--bcher-kva.example.",
        signed(with_field(make_body(), "publisher.domain", "xn--bcher-kva.example")),
    )

    # URLs, in merchant.url.
    url_prefix = "https://acmemail.example/"
    for name, url in [
        ("url-http", "http://acmemail.example/pricing"),
        ("url-userinfo", "https://user@acmemail.example/pricing"),
        ("url-port", "https://acmemail.example:8443/pricing"),
        ("url-non-ascii", url_prefix + "préis"),
        ("url-space", url_prefix + "pricing plans"),
        ("url-bad-percent", url_prefix + "%zz"),
        ("url-2049-chars", url_prefix + "a" * (2049 - len(url_prefix))),
    ]:
        v.field(name, f"merchant.url ({name[4:]}).", "merchant.url", url)
    v.valid(
        "url-2048-chars",
        "merchant.url of exactly 2048 characters.",
        signed(
            with_field(make_body(), "merchant.url", url_prefix + "a" * (2048 - len(url_prefix)))
        ),
    )

    # timestamps, in exp.
    for name, stamp in [
        ("timestamp-lowercase-z", "2026-11-10T12:00:00z"),
        ("timestamp-offset", "2026-11-10T12:00:00+00:00"),
        ("timestamp-fraction", "2026-11-10T12:00:00.000Z"),
        ("timestamp-hour-24", "2026-11-10T24:00:00Z"),
        ("timestamp-leap-second", "2026-12-31T23:59:60Z"),
    ]:
        v.field(name, f"exp {stamp}.", "exp", stamp)

    # claim tokens.
    claim_tail = "KQ2M9XR4TBV8HNE3WPA6CJD0F"
    for name, claim in [
        ("claim-lowercase", "clm_3" + claim_tail.lower()),
        ("claim-letter-i", "clm_3" + claim_tail[:-1] + "I"),
        ("claim-letter-l", "clm_3" + claim_tail[:-1] + "L"),
        ("claim-letter-o", "clm_3" + claim_tail[:-1] + "O"),
        ("claim-letter-u", "clm_3" + claim_tail[:-1] + "U"),
        ("claim-first-char-8", "clm_8" + claim_tail),
    ]:
        v.field(name, f"claim {name[6:]}.", "claim", claim)

    # sig encoding.
    for name, change in [
        ("sig-padded", lambda s: s + "=="),
        ("sig-plus", lambda s: s[:10] + "+" + s[11:]),
        ("sig-slash", lambda s: s[:10] + "/" + s[11:]),
        ("sig-85-chars", lambda s: s[1:]),
        ("sig-87-chars", lambda s: "A" + s),
        ("sig-invalid-char", lambda s: s[:10] + "." + s[11:]),
    ]:
        v.text(name, f"sig ({name[4:]}).", _swap_sig(base, change), "malformed")

    # Step order.
    v.text(
        "extra-member-signed",
        "an extra member, correctly signed, is malformed, not valid.",
        dumps(sign_unchecked(make_body(note="hello"))),
        "malformed",
    )
    v.text(
        "untrusted-issuer-bad-signature",
        "an untrusted issuer is reported before a bad signature.",
        replace_once(dumps(other), '"percent":20', '"percent":25'),
        "untrusted_issuer",
        key_issuers=(TEST_ISSUER, OTHER_ISSUER),
    )

    # expiry boundaries. exp is TEST_NOW + 14 days.
    v.text(
        "now-equals-exp-no-skew",
        "now == exp with no skew tolerance counts as expired.",
        base_text,
        "expired",
        now=exp,
        skew_seconds=0,
    )
    v.add(
        "now-within-skew",
        "now = exp + skew - 1 s is still valid.",
        base_text,
        "valid",
        expected_block=base,
        now=exp + timedelta(seconds=59),
    )
    v.text(
        "now-at-skew-limit",
        "now = exp + skew is expired.",
        base_text,
        "expired",
        now=exp + timedelta(seconds=60),
    )

    # lifetime cap.
    cap = TEST_NOW + timedelta(days=30, seconds=60)
    at_cap = sign_unchecked(with_field(make_body(), "exp", ts(cap)))
    v.valid("exp-at-lifetime-cap", "exp = now + 30 days + skew is valid.", at_cap)
    v.field(
        "exp-past-lifetime-cap",
        "exp = now + 30 days + skew + 1 s is malformed.",
        "exp",
        ts(cap + timedelta(seconds=1)),
    )

    # --- Format spec §12.3: JSON-text rules before the version check ------------------------
    v12 = dumps(sign_unchecked(make_body(typ="o2a-sponsored-offer/v9", extra=[1])))
    v.text(
        "unknown-version-float-in-array",
        "typ v9 with an extra member [1.5]: the JSON-text rules run before the version check.",
        replace_once(v12, '"extra":[1]', '"extra":[1.5]'),
        "malformed",
    )
    v.text(
        "dup-key-in-array",
        'typ v9 with an extra member [{"a": 1, "a": 2}].',
        replace_once(v12, '"extra":[1]', '"extra":[{"a":1,"a":2}]'),
        "malformed",
    )

    # --- Format spec §12.3 locating cases (§4.1.1) -----------------------------------------
    other = signed(make_body(claim=OTHER_CLAIM))
    other_text = dumps(other)

    def in_response(name: str, description: str, text: str, outcome: str) -> None:
        v.add(name, description, text, outcome, expected_block=base, input_kind="response")

    def mcp(name: str, description: str, value: object, outcome: str) -> None:
        text = value if isinstance(value, str) else dumps(value)
        v.add(name, description, text, outcome, expected_block=base, input_kind="mcp_result")

    in_response(
        "duplicate-sponsored",
        "Two different blocks under duplicate top-level o2a_sponsored keys.",
        '{"data":{"total":0},"o2a_sponsored":' + base_text + ',"o2a_sponsored":' + other_text + "}",
        "malformed",
    )
    in_response(
        "duplicate-sponsored-identical",
        "The same block under duplicate top-level o2a_sponsored keys collapses into one.",
        '{"data":{"total":0},"o2a_sponsored":' + base_text + ',"o2a_sponsored":' + base_text + "}",
        "valid",
    )
    in_response(
        "gateway-wrapped",
        'A gateway wrapped the response: block at depth 1 inside {"data": ...}.',
        dumps({"status": "ok", "data": {"results": [], "o2a_sponsored": base}}),
        "valid",
    )
    in_response(
        "wrapped-in-array",
        'Block at depth 2 inside {"results": [ ... ]}.',
        dumps({"results": [{"title": "Sending email", "o2a_sponsored": base}]}),
        "valid",
    )
    in_response(
        "shallowest-wins",
        "A different genuine block embedded at depth 3 can't displace the top-level one.",
        dumps(
            {
                "data": {"comments": [{"body": "nice", "o2a_sponsored": other}]},
                "o2a_sponsored": base,
            }
        ),
        "valid",
    )
    in_response(
        "same-depth-conflict",
        "Two different blocks, both at depth 1: neither is used.",
        dumps({"a": {"o2a_sponsored": base}, "b": {"o2a_sponsored": other}}),
        "malformed",
    )
    in_response(
        "sponsored-flags-ignored",
        'Listings with "sponsored": true and "o2a_sponsored": true flags beside the real block.',
        dumps(
            {
                "results": [
                    {"title": "A", PLAIN: True},
                    {"title": "B", PLAIN: False, MEMBER: True},
                ],
                PLAIN: True,
                MEMBER: base,
            }
        ),
        "valid",
    )
    in_response(
        "sponsored-flags-only",
        'Only "sponsored" and "o2a_sponsored" flags; no block.',
        dumps({"results": [{"title": "A", PLAIN: True, MEMBER: True}], PLAIN: True, MEMBER: False}),
        "none",
    )
    in_response(
        "plain-sponsored-member",
        "A genuine block under a plain sponsored key is not a candidate.",
        dumps({"data": {"results": []}, PLAIN: base}),
        "none",
    )
    in_response(
        "sponsored-object-without-typ",
        "An o2a_sponsored object without typ is not a candidate.",
        dumps({MEMBER: {"label": "Ad", "advertiser": "Acme"}}),
        "none",
    )
    in_response(
        "sponsored-not-object", 'o2a_sponsored is the string "x".', '{"o2a_sponsored":"x"}', "none"
    )
    in_response(
        "unknown-version-candidate",
        "The only candidate has typ o2a-sponsored-offer/v9.",
        dumps({"o2a_sponsored": sign_unchecked(make_body(typ="o2a-sponsored-offer/v9"))}),
        "unsupported",
    )
    too_deep: object = {"o2a_sponsored": base}
    for _ in range(9):
        too_deep = {"wrap": too_deep}
    in_response("too-deep", "The only block is at depth 9.", dumps(too_deep), "none")
    in_response(
        "noise-outside-block",
        "9.99, 1e3, NaN, a 5000-digit integer and duplicate keys outside the block.",
        '{"price":9.99,"count":1e3,"score":NaN,"big":'
        + "1" * 5000
        + ',"meta":{"a":1,"a":2},"o2a_sponsored":'
        + base_text
        + "}",
        "valid",
    )
    in_response(
        "dup-key-inside-block",
        "campaign appears twice (same value) inside the block.",
        '{"data":{},"o2a_sponsored":' + base_text[:-1] + ',"campaign":"cmp_9x2a"}}',
        "malformed",
    )
    in_response("no-block", "An ordinary response.", dumps({"data": {"results": []}}), "none")
    in_response("not-json", "Plain text is not JSON.", "Service temporarily unavailable", "none")

    summary = {"type": "text", "text": "Found 1 result."}
    mcp(
        "mcp-structured",
        "Block in structuredContent.",
        {"content": [summary], "structuredContent": {"results": [], "o2a_sponsored": base}},
        "valid",
    )
    mcp(
        "mcp-text",
        "Block inside JSON in a text content item.",
        {"content": [{"type": "text", "text": dumps({"results": [], "o2a_sponsored": base})}]},
        "valid",
    )
    mcp(
        "mcp-both-identical",
        "The same block in structuredContent and a text item.",
        {
            "content": [{"type": "text", "text": dumps({"o2a_sponsored": base})}],
            "structuredContent": {"o2a_sponsored": base},
        },
        "valid",
    )
    mcp(
        "mcp-mismatch",
        "Different blocks in structuredContent and a text item.",
        {
            "content": [{"type": "text", "text": dumps({"o2a_sponsored": other})}],
            "structuredContent": {"o2a_sponsored": base},
        },
        "malformed",
    )
    mcp(
        "mcp-jsonrpc-wrapped",
        "An MCP result inside a JSON-RPC response.",
        {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {"content": [summary], "structuredContent": {"o2a_sponsored": base}},
        },
        "valid",
    )
    mcp(
        "mcp-prose-text",
        "The text item is prose that starts with {, not JSON.",
        {"content": [{"type": "text", "text": "{braces} mark a set in this notation."}]},
        "none",
    )

    # --- The hint (§4.7) is never a candidate and never changes the outcome ---------------
    def hint(claim: str) -> str:
        return f"Sponsored offer ref {claim}, issued by {base['iss']}"

    in_response(
        "hint-alongside-block",
        "A block with a correct o2a_sponsored_hint beside it: the block is located as usual.",
        dumps(
            {"data": {"total": 0}, "o2a_sponsored": base, "o2a_sponsored_hint": hint(base["claim"])}
        ),
        "valid",
    )
    in_response(
        "hint-only",
        "An o2a_sponsored_hint and no block: a hint is not a block, so there is none.",
        dumps({"data": {"total": 0}, "o2a_sponsored_hint": hint(base["claim"])}),
        "none",
    )
    in_response(
        "hint-mismatched-claim",
        "A block with a hint naming a different claim: the block counts, the hint is ignored.",
        dumps(
            {"data": {"total": 0}, "o2a_sponsored": base, "o2a_sponsored_hint": hint(OTHER_CLAIM)}
        ),
        "valid",
    )
    return v.items


def _swap_sig(block: Block, change: Callable[[str], str]) -> str:
    sig = block["sig"]
    return replace_once(dumps(block), f'"sig":"{sig}"', f'"sig":"{change(sig)}"')


def render(vector: dict[str, Any]) -> str:
    return json.dumps(vector, ensure_ascii=True, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--check", action="store_true", help="fail if vectors/ is out of date")
    args = parser.parse_args(argv)

    expected = {f"{name}.json": render(vector) for name, vector in build().items()}
    if args.check:
        actual = {p.name: p.read_text(encoding="utf-8") for p in VECTORS_DIR.glob("*.json")}
        stale = sorted(n for n in expected if actual.get(n) != expected[n])
        extra = sorted(set(actual) - set(expected))
        for name in stale:
            print(f"out of date or missing: vectors/{name}")
        for name in extra:
            print(f"not generated: vectors/{name}")
        if stale or extra:
            return 1
        print(f"vectors/ is up to date ({len(expected)} vectors)")
        return 0

    VECTORS_DIR.mkdir(exist_ok=True)
    for path in VECTORS_DIR.glob("*.json"):
        if path.name not in expected:
            path.unlink()
    for name, text in expected.items():
        (VECTORS_DIR / name).write_text(text, encoding="utf-8")
    print(f"wrote {len(expected)} vectors to {VECTORS_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
