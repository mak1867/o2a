# o2a-protocol

The reference implementation of **O2A (Offers to Agents) Format v0**: signed, offline-verifiable
discount offers that publishers attach to responses served to AI agents.

- Format spec (what is correct): [`docs/o2a-format-v0.md`](docs/o2a-format-v0.md)
- Roadmap (planned for v1): [`ROADMAP.md`](ROADMAP.md)

Any implementation, in any language, that follows the format spec and passes the vectors in
`vectors/` is conformant. This package is one such implementation.

The base package covers strict JSON parsing, validation, canonicalization (RFC 8785), claim
tokens and offer IDs, Ed25519 signing and verification, static key handling, and finding
blocks inside whole responses. It has no network code. The optional `[http]` extra adds an
HTTPS key resolver and the claim client:

```sh
pip install 'o2a-protocol[http]'   # or: uv add 'o2a-protocol[http]'
```

Everything beyond `Verifier.verify` is an optional helper. A harness that pulls out the
`o2a_sponsored` member its own way can pass the raw block text straight to `verify`.

> **Warning: the test key is public.** `o2a_protocol.testing` uses the RFC 8032 §7.1 Test 1
> key, whose private seed is printed in the RFC. Anyone can sign blocks with it. Never trust
> `offers.example` or that key outside tests.

## Quickstart

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run python
```

```python
import json
from datetime import timedelta

from o2a_protocol import Outcome, Signer, StaticKeyResolver, Verifier, new_claim_token
from o2a_protocol.testing import TEST_NOW, TEST_SEED, make_body
from o2a_protocol.validate import format_timestamp

# Issuer side: build a body and sign it.
signer = Signer.from_seed("offers.example", "test-1", TEST_SEED)
body = make_body(claim=new_claim_token(), exp=format_timestamp(TEST_NOW + timedelta(days=7)))
block = signer.sign(body, now=TEST_NOW)

# Reader side: trust the issuer from configuration, then verify the raw text.
verifier = Verifier(
    ["offers.example"],
    StaticKeyResolver({"offers.example": {"test-1": signer.public_key()}}),
)
result = verifier.verify(json.dumps(block), now=TEST_NOW)

assert result.outcome is Outcome.VALID
print(result.offer_id)  # off_... : log this, never the claim token
print(result.offer.terms)  # PercentOff(percent=20, duration_months=3)
```

`o2a_protocol.testing` also provides ready-made `test_signer()`, `test_resolver()` and
`test_verifier()`, plus `with_field`, `without_field` and `sign_unchecked` for building
negative test cases.

## Outcomes

`Verifier.verify` returns a `VerificationResult` for **any** input and never raises for bad
input. The steps run in order, and the first failure decides the outcome (format spec §7).

| Outcome | Meaning |
|---|---|
| `valid` | Every check passed. `result.offer` holds the typed offer. |
| `unsupported` | Not a block this reader supports: not an object, an unknown `typ`, or an unknown `terms.kind`. Ignore it silently. |
| `malformed` | Breaks a format rule: strict JSON, members, value rules, or `exp` more than 30 days ahead. |
| `untrusted_issuer` | `iss` isn't in the reader's configured trusted issuers. |
| `unknown_key` | No key with this `kid` is available for the issuer. |
| `bad_signature` | The Ed25519 signature doesn't verify against `JCS(body)`. |
| `expired` | The current time is at or after `exp` (with up to 60 s skew tolerance). |

Only `valid` blocks may be stored, displayed as offers or claimed. `result.offer_id` is set
whenever the input had a well-formed claim token, so failures can be logged by offer ID.

## Extracting blocks from responses and MCP results

`Verifier.verify_response` finds the block in a whole publisher response or MCP tool result,
then verifies it:

```python
report = verifier.verify_response(response_text)  # mode="auto" by default
report.status  # "found", "none", "conflict" or "not_json"
report.locations  # e.g. ("/data/o2a_sponsored",) or ("/result/content/0/text#/o2a_sponsored",)
report.result  # a VerificationResult, or None when there is no block
```

**Shallowest wins.** A response carries at most one block. The extractor looks for
`"o2a_sponsored": {... "typ": ...}` members breadth-first, up to depth 8, and keeps only the
shallowest ones (format spec §4.1.1):

- A gateway that wraps the response pushes everything down equally, so the publisher's own
  block is still the shallowest.
- A block copied into user content (a review, a search result) sits deeper than the
  publisher's, so it can't displace it.
- Identical copies at the same depth count as one. Two *different* blocks at the same depth
  make the result `malformed`, because the reader can't tell which one is the publisher's.
- Only the `o2a_sponsored` name counts, so publishers' own `"sponsored": true` flags never
  clash. An `o2a_sponsored` member that isn't an object with `typ` is ignored too.

The response is parsed tolerantly, so floats, `NaN` or duplicate keys elsewhere in it don't
matter. Only the block's own subtree must pass the strict JSON rules, exactly as if it had
been given to `verify` on its own.

`mode="mcp"` reads `structuredContent` and JSON text items (unwrapping a JSON-RPC response
first). `mode="auto"` picks MCP for MCP-shaped input and plain JSON otherwise. To keep every
detail of a larger payload, such as a hook's stdin, parse it once with `parse_tolerant`, pick
the node with `get_path`, and pass that node in. Plain `dict`s are rejected, because
`json.loads` has already dropped duplicate keys.

## Keys: a pinned key plus HTTPS

```python
from o2a_protocol import ChainedKeyResolver, StaticKeyResolver, Verifier
from o2a_protocol.keys_http import HttpKeyResolver  # needs the [http] extra

trusted = ["offers.example"]
keys = ChainedKeyResolver(
    StaticKeyResolver({"offers.example": {"2026-10-a": pinned_public_key}}),  # checked first
    HttpKeyResolver(trusted),  # fetches https://offers.example/.well-known/o2a-keys.json
)
verifier = Verifier(trusted, keys)
```

`HttpKeyResolver` only ever fetches issuers in its own trusted list, because `iss` comes from
untrusted block content. It caches key sets according to `Cache-Control: max-age` (capped at
1 hour), refetches for an unknown `kid` at most once per 5 minutes, follows only same-host
HTTPS redirects, and never raises: a failure just means `unknown_key`. A wallet can persist
the cache with `snapshot()` and restore it with `load_snapshot()` to verify offline after a
restart.

> **Revocation is not instant.** An issuer revokes a key by removing it from its key set, but
> a reader can keep accepting a cached copy for up to `max_ttl + max_stale`: **two hours by
> default**. That's up to 1 hour while the cached set is fresh, plus up to 1 more hour of
> serving the stale set if refetching fails. This bounded window is what lets readers verify
> offline and ride out issuer outages. Lower `max_ttl` and `max_stale` to shorten it.

## Claiming

Claim only once a purchase has been decided (format spec §9.3), and only a verified offer:

```python
from o2a_protocol.claims import ClaimClient, ClaimError  # needs the [http] extra

with ClaimClient(["offers.example"]) as claims:
    try:
        result = claims.claim(result.offer)  # optionally buyer_email="..."
        print(result.code, result.exp)  # enter result.code at checkout, as given
    except ClaimError as error:
        print(error.kind, error.detail)  # e.g. already_claimed, rate_limited
```

The client re-checks `exp` before sending, sends buyer details only when you pass them, and
retries network errors, 5xx responses and short `Retry-After` 429s (claims are idempotent).
It never follows redirects. The claim token and the promo code never appear in exception
messages or `repr` output.

## Development

```sh
uv run --extra http pytest --cov                  # all tests, with branch coverage
uv run --exact pytest                             # base package alone, without httpx
uv run --extra http mypy                          # strict type checking
uv run ruff check . && uv run ruff format --check .
uv run python scripts/generate_vectors.py --check # vectors/ matches the generator
```

The suite blocks all network access; HTTP code is tested against `httpx.MockTransport`.

`vectors/` holds the conformance vectors in the format spec §12.2 format. Every conformant
reader, in any language, must produce the expected outcome for every vector. Tests only read
the committed files; regenerate them with `uv run python scripts/generate_vectors.py`.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
