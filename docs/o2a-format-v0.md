# O2A (Offers to Agents) — Format v0

**Status:** Draft 0.3 · 2026-10-29 (0.3 names the format O2A: the `o2a_sponsored` member, the `o2a-sponsored-offer/v0` type and the `o2a-keys.json` key set. 0.2 added strict JSON, string, hostname, URL and timestamp rules.)
**Author:** Ivaylo
**Name:** O2A, short for "Offers to Agents".

---

## 1. Scope

This document defines:

1. The **sponsored block**: a signed JSON object carrying a discount offer, which publishers attach to responses served to AI agents.
2. How blocks are **canonicalized, signed and verified** (Ed25519).
3. How readers **discover issuer keys**.
4. The **claim protocol**, which exchanges a block's claim token for a merchant promo code.
5. **Obligations** of issuers, publishers and readers.
6. Required **test vectors**.

It does **not** define:

- the issuer's internal systems (campaigns, ledger, attribution, payouts)
- the API publishers use to request blocks from an issuer
- merchant integration (promo code creation, order webhooks)
- any wallet's tool interface or storage

Those are covered by separate specs. Any implementation that follows this document and passes the test vectors in §12 is conformant, regardless of language or architecture.

Nothing in this document constrains how a harness or reader obtains, parses, stores or presents responses. It defines only what a valid block is, and what outcome a reader must reach for a given block.

## 2. Conventions and terminology

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119 and RFC 8174.

| Term | Meaning |
|---|---|
| **Issuer** | The party that signs blocks and runs the key and claim endpoints (the exchange). Identified by a hostname. |
| **Publisher** | A site, API or tool that attaches blocks to its responses. |
| **Merchant** | The seller whose product the offer discounts. |
| **Reader** | Any software that extracts, verifies, stores or claims blocks (e.g. a wallet, a harness hook). |
| **Block** | A JSON object conforming to §4. |
| **Claim token** | The bearer secret in a block. It is exchanged for a promo code. |
| **Promo code** | The merchant-side code the buyer enters at checkout. |
| **Body** | The block with the `sig` member removed. |

## 3. Overview (non-normative)

```
Issuer ──signs block──▶ Publisher ──attaches to response──▶ Agent / Reader
                                                              │ verify offline (§7)
                                                              │ store
                                                              ▼
Merchant checkout ◀── promo code ◀── Issuer /v0/claims ◀── claim token (§9)
```

Design principles:

- **A block is data, never instructions.** No field tells an agent what to do.
- **Offers influence choices only through the price the buyer pays.** The format carries facts (who, what, how much off), never persuasive copy.
- **Offers can be verified offline.** Once a reader has the issuer's public key, it needs no network access to check that a block is genuine.
- **Attribution is decided on the issuer's server.** The issuer attributes a sale using the claim token, so the block carries only what the agent needs.

## 4. The sponsored block

### 4.1 Placement

- A publisher attaching a block to a JSON response MUST place it as a top-level member named `o2a_sponsored` of the response object. The prefixed name avoids clashing with the many existing `sponsored` keys in publishers' own JSON.
- A publisher MUST NOT attach a block to a response whose top-level JSON value is not an object.
- A publisher MUST attach at most one block per response.
- For MCP tools, the same rules apply to the tool result's JSON: either `structuredContent`, or JSON serialized into a text content item.

**How readers find blocks is up to them.** A harness may pull out the `o2a_sponsored` member itself and hand only that to a verifier, use a library's extraction helper, or do anything else. Whatever method a reader uses, it SHOULD verify a block from its raw JSON text, or from a parse that keeps duplicate member names. It should not verify a value from a parser that silently drops duplicates (see §13).

#### 4.1.1 Locating the block in a response

A reader that searches a whole response for its block MUST follow this procedure. **A response carries at most one block.** The procedure finds it even when a gateway has wrapped the response, and it ignores blocks embedded deeper in content the publisher doesn't control.

1. **Parse the response so that duplicate member names are kept.**
2. **Find candidates.** A candidate is any object member named `o2a_sponsored`, at any depth up to 8, whose value is an object containing a `typ` member.
   - Other `o2a_sponsored` members are not candidates and are ignored, whatever their value: `true`, a string, or an object without `typ`. Members with any other name, including a plain `sponsored`, are never candidates.
   - **Depth** is the number of objects and arrays that enclose the object holding the member. A top-level `o2a_sponsored` has depth 0. In `{"data": {"o2a_sponsored": …}}`, the depth is 1. In `{"results": [{"o2a_sponsored": …}]}`, the depth is 2.
   - Members deeper than 8 are not considered.
3. **Keep only the shallowest.** Discard every candidate whose depth is greater than the smallest depth found.
4. **Collapse identical candidates.** Candidates that are equal as JSON values (ignoring member order and whitespace, with numbers compared as written) count as one.
5. **Decide:**
   - Exactly one candidate remains → it is the response's block. Verify it under §7, applying the JSON-text rules of §4.4 to the block's entire subtree, including everything inside arrays, before step 1. The rest of the response is never checked against those rules.
   - More than one remains → the outcome is `malformed`, and none of them is used.
   - None → the response carries no block.

**MCP tool results.** If the result is wrapped in a JSON-RPC response, unwrap `result` first. Then:

- Treat each of the following as a separate document, with depth counted from that document's root:
  - `structuredContent`, if it is an object
  - each text content item whose text is a JSON object (likewise the text of embedded text resources)
- Apply steps 2–4 to each document, then pool the surviving candidates from all documents, collapse identical ones, and decide as in step 5.
- Text items that aren't JSON objects are ignored.

*Rationale (non-normative):*

- Wrapping a response pushes everything down by the same amount, so the publisher's own top-level block stays the shallowest.
- A block copied into user content sits deeper than the publisher's own block, so it can't knock the publisher's block out.
- The prefixed member name avoids false matches with the common `"sponsored": true` flag in listings, and also requiring `typ` guards against any other use of the name.
- If two different blocks sit at the same depth, the reader can't tell which is the publisher's, so it uses neither.

### 4.2 Members

A v0 block MUST contain **exactly** the following members: no more and no fewer. Member names are case-sensitive.

| Member | Type | Constraints |
|---|---|---|
| `typ` | string | Exactly `"o2a-sponsored-offer/v0"`. Declares the version and that the content is sponsored. |
| `iss` | string | Issuer hostname (§4.4.1). |
| `kid` | string | 1–64 characters matching `[A-Za-z0-9._-]`. Identifies the signing key (§8). |
| `campaign` | string | 1–64 characters matching `[A-Za-z0-9._-]`. Opaque campaign identifier. |
| `publisher` | object | Exactly `name` and `domain` (§4.3). |
| `merchant` | object | Exactly `name` and `url` (§4.3). |
| `product` | string | 1–80 characters. A factual noun phrase describing what the terms apply to (§4.4). |
| `terms` | object | §5. |
| `claim` | string | Matches `^clm_[0-7][0-9A-HJKMNP-TV-Z]{25}$` (§4.5). |
| `exp` | string | UTC timestamp (§4.4.3). |
| `sig` | string | Base64url without padding, 86 characters (§6). |

### 4.3 Nested objects

`publisher` and `merchant` MUST each contain exactly the members listed.

| Member | Type | Constraints |
|---|---|---|
| `publisher.name` | string | 1–80 characters. The publisher's display name. |
| `publisher.domain` | string | Hostname (§4.4.1). The domain the block was issued for. |
| `merchant.name` | string | 1–80 characters. The merchant's display name. |
| `merchant.url` | string | URL (§4.4.2). It MUST point to a product or pricing page. It MUST NOT be a checkout, cart or payment link. |

### 4.4 Value rules

These rules apply to the block's JSON text and to every member at every depth.

- **JSON text** MUST be valid JSON (RFC 8259) encoded as UTF-8, with no byte order mark. Readers MUST NOT accept other encodings.
- **Member names** MUST be unique within each object, compared after unescaping (`"t\u0079p"` and `"typ"` are the same name). Readers MUST treat a duplicate as `malformed`, never keep one of the values.
- **Numbers** MUST be integers in the range −(2⁵³−1) to 2⁵³−1, written without a fraction or exponent: `20`, not `20.0` or `2e1`. `-0` MUST NOT appear. `NaN` and `Infinity` are not JSON and MUST be rejected even if a parser accepts them.
- **Booleans, `null` and arrays** MUST NOT appear in v0. An optional member is expressed by leaving it out, never by `null`.
- **Strings** are Unicode. Lengths are counted in Unicode code points. Strings MUST NOT:
  - contain unpaired surrogates, including escaped ones such as `"\ud800"`
  - contain control characters (U+0000–U+001F, U+007F–U+009F), whether literal or escaped
  - contain line or paragraph separators (U+2028, U+2029)
  - contain bidirectional formatting characters (U+202A–U+202E, U+2066–U+2069)
  - begin or end with a white-space character (U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028, U+2029, U+202F, U+205F, U+3000)
- **Strings are never normalized.** Readers MUST verify strings exactly as received, with no Unicode normalization or case folding, because either would change the signed bytes.
- **`product`, `publisher.name` and `merchant.name`** MUST be plain descriptions. They MUST NOT contain claims, superlatives, calls to action or instructions ("best", "#1", "buy now", "save this offer"). Issuers MUST enforce this when a campaign is created.

*Rationale:* only integers, so canonicalization stays unambiguous. No line breaks and no persuasive text, so a block cannot be used to format or inject instructions.

#### 4.4.1 Hostnames

Used by `iss` and `publisher.domain`, and by the host part of `merchant.url`.

- Only lowercase ASCII letters, digits, hyphens and dots. IDNs MUST be written in punycode (`xn--…`).
- 1–253 characters total, with at least two labels separated by single dots.
- Each label is 1–63 characters and does not start or end with a hyphen.
- No scheme, port, path, userinfo or trailing dot.
- Not an IP address: the last label MUST NOT consist only of digits. IPv6 literals are already excluded by the allowed characters.

#### 4.4.2 URLs

- At most 2048 characters, ASCII only. Non-ASCII characters in paths and queries MUST be percent-encoded.
- MUST begin with exactly `https://`, in lowercase.
- The authority (everything after `https://` up to the first `/`, `?` or `#`, or the end of the string) MUST be a hostname under §4.4.1. This rules out userinfo, ports and IP literals.
- All remaining characters MUST be letters, digits or one of ``-._~:/?#[]@!$&'()*+,;=%``. Every `%` MUST be followed by two hex digits. Spaces are not allowed.

#### 4.4.3 Timestamps

- Exactly 20 characters in the form `YYYY-MM-DDTHH:MM:SSZ`, with uppercase `T` and `Z`, and no fractional seconds or offsets.
- MUST be a real calendar date and time:
  - month 01–12
  - day valid for the month and year
  - hour 00–23, minute 00–59 and second 00–59 (no leap second)

### 4.5 Claim tokens and offer IDs

- The issuer generates each claim token from **128 bits** of a cryptographically secure random source. It is encoded as 26 characters of Crockford base32 (uppercase, alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), with two leading zero bits so the first character is `0`–`7`, and prefixed with `clm_`.
- Each issued block MUST carry a claim token that has never been issued before.
- The **offer ID** is derived, not transmitted:

  `offer_id = "off_" + lowercase_hex(SHA-256(ASCII(claim)))[0:24]`

  It is computed over the full claim string, including the `clm_` prefix.
- The claim token is a bearer secret. Readers SHOULD use the offer ID, never the claim token, in logs, telemetry, user interfaces and anything shared beyond the reader's own storage.

### 4.6 Example

```json
{
  "data": { "...": "publisher's normal response" },
  "o2a_sponsored": {
    "typ": "o2a-sponsored-offer/v0",
    "iss": "offers.example",
    "kid": "2026-10-a",
    "campaign": "cmp_9x2a",
    "publisher": { "name": "DevDocs API", "domain": "devdocs.example" },
    "merchant": { "name": "Acme Mail", "url": "https://acmemail.example/pricing" },
    "product": "Transactional email API, paid plans",
    "terms": { "kind": "percent_off", "percent": 20, "duration_months": 3 },
    "claim": "clm_3KQ2M9XR4TBV8HNE3WPA6CJD0F",
    "exp": "2026-11-10T15:00:00Z",
    "sig": "<86 base64url characters>"
  }
}
```

## 5. Terms

`terms` MUST contain a `kind` member. The other members it may contain depend on `kind`, and no members beyond those listed are allowed.

### 5.1 `percent_off`

| Member | Type | Constraints |
|---|---|---|
| `kind` | string | `"percent_off"` |
| `percent` | integer | 1–100 |
| `duration_months` | integer | Optional, 1–36 |

### 5.2 `amount_off`

| Member | Type | Constraints |
|---|---|---|
| `kind` | string | `"amount_off"` |
| `amount_minor` | integer | 1–1,000,000,000, in the currency's ISO 4217 minor unit (cents for USD; yen for JPY) |
| `currency` | string | ISO 4217 alphabetic code, uppercase (e.g. `"USD"`) |
| `duration_months` | integer | Optional, 1–36 |

### 5.3 Duration semantics

- If `duration_months` is **absent**, the discount applies once: to a single purchase, or to the first billing period of a subscription.
- If it is **present**, the discount applies to every billing in the first N months of a subscription. Issuers MUST NOT set it for products that aren't subscriptions.
- Example: "first month free" is `percent_off`, 100, `duration_months` 1.

### 5.4 Unknown kinds

Issuers MAY introduce new `kind` values without changing `typ`. A reader that encounters a `kind` it doesn't support MUST treat the block as `unsupported` (§7) and ignore it.

## 6. Canonicalization and signing

### 6.1 Algorithm

Blocks are signed with **Ed25519** as defined in RFC 8032 §5.1, in its pure form. Ed25519ph and Ed25519ctx are not used.

### 6.2 Signing input

The bytes that are signed are:

```
signing_input = JCS(body)
```

where `body` is the block without `sig`, and `JCS` is the JSON Canonicalization Scheme (RFC 8785), output as UTF-8.

Given the value rules in §4.4 (integer numbers only, no floats), JCS reduces to:

- members sorted by name, at every depth
- no whitespace
- strings escaped minimally per RFC 8785
- integers written in shortest decimal form

### 6.3 Signature encoding

`sig` is the 64-byte Ed25519 signature encoded as base64url without padding (RFC 4648 §5), giving exactly 86 characters.

- The encoding MUST be canonical. The last character carries 4 unused bits, which MUST be zero, so the last character is one of `A`, `Q`, `g` or `w`.
- Readers MUST reject any character outside the base64url alphabet, and any padding, rather than skipping it.

### 6.4 Issuer signing procedure

1. Construct the body and validate it against §4 and §5. An issuer MUST NOT sign an invalid body.
2. Compute `JCS(body)` and sign it with the private key identified by `kid`.
3. Add `sig` to the body to form the block.

Transport formatting doesn't matter. Publishers and intermediaries may re-serialize the block (reorder members, change whitespace), and it stays valid, because verification recomputes the canonical form.

## 7. Verification

Before step 1, the reader parses the input under the JSON-text rules in §4.4. Input that breaks those rules gets the outcome `malformed`: that covers JSON that won't parse, input that isn't UTF-8, duplicate member names, non-integer number tokens and unpaired surrogates. Readers MUST return an outcome for every input and MUST NOT fail with an error.

A reader MUST perform these steps in order and stop at the first failure. The outcome of the first failing step is the result.

| # | Step | Failure outcome |
|---|---|---|
| 1 | Value is a JSON object with a string `typ`, and `typ` is a type the reader supports. | `unsupported` |
| 2 | Block satisfies every member and value rule in §4, except that an unknown `terms.kind` is not a failure at this step. | `malformed` |
| 3 | `terms.kind` is supported by the reader and `terms` satisfies §5. | `unsupported` if the kind is unknown, otherwise `malformed` |
| 4 | `iss` is in the reader's trusted issuer list (§8.3). | `untrusted_issuer` |
| 5 | A public key with id `kid` is available for `iss` (§8.2). | `unknown_key` |
| 6 | The Ed25519 signature `sig` verifies against `JCS(body)` with that key. | `bad_signature` |
| 7 | The current time is earlier than `exp`. Readers MAY allow up to 60 seconds of clock-skew tolerance. | `expired` |
| 8 | `exp` is no more than 30 days after the current time, with the same skew tolerance. Any block further out must have been issued with a lifetime over the cap. | `malformed` |

If all steps pass, the outcome is `valid` and the reader computes `offer_id` (§4.5).

Readers:

- MUST NOT store, display as an offer, or claim a block unless its outcome is `valid`.
- SHOULD ignore `unsupported` blocks silently.
- MAY log other failures, using the outcome name and, where the claim is well-formed, the derived offer ID.
- MUST check `exp` again immediately before claiming.

## 8. Keys

### 8.1 Publication

An issuer MUST publish its verification keys at:

```
https://{iss}/.well-known/o2a-keys.json
```

as a JWK Set (RFC 7517), using the OKP key type for Ed25519 (RFC 8037):

```json
{
  "keys": [
    { "kty": "OKP", "crv": "Ed25519", "kid": "2026-10-a", "x": "<base64url public key>", "use": "sig", "alg": "EdDSA" }
  ]
}
```

- The endpoint MUST be served over HTTPS with a valid certificate.
- It SHOULD set `Cache-Control: max-age` to at most 3600 seconds.

### 8.2 Fetching and caching

- Readers SHOULD cache key sets according to their HTTP cache headers.
- A reader that meets an unknown `kid` from a trusted issuer MAY refetch the key set, but at most once per 5 minutes per issuer.
- Readers MUST NOT follow redirects to a different host.
- Readers MUST ignore keys with a `kty` or `crv` other than `OKP` / `Ed25519`.

### 8.3 Trust

- The trusted issuer list MUST come from the reader's configuration (set by the user or installer). It MUST NOT be derived from block content or responses.
- Trusting an issuer means trusting the keys served at its well-known URL.

### 8.4 Rotation and revocation

- An issuer MUST publish a new key before signing with it.
- An issuer MUST keep a retired key published until every block signed with it has expired.
- Removing a key from the set revokes it. Readers holding a cached copy may keep accepting the key until their cache expires, so the cache lifetime bounds how long a compromised key remains usable.
- An issuer's signing keys MUST be used only for signing blocks.

## 9. Claim protocol

### 9.1 Request

```
POST https://{iss}/v0/claims
Content-Type: application/json

{ "claim": "clm_...", "buyer": { "email": "user@example.com" } }
```

- `buyer` is optional. An issuer MAY require it, for example to enforce one redemption per buyer per campaign, or to bind the promo code to the buyer.
- A reader MUST NOT send buyer details unless the user configured it to.
- There is no other authentication. The claim token is the credential.

### 9.2 Success

```
200 OK
{ "offer_id": "off_...", "code": "AGT7KQ2M9X", "exp": "2026-11-10T15:00:00Z" }
```

- **`code`** is the promo code. Readers MUST treat it as an opaque string, enter it at the merchant's normal checkout exactly as given, and make no assumptions about its format.
- **`exp`** is the code's expiry, in the same timestamp format as the block's `exp`. It MAY be earlier than the block's `exp`.

### 9.3 Semantics

- **Idempotency:** repeating a successful claim with the same claim token and the same buyer (or with no buyer both times) MUST return the same code.
- **Claim limits:** how many distinct claims a token allows is decided by the issuer, and the claim response is authoritative. v0 issuers allow one.
- **Timing:** readers MAY read, store, search and compare offers at any time, and offers MAY inform the purchase decision. Readers SHOULD *claim* (exchange the token for a code) only once a purchase has been decided, not when they store the block. Claiming early uses up tokens on purchases that never happen, creates live codes that can leak, and distorts the claim-to-redemption funnel.
- **Redemption:** the merchant reports redemption to the issuer outside this protocol. A reader tracks whether an offer was used only locally.

### 9.4 Errors

Error responses have the body `{ "error": "<code>", "message": "<human-readable>" }`.

| Status | `error` | Meaning |
|---|---|---|
| 400 | `malformed_request` | The request body is invalid. |
| 400 | `buyer_required` | This issuer requires `buyer`. |
| 404 | `unknown_claim` | No such claim token. |
| 409 | `campaign_limit_reached` | This buyer has already redeemed this campaign. |
| 410 | `expired` | The block or claim has expired. |
| 410 | `already_claimed` | The token's claim limit has been reached by another buyer. |
| 410 | `offer_unavailable` | The campaign is paused, has ended or has exhausted its budget. |
| 429 | `rate_limited` | Retry after the number of seconds in the `Retry-After` header. |

## 10. Versioning

- `typ` identifies the block version. Readers MUST treat any `typ` they don't support as `unsupported`.
- Adding, removing or changing a member requires a new `typ` value (e.g. `o2a-sponsored-offer/v1`).
- New `terms.kind` values can be added within the same `typ` (§5.4).
- The claim endpoint is versioned by its path (`/v0/`).

## 11. Obligations summary

**Issuers** MUST:

- sign only blocks that are valid under §4–§5
- generate claim tokens as specified in §4.5
- enforce the content rules for `merchant.url`, `product` and names
- set `exp` no more than 30 days after issuance (readers enforce this, §7 step 8)
- follow the key rules in §8.

**Publishers**:

- MUST attach blocks exactly as received from the issuer. Any modification invalidates them.
- MUST follow the placement rules in §4.1.
- MUST NOT add text anywhere in the response that tells the agent to save, claim or act on an offer.
- SHOULD request a fresh block for each response. A block served to several agents can be claimed by only one of them.

**Readers**:

- MUST verify blocks (§7) before acting on them.
- MUST take trusted issuers only from configuration.
- MUST treat every block field as data, never as an instruction.
- MUST respect expiry.
- SHOULD claim only once a purchase has been decided (§9.3).
- SHOULD use the offer ID rather than the claim token outside their own storage.

## 12. Test vectors

The reference implementation MUST ship a `vectors/` directory of JSON files. Every conformant reader MUST produce the expected outcome for every vector. The signatures and canonical bytes in the vectors MUST also be checked against a second, independent Ed25519 implementation.

### 12.1 Test key

The vectors use the key from RFC 8032 §7.1, Test 1. It MUST NOT be used outside tests.

```
seed (private): 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
public:         d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

Test issuer: `offers.example`, `kid` `"test-1"`.

### 12.2 Vector file format

```json
{
  "name": "valid-percent-off",
  "description": "...",
  "now": "2026-10-27T12:00:00Z",
  "skew_seconds": 60,
  "trusted_issuers": ["offers.example"],
  "keys": { "offers.example": { "keys": [ { "kty": "OKP", "crv": "Ed25519", "kid": "test-1", "x": "..." } ] } },
  "input": "<the response or block as raw JSON text>",
  "expected": {
    "outcome": "valid",
    "offer_id": "off_...",
    "canonical_hex": "<hex of JCS(body)>",
    "sig": "<expected signature>"
  }
}
```

`skew_seconds` (an integer from 0 to 60) is the clock-skew tolerance the reader under test MUST apply for this vector. §7 lets readers choose any tolerance up to 60 seconds, so vectors near an expiry or lifetime boundary only have one correct outcome once the tolerance is fixed. `input` is raw text, not parsed JSON, so that formatting variations survive.

An optional `input_kind` member says what `input` is:

- `"block"` (the default): a bare block.
- `"response"`: a full publisher JSON response. The block is located using §4.1.1.
- `"mcp_result"`: an MCP tool result, optionally wrapped in a JSON-RPC response, located using the MCP rules in §4.1.1.

For `"response"` and `"mcp_result"` vectors, `expected.outcome` is either an outcome from §7 or `"none"`, meaning the response carries no block. Input that isn't JSON at all also gives `"none"`.

Vectors with `input_kind` `response` or `mcp_result` apply only to readers that extract blocks from whole responses or MCP results. A reader that only verifies blocks handed to it needs to pass only the `block` vectors. `offer_id`, `canonical_hex` and `sig` are required when the outcome is `valid`.

### 12.3 Required cases

| Name | Expected outcome |
|---|---|
| `valid-percent-off` | `valid` (with `duration_months`) |
| `valid-amount-off` | `valid` (without `duration_months`) |
| `valid-non-ascii` | `valid` (merchant name containing non-ASCII characters) |
| `valid-reformatted` | `valid` (members reordered and whitespace added after signing) |
| `valid-embedded` | `valid` (block nested in a full publisher response at top-level `o2a_sponsored`) |
| `tampered-terms` | `bad_signature` (`percent` changed after signing) |
| `tampered-publisher` | `bad_signature` (`publisher.domain` changed after signing) |
| `extra-member` | `malformed` |
| `missing-member` | `malformed` |
| `float-number` | `malformed` (`percent` given as `20.0`) |
| `control-char` | `malformed` (newline in `product`) |
| `checkout-shaped-url` | `valid` at format level (the URL rule is enforced by the issuer and cannot be checked offline; included to document that) |
| `expired` | `expired` |
| `exp-too-far` | `malformed` (`exp` 45 days after `now`) |
| `unknown-typ` | `unsupported` |
| `unknown-kind` | `unsupported` |
| `unknown-version-float-in-array` | `malformed` (`typ` `o2a-sponsored-offer/v9` with an extra member `[1.5]`; the JSON-text rules run before the version check) |
| `dup-key-in-array` | `malformed` (`typ` `o2a-sponsored-offer/v9` with an extra member `[{"a": 1, "a": 2}]`) |
| `untrusted-issuer` | `untrusted_issuer` |
| `unknown-kid` | `unknown_key` |
| `duplicate-member` | `malformed` |
| `escaped-duplicate-member` | `malformed` (`"t\u0079p"` and `"typ"`) |
| `exponent-number` | `malformed` (`2e1`) |
| `negative-zero` | `malformed` |
| `nan-number` | `malformed` |
| `unpaired-surrogate` | `malformed` |
| `leading-whitespace` | `malformed` |
| `ip-hostname` | `malformed` |
| `uppercase-scheme` | `malformed` (`HTTPS://`) |
| `impossible-date` | `malformed` (`2026-02-30`) |
| `escaped-equivalent` | `valid` (`"\u0041"` in place of `"A"`, same signature) |
| `decomposed-unicode` | `valid` (decomposed "é", verified as received) |
| `noncanonical-sig-encoding` | `malformed` (non-zero unused bits in the last character) |

**Locating cases (§4.1.1).** These apply only to readers that search whole responses. The `input_kind` is `response` unless the name starts with `mcp-`, in which case it is `mcp_result`.

| Name | Expected outcome |
|---|---|
| `duplicate-sponsored` | `malformed` (two *different* blocks under duplicate top-level `o2a_sponsored` keys) |
| `duplicate-sponsored-identical` | `valid` (the same block under duplicate top-level `o2a_sponsored` keys) |
| `gateway-wrapped` | `valid` (block at depth 1 inside `{"data": …}`) |
| `wrapped-in-array` | `valid` (block at depth 2 inside `{"results": [ … ]}`) |
| `shallowest-wins` | `valid`, with the top-level block's `offer_id` (a different genuine block is embedded at depth 3) |
| `same-depth-conflict` | `malformed` (two different blocks, both at depth 1) |
| `sponsored-flags-ignored` | `valid` (listings carrying `"sponsored": true` and `"o2a_sponsored": true` alongside the real top-level block) |
| `sponsored-flags-only` | `none` (only `"sponsored"` and `"o2a_sponsored"` flags) |
| `plain-sponsored-member` | `none` (a genuine block under a plain `sponsored` key is not a candidate) |
| `sponsored-object-without-typ` | `none` (an `o2a_sponsored` object without `typ`) |
| `sponsored-not-object` | `none` (`"o2a_sponsored": "x"`) |
| `unknown-version-candidate` | `unsupported` (`typ` `o2a-sponsored-offer/v9`) |
| `too-deep` | `none` (only block at depth 9) |
| `noise-outside-block` | `valid` (the response contains `9.99`, `1e3`, `NaN`, a 5000-digit integer and duplicate keys *outside* the block) |
| `dup-key-inside-block` | `malformed` |
| `no-block` | `none` |
| `not-json` | `none` |
| `mcp-structured` | `valid` |
| `mcp-text` | `valid` (block inside JSON in a text item) |
| `mcp-both-identical` | `valid` (the same block in `structuredContent` and a text item) |
| `mcp-mismatch` | `malformed` (different blocks in `structuredContent` and a text item) |
| `mcp-jsonrpc-wrapped` | `valid` |
| `mcp-prose-text` | `none` (the text item is prose that starts with `{`, not JSON) |

## 13. Security and privacy considerations

- **What the signature guarantees:** the block was issued by the holder of the issuer's key, and the signed members haven't changed. Readers can therefore trust the terms, merchant and publisher offline.
- **What it doesn't guarantee:**
  - Freshness: `exp` bounds it.
  - Exclusivity: anyone can copy a block.
  - Secrecy: the contents are readable.
  - Attribution: the issuer decides attribution from the claim token, so copying a block can't move credit.
- **Bearer tokens and leakage:** a leaked claim token can be claimed by whoever holds it. The format deliberately does not bind tokens to a particular agent or wallet: the issuer doesn't know the agent when it issues a block, and binding would add friction for honest local wallets. The damage is bounded economically instead:
  - single-claim tokens
  - one redemption per buyer per campaign, so no number of leaked tokens gives a buyer more than one discount
  - the 30-day lifetime
  - rate limits on issuance and claims
  - readers keeping tokens out of logs (§4.5)

  Issuers SHOULD default campaigns to new customers only, so a leaked code can only ever acquire a new customer. Whatever leakage remains is a measurement question (incrementality), not a format one.
- **Duplicate members:** a block that repeats a member (`"percent": 5` … `"percent": 50`) can verify against one value while a model reading the raw text sees the other. The signature can't help, because the verifier and the model are reading different things. That's why duplicates are `malformed` (§4.4), and why readers should verify from raw text or from a parse that keeps duplicates (§4.1). The same reasoning is why the locating procedure (§4.1.1) refuses to choose between two different blocks. If a reader doesn't, the worst case is misleading terms, which the claim and checkout then expose. It cannot produce a forged offer.
- **Prompt injection:** blocks contain no instruction fields. Strings are short, can't contain line breaks or bidi controls, and can't contain persuasive copy (§4.4). A block that fails verification is never acted on, so a malicious publisher can't inject fake offers or phishing URLs under a trusted issuer.
- **Key compromise:** remove the key from the set and rotate. Exposure is bounded by readers' cache lifetimes, which is why the cache limit is ≤ 1 hour.
- **Privacy:**
  - `publisher.domain` reveals where the agent has been. In a local wallet that's harmless; a hosted wallet holds a partial browsing history and must disclose this.
  - Buyer email reaches the issuer only if the user configured the reader to send it.
  - Issuers never receive the publisher's response content.
