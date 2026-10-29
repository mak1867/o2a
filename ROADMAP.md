# O2A roadmap

These are plans for a future version, not part of the v0 format. v0 is defined entirely by
[`docs/o2a-format-v0.md`](docs/o2a-format-v0.md).

## Planned for v1

- **A placement for responses that aren't JSON.** An HTTP response header that carries the block,
  so publishers serving HTML, plain text or binary content can attach offers too.
- **More term kinds:** `credit` (account credit) and `free_units` (for example, free API calls),
  once a merchant integration can honor them. New kinds can be added without changing `typ`
  (format spec §5.4).

## Settled in v0

- **Requiring a buyer at claim time** is left to each issuer: an issuer MAY require `buyer`
  (format spec §9.1).
