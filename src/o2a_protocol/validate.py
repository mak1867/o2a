"""Structural and value validation (format spec §4, §5; §7 steps 1-3).

Validation never checks time: expiry and the 30-day cap are the verifier's job.
Every type check is exact (``type(x) is int``), so ``bool`` and subclasses are rejected.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

from .ids import CLAIM_RE
from .outcomes import Outcome
from .strictjson import MAX_SAFE_INTEGER

TYP_V0 = "o2a-sponsored-offer/v0"

Problem = tuple[Outcome, str]

BODY_MEMBERS = frozenset(
    {"typ", "iss", "kid", "campaign", "publisher", "merchant", "product", "terms", "claim", "exp"}
)
BLOCK_MEMBERS = BODY_MEMBERS | {"sig"}
_PUBLISHER_MEMBERS = frozenset({"name", "domain"})
_MERCHANT_MEMBERS = frozenset({"name", "url"})
# kind -> (required members, optional members)
_TERM_KINDS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "percent_off": (frozenset({"kind", "percent"}), frozenset({"duration_months"})),
    "amount_off": (frozenset({"kind", "amount_minor", "currency"}), frozenset({"duration_months"})),
}

_BANNED_CHAR = re.compile(
    r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069\ud800-\udfff]"
)
_EDGE_WHITESPACE = frozenset(
    "\t\n\x0b\x0c\r\x20\x85\xa0\u1680\u2028\u2029\u202f\u205f\u3000"
) | frozenset(chr(c) for c in range(0x2000, 0x200B))
_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")
_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_URL_AUTHORITY_END = re.compile(r"[/?#]")
_URL_REST_RE = re.compile(r"(?:[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*")
_SIG_RE = re.compile(r"[A-Za-z0-9_-]{85}[AQgw]")
_CURRENCY_RE = re.compile(r"[A-Z]{3}")
# [0-9], not \d: in Python, \d also matches non-ASCII digits such as "٣".
_TIMESTAMP_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z")


def validate_block(value: object) -> Problem | None:
    """Check a parsed block (with ``sig``).

    Returns ``None``, or ``(UNSUPPORTED | MALFORMED, detail)``.
    """
    return _validate(value, with_sig=True)


def validate_body(value: object) -> Problem | None:
    """Check a body (a block without ``sig``), as the signer does."""
    return _validate(value, with_sig=False)


# Field formats --------------------------------------------------------------------------


def is_hostname(value: object) -> bool:
    """Format spec §4.4.1."""
    if type(value) is not str or not 1 <= len(value) <= 253:
        return False
    labels = value.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.fullmatch(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def is_url(value: object) -> bool:
    """Format spec §4.4.2."""
    if type(value) is not str or len(value) > 2048 or not value.isascii():
        return False
    if not value.startswith("https://"):
        return False
    rest = value[len("https://") :]
    end = _URL_AUTHORITY_END.search(rest)
    split = end.start() if end else len(rest)
    return is_hostname(rest[:split]) and _URL_REST_RE.fullmatch(rest[split:]) is not None


def is_id(value: object) -> bool:
    """``kid`` and ``campaign``: 1-64 characters of ``[A-Za-z0-9._-]``."""
    return type(value) is str and _ID_RE.fullmatch(value) is not None


def parse_timestamp(value: object) -> datetime | None:
    """Format spec §4.4.3. Returns an aware UTC datetime, or ``None`` if invalid."""
    if type(value) is not str:
        return None
    match = _TIMESTAMP_RE.fullmatch(value)
    if match is None:
        return None
    year, month, day, hour, minute, second = (int(group) for group in match.groups())
    try:
        # The constructor rejects impossible dates, hour 24 and second 60.
        return datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    except ValueError:
        return None


def format_timestamp(moment: datetime) -> str:
    """Format an aware datetime with whole seconds as a §4.4.3 timestamp."""
    if moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if moment.microsecond:
        raise ValueError("timestamp must have whole seconds")
    t = moment.astimezone(UTC)
    return f"{t.year:04d}-{t.month:02d}-{t.day:02d}T{t.hour:02d}:{t.minute:02d}:{t.second:02d}Z"


def string_problem(value: str) -> str | None:
    """The §4.4 string rules shared by every string at every depth."""
    if _BANNED_CHAR.search(value):
        return "contains a control, separator, bidi or surrogate character"
    if value and (value[0] in _EDGE_WHITESPACE or value[-1] in _EDGE_WHITESPACE):
        return "begins or ends with white space"
    return None


# Internals ------------------------------------------------------------------------------


def _validate(value: object, *, with_sig: bool) -> Problem | None:
    # Step 1: is this a block type we support?
    if type(value) is not dict:
        return Outcome.UNSUPPORTED, "not a JSON object"
    typ = value.get("typ")
    if type(typ) is not str:
        return Outcome.UNSUPPORTED, "typ: missing or not a string"
    if typ != TYP_V0:
        return Outcome.UNSUPPORTED, "typ: unsupported block type"

    # Step 2: every §4 rule, except that an unknown terms.kind is not a failure yet.
    detail = _value_rules(value) or _block_rules(value, with_sig=with_sig)
    if detail is not None:
        return Outcome.MALFORMED, detail

    # Step 3: terms.kind is supported and terms satisfies §5.
    terms = value["terms"]
    assert type(terms) is dict  # checked by _block_rules
    return _terms_rules(terms)


def _value_rules(root: dict[object, object]) -> str | None:
    """§4.4 at every depth: only objects, strings and safe integers; the string rules."""
    stack: list[tuple[str, object]] = [("", root)]
    while stack:
        path, value = stack.pop()
        kind = type(value)
        if kind is dict:
            assert isinstance(value, dict)
            for key, child in value.items():
                if type(key) is not str:
                    return f"{_where(path)}: member names must be strings"
                problem = string_problem(key)
                if problem is not None:
                    return f"{_where(path)}: member name {problem}"
                stack.append((_join(path, key), child))
        elif kind is str:
            assert isinstance(value, str)
            problem = string_problem(value)
            if problem is not None:
                return f"{_where(path)}: {problem}"
        elif kind is int:
            assert isinstance(value, int)
            if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
                return f"{_where(path)}: integer out of range"
        else:
            return f"{_where(path)}: {_type_name(value)} is not allowed"
    return None


def _block_rules(block: dict[object, object], *, with_sig: bool) -> str | None:
    detail = _members("", block, BLOCK_MEMBERS if with_sig else BODY_MEMBERS)
    if detail is not None:
        return detail
    if not is_hostname(block["iss"]):
        return "iss: expected a hostname"
    if not is_id(block["kid"]):
        return "kid: expected 1-64 characters of [A-Za-z0-9._-]"
    if not is_id(block["campaign"]):
        return "campaign: expected 1-64 characters of [A-Za-z0-9._-]"

    publisher = block["publisher"]
    if type(publisher) is not dict:
        return "publisher: expected an object"
    detail = _members("publisher", publisher, _PUBLISHER_MEMBERS)
    if detail is not None:
        return detail
    if not _is_text(publisher["name"]):
        return "publisher.name: expected a string of 1-80 code points"
    if not is_hostname(publisher["domain"]):
        return "publisher.domain: expected a hostname"

    merchant = block["merchant"]
    if type(merchant) is not dict:
        return "merchant: expected an object"
    detail = _members("merchant", merchant, _MERCHANT_MEMBERS)
    if detail is not None:
        return detail
    if not _is_text(merchant["name"]):
        return "merchant.name: expected a string of 1-80 code points"
    if not is_url(merchant["url"]):
        return "merchant.url: expected an https URL"

    if not _is_text(block["product"]):
        return "product: expected a string of 1-80 code points"
    if type(block["terms"]) is not dict:
        return "terms: expected an object"
    claim = block["claim"]
    if type(claim) is not str or CLAIM_RE.fullmatch(claim) is None:
        return "claim: expected a claim token"
    if parse_timestamp(block["exp"]) is None:
        return "exp: expected a timestamp YYYY-MM-DDTHH:MM:SSZ with a real date and time"
    if with_sig:
        sig = block["sig"]
        if type(sig) is not str or _SIG_RE.fullmatch(sig) is None:
            return "sig: expected 86 characters of canonical unpadded base64url"
    return None


def _terms_rules(terms: dict[object, object]) -> Problem | None:
    if "kind" not in terms:
        return Outcome.MALFORMED, "terms.kind: missing member"
    kind = terms["kind"]
    if type(kind) is not str:
        return Outcome.MALFORMED, "terms.kind: expected a string"
    if kind not in _TERM_KINDS:
        return Outcome.UNSUPPORTED, f"terms.kind: unsupported kind {_safe(kind)}"
    required, optional = _TERM_KINDS[kind]
    detail = _members("terms", terms, required, optional)
    if detail is None:
        detail = _terms_values(kind, terms)
    return None if detail is None else (Outcome.MALFORMED, detail)


def _terms_values(kind: str, terms: dict[object, object]) -> str | None:
    if kind == "percent_off":
        if not _is_int_in(terms["percent"], 1, 100):
            return "terms.percent: expected an int in 1..100"
    else:
        if not _is_int_in(terms["amount_minor"], 1, 1_000_000_000):
            return "terms.amount_minor: expected an int in 1..1000000000"
        currency = terms["currency"]
        if type(currency) is not str or _CURRENCY_RE.fullmatch(currency) is None:
            return "terms.currency: expected an uppercase ISO 4217 code"
    if "duration_months" in terms and not _is_int_in(terms["duration_months"], 1, 36):
        return "terms.duration_months: expected an int in 1..36"
    return None


def _members(
    path: str,
    obj: dict[object, object],
    required: frozenset[str],
    optional: frozenset[str] = frozenset(),
) -> str | None:
    keys = set(obj)
    missing = required - keys
    if missing:
        return f"{_where(path)}: missing member {', '.join(sorted(missing))}"
    extra = keys - required - optional
    if extra:
        names = sorted(_safe(name) for name in extra)
        return f"{_where(path)}: unexpected member {', '.join(names)}"
    return None


def _is_text(value: object) -> bool:
    return type(value) is str and 1 <= len(value) <= 80


def _is_int_in(value: object, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "boolean"
    if type(value) in (list, tuple):
        return "array"
    if type(value) is float:
        return "non-integer number"
    return f"value of type {type(value).__name__}"


def _safe(name: object) -> str:
    """Render untrusted text for a detail string: escaped, quoted and truncated."""
    text = str(name)
    if is_id(text):
        return text
    return repr(text[:32] + ("…" if len(text) > 32 else ""))


def _join(path: str, key: str) -> str:
    segment = key if is_id(key) else _safe(key)
    return f"{path}.{segment}" if path else segment


def _where(path: str) -> str:
    return path or "block"
