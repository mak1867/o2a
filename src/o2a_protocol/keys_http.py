"""Fetching and caching issuer keys over HTTPS (format spec §8).

Needs the ``[http]`` extra: ``pip install 'o2a-protocol[http]'``.

Revocation: removing a key from the issuer's key set revokes it, but a resolver may keep
accepting a cached copy for up to ``max_ttl + max_stale`` (two hours by default): up to
``max_ttl`` while the cached set is fresh, and up to ``max_stale`` longer if refetching
fails. That bounded window is the price of verifying offline and surviving issuer outages.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

try:
    import httpx
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "o2a_protocol.keys_http needs the [http] extra: pip install 'o2a-protocol[http]'"
    ) from exc

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .keys import ChainedKeyResolver, parse_jwks
from .strictjson import StrictJSONError, parse_strict_json
from .validate import format_timestamp, is_hostname, parse_timestamp

__all__ = ["ChainedKeyResolver", "HttpKeyResolver"]

MAX_KEYSET_BYTES = 64 * 1024
MAX_REDIRECTS = 2
SNAPSHOT_VERSION = 1
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class _FetchFailed(Exception):
    pass


@dataclass
class _Entry:
    keys: dict[str, Ed25519PublicKey]
    document: dict[str, object]
    expires: float  # monotonic
    fetched_wall: float
    expires_wall: float


@dataclass
class _IssuerState:
    lock: threading.Lock
    entry: _Entry | None = None
    last_failure: float | None = None  # monotonic
    last_kid_refetch: float | None = None  # monotonic


class HttpKeyResolver:
    """A ``KeyResolver`` that fetches ``https://{iss}/.well-known/o2a-keys.json``.

    Only issuers in its own trusted set are ever fetched, because ``iss`` comes from
    untrusted block content. Failures never raise: they surface as ``None``, which the
    verifier reports as ``unknown_key``.
    """

    def __init__(
        self,
        trusted_issuers: Iterable[str],
        *,
        client: httpx.Client | None = None,
        timeout: float = 5.0,
        default_ttl: timedelta = timedelta(seconds=600),
        max_ttl: timedelta = timedelta(seconds=3600),
        min_refetch_interval: timedelta = timedelta(seconds=300),
        max_stale: timedelta = timedelta(seconds=3600),
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if isinstance(trusted_issuers, str):
            raise TypeError("trusted_issuers must be a collection of hostnames, not one string")
        self._trusted = frozenset(trusted_issuers)
        for iss in self._trusted:
            if not is_hostname(iss):
                raise ValueError(f"trusted issuer {iss!r} is not a hostname")
        for name, value in [
            ("default_ttl", default_ttl),
            ("max_ttl", max_ttl),
            ("min_refetch_interval", min_refetch_interval),
            ("max_stale", max_stale),
        ]:
            if not isinstance(value, timedelta) or value < timedelta(0):
                raise ValueError(f"{name} must be a non-negative timedelta")
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout, follow_redirects=False)
        self._default_ttl = default_ttl.total_seconds()
        self._max_ttl = max_ttl.total_seconds()
        self._min_refetch = min_refetch_interval.total_seconds()
        self._max_stale = max_stale.total_seconds()
        self._clock = clock
        self._wall_clock = wall_clock
        self._states: dict[str, _IssuerState] = {}
        self._states_lock = threading.Lock()

    # KeyResolver ---------------------------------------------------------------------

    def get(self, iss: str, kid: str) -> Ed25519PublicKey | None:
        """The key ``kid`` for a trusted issuer, or ``None``. May make network requests."""
        if iss not in self._trusted:
            return None
        state = self._state(iss)
        with state.lock:
            now = self._clock()
            entry = state.entry
            if entry is not None and now < entry.expires:
                if kid in entry.keys:
                    return entry.keys[kid]
                # Unknown kid while fresh: the issuer may have rotated. Refetch, throttled.
                if self._may_refetch_kid(state, now):
                    state.last_kid_refetch = now
                    self._refresh(iss, state, now)
            elif self._may_retry_after_failure(state, now):
                self._refresh(iss, state, now)
            return self._lookup(state, kid, now)

    def prefetch(self, iss: str) -> bool:
        """Warm the cache for a trusted issuer. Returns whether fresh keys are now cached."""
        if iss not in self._trusted:
            return False
        state = self._state(iss)
        with state.lock:
            now = self._clock()
            if state.entry is not None and now < state.entry.expires:
                return True
            if not self._may_retry_after_failure(state, now):
                return False
            return self._refresh(iss, state, now)

    # Snapshots -----------------------------------------------------------------------

    def snapshot(self) -> dict[str, object]:
        """Export the cache (JSON-serializable) so a wallet can verify offline after a restart."""
        issuers: dict[str, object] = {}
        for iss, state in list(self._states.items()):
            with state.lock:
                entry = state.entry
                if entry is not None:
                    issuers[iss] = {
                        "jwks": entry.document,
                        "fetched_at": _stamp(entry.fetched_wall),
                        "expires_at": _stamp(entry.expires_wall),
                    }
        return {"version": SNAPSHOT_VERSION, "issuers": issuers}

    def load_snapshot(self, snapshot: dict[str, object]) -> None:
        """Import a snapshot. Every entry is re-validated with ``parse_jwks``.

        Entries for untrusted issuers, invalid entries, and entries more than
        ``max_stale`` past their expiry are dropped. An entry past its expiry but within
        ``max_stale`` loads as stale: it is refetched on first use, and served only if
        that fetch fails. A fresher entry already in the cache is kept.
        """
        if not isinstance(snapshot, dict) or snapshot.get("version") != SNAPSHOT_VERSION:
            raise ValueError("not an O2A key snapshot (version 1)")
        issuers = snapshot.get("issuers")
        if not isinstance(issuers, dict):
            raise ValueError("snapshot 'issuers' must be an object")
        now, wall_now = self._clock(), self._wall_clock()
        for iss, raw in issuers.items():
            entry = self._entry_from_snapshot(iss, raw, now, wall_now)
            if entry is None:
                continue
            state = self._state(iss)
            with state.lock:
                if state.entry is None or state.entry.expires < entry.expires:
                    state.entry = entry

    def close(self) -> None:
        """Close the HTTP client if this resolver created it."""
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> HttpKeyResolver:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # Internals -----------------------------------------------------------------------

    def _state(self, iss: str) -> _IssuerState:
        with self._states_lock:
            state = self._states.get(iss)
            if state is None:
                state = self._states[iss] = _IssuerState(threading.Lock())
            return state

    def _may_retry_after_failure(self, state: _IssuerState, now: float) -> bool:
        return state.last_failure is None or now - state.last_failure >= self._min_refetch

    def _may_refetch_kid(self, state: _IssuerState, now: float) -> bool:
        recent_kid = state.last_kid_refetch is not None and (
            now - state.last_kid_refetch < self._min_refetch
        )
        return not recent_kid and self._may_retry_after_failure(state, now)

    def _lookup(self, state: _IssuerState, kid: str, now: float) -> Ed25519PublicKey | None:
        entry = state.entry
        if entry is None:
            return None
        if now > entry.expires + self._max_stale:
            state.entry = None
            return None
        return entry.keys.get(kid)

    def _refresh(self, iss: str, state: _IssuerState, now: float) -> bool:
        try:
            document, keys, ttl = self._fetch(iss)
        except _FetchFailed:
            state.last_failure = now
            return False
        state.last_failure = None
        wall = self._wall_clock()
        state.entry = _Entry(keys, document, now + ttl, wall, wall + ttl)
        return True

    def _fetch(self, iss: str) -> tuple[dict[str, object], dict[str, Ed25519PublicKey], float]:
        url = httpx.URL(f"https://{iss}/.well-known/o2a-keys.json")
        try:
            for _ in range(MAX_REDIRECTS + 1):
                with self._client.stream(
                    "GET", url, headers={"Accept": "application/json"}, follow_redirects=False
                ) as response:
                    if response.status_code in _REDIRECT_STATUSES:
                        url = _same_host_redirect(url, response.headers.get("location"), iss)
                        continue
                    if response.status_code != 200:
                        raise _FetchFailed
                    body = _read_limited(response)
                    ttl = self._ttl(response.headers.get_list("cache-control"))
                    document = parse_strict_json(body)
                    if not isinstance(document, dict):
                        raise _FetchFailed
                    return document, parse_jwks(document), ttl
            raise _FetchFailed  # too many redirects
        except (httpx.HTTPError, httpx.InvalidURL, StrictJSONError, ValueError):
            raise _FetchFailed from None

    def _ttl(self, cache_control: list[str]) -> float:
        max_age: float | None = None
        for directive in ",".join(cache_control).split(","):
            name, _, value = directive.strip().lower().partition("=")
            if name in {"no-store", "no-cache"}:
                return 0.0
            if name == "max-age" and value.strip().isdigit() and value.strip().isascii():
                max_age = float(value.strip())
        if max_age is None:
            return min(self._default_ttl, self._max_ttl)
        return min(max_age, self._max_ttl)

    def _entry_from_snapshot(
        self, iss: object, raw: object, now: float, wall_now: float
    ) -> _Entry | None:
        if not isinstance(iss, str) or iss not in self._trusted or not isinstance(raw, dict):
            return None
        document, fetched, expires = raw.get("jwks"), raw.get("fetched_at"), raw.get("expires_at")
        fetched_at, expires_at = parse_timestamp(fetched), parse_timestamp(expires)
        if not isinstance(document, dict) or fetched_at is None or expires_at is None:
            return None
        try:
            keys = parse_jwks(document)
        except ValueError:
            return None
        expires_wall = expires_at.timestamp()
        if wall_now > expires_wall + self._max_stale:
            return None
        return _Entry(
            keys, document, now + (expires_wall - wall_now), fetched_at.timestamp(), expires_wall
        )


def _same_host_redirect(current: httpx.URL, location: str | None, iss: str) -> httpx.URL:
    """Follow a redirect only to ``https`` on the same host with no explicit port."""
    if not location:
        raise _FetchFailed
    target = current.join(location)
    if target.scheme != "https" or target.host != iss or target.port is not None:
        raise _FetchFailed
    return target


def _read_limited(response: httpx.Response) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > MAX_KEYSET_BYTES:
            raise _FetchFailed
    return bytes(body)


def _stamp(wall: float) -> str:
    return format_timestamp(datetime.fromtimestamp(int(wall), UTC))
