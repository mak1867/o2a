"""The HTTP key resolver (format spec §8). No real network: MockTransport only."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any

import pytest

httpx = pytest.importorskip("httpx")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from o2a_protocol import ChainedKeyResolver, StaticKeyResolver, make_jwks  # noqa: E402
from o2a_protocol.keys_http import HttpKeyResolver  # noqa: E402
from o2a_protocol.testing import TEST_ISSUER, TEST_KID, test_signer  # noqa: E402

KEY = test_signer().public_key()
KEY2 = Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
JWKS = make_jwks({TEST_KID: KEY})
URL = f"https://{TEST_ISSUER}/.well-known/o2a-keys.json"

Handler = Callable[[Any], Any]


class Clocks:
    def __init__(self) -> None:
        self.mono = 1000.0
        self.wall = 1_800_000_000.0

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.wall += seconds


class Server:
    """A scripted MockTransport that records every request."""

    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any) -> Any:
        self.requests.append(request)
        response = self.responses[0] if len(self.responses) == 1 else self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response(request) if callable(response) else response


def keys_response(document: object = JWKS, **headers: str) -> Any:
    return httpx.Response(200, content=json.dumps(document).encode(), headers=headers)


def make(server: Server, clocks: Clocks | None = None, **kwargs: Any) -> HttpKeyResolver:
    clocks = clocks or Clocks()
    return HttpKeyResolver(
        [TEST_ISSUER],
        client=httpx.Client(transport=httpx.MockTransport(server)),
        clock=lambda: clocks.mono,
        wall_clock=lambda: clocks.wall,
        **kwargs,
    )


def raw(key: Any) -> bytes:
    return bytes(key.public_bytes_raw())


def test_fetches_the_well_known_url_and_caches() -> None:
    server = Server(keys_response())
    resolver = make(server)
    key = resolver.get(TEST_ISSUER, TEST_KID)
    assert key is not None and raw(key) == raw(KEY)
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None
    assert len(server.requests) == 1
    request = server.requests[0]
    assert str(request.url) == URL and request.method == "GET"


def test_untrusted_issuer_makes_no_request() -> None:
    server = Server(keys_response())
    resolver = make(server)
    assert resolver.get("evil.example", TEST_KID) is None
    assert resolver.prefetch("evil.example") is False
    assert server.requests == []


@pytest.mark.parametrize(
    ("cache_control", "ttl"),
    [
        ("max-age=100", 100),
        ("public, max-age=100", 100),
        ("max-age=999999", 3600),
        ("max-age=0", 0),
        ("no-store", 0),
        ("no-cache, max-age=100", 0),
        ("max-age=abc", 600),
        ("max-age=-5", 600),
        (None, 600),
    ],
)
def test_cache_lifetime(cache_control: str | None, ttl: int) -> None:
    headers = {} if cache_control is None else {"cache-control": cache_control}
    server = Server(keys_response(**headers))
    clocks = Clocks()
    resolver = make(server, clocks)
    resolver.get(TEST_ISSUER, TEST_KID)
    if ttl > 0:
        clocks.advance(ttl - 1)
        resolver.get(TEST_ISSUER, TEST_KID)
        assert len(server.requests) == 1
    clocks.advance(1)
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None
    assert len(server.requests) == 2


def test_default_ttl_is_clamped_to_max_ttl() -> None:
    server = Server(keys_response())
    clocks = Clocks()
    resolver = make(server, clocks, default_ttl=timedelta(hours=5), max_ttl=timedelta(seconds=10))
    resolver.get(TEST_ISSUER, TEST_KID)
    clocks.advance(10)
    resolver.get(TEST_ISSUER, TEST_KID)
    assert len(server.requests) == 2


def test_unknown_kid_refetch_is_throttled() -> None:
    server = Server(keys_response())
    clocks = Clocks()
    resolver = make(server, clocks)
    resolver.get(TEST_ISSUER, TEST_KID)
    assert resolver.get(TEST_ISSUER, "test-2") is None  # refetch 1
    assert resolver.get(TEST_ISSUER, "test-2") is None  # throttled
    assert len(server.requests) == 2
    clocks.advance(299)
    resolver.get(TEST_ISSUER, "test-2")
    assert len(server.requests) == 2
    clocks.advance(1)
    server.responses = [keys_response(make_jwks({TEST_KID: KEY, "test-2": KEY2}))]
    key = resolver.get(TEST_ISSUER, "test-2")
    assert key is not None and raw(key) == raw(KEY2)
    assert len(server.requests) == 3


def redirect(location: str, status: int = 302) -> Any:
    return httpx.Response(status, headers={"location": location})


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_same_host_https_redirect_is_followed(status: int) -> None:
    server = Server(redirect(f"https://{TEST_ISSUER}/keys/v2.json", status), keys_response())
    resolver = make(server)
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None
    assert str(server.requests[1].url) == f"https://{TEST_ISSUER}/keys/v2.json"


def test_relative_redirect_and_two_hops_are_followed() -> None:
    server = Server(redirect("/a.json"), redirect("/b.json"), keys_response())
    assert make(server).get(TEST_ISSUER, TEST_KID) is not None


@pytest.mark.parametrize(
    "responses",
    [
        [redirect("https://cdn.example/keys.json")],
        [redirect(f"http://{TEST_ISSUER}/keys.json")],
        [redirect(f"https://{TEST_ISSUER}:8443/keys.json")],
        [redirect("/a"), redirect("/b"), redirect("/c"), keys_response()],
        [httpx.Response(302)],
        [redirect("https://[::1")],
    ],
    ids=["cross-host", "http", "port", "third-redirect", "no-location", "invalid-location"],
)
def test_bad_redirects_fail(responses: list[Any]) -> None:
    server = Server(*responses, keys_response())
    assert make(server).get(TEST_ISSUER, TEST_KID) is None


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b'{"keys":[]}' + b" " * (64 * 1024)),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, content=b"[]"),
        httpx.Response(
            200, content=b'{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"bad"}]}'
        ),
        httpx.Response(404, content=json.dumps(JWKS).encode()),
        httpx.Response(500),
        httpx.ConnectError("refused"),
        httpx.ReadTimeout("slow"),
    ],
    ids=[
        "oversized",
        "not-json",
        "not-object",
        "malformed-jwks",
        "404",
        "500",
        "connect",
        "timeout",
    ],
)
def test_failed_fetches_return_none_never_raise(response: Any) -> None:
    server = Server(response)
    resolver = make(server)
    assert resolver.get(TEST_ISSUER, TEST_KID) is None
    assert resolver.prefetch(TEST_ISSUER) is False  # within the failure backoff: no new request
    assert len(server.requests) == 1


def test_body_of_exactly_64_kib_is_accepted() -> None:
    body = json.dumps(JWKS).encode()
    body += b" " * (64 * 1024 - len(body))
    assert make(Server(httpx.Response(200, content=body))).get(TEST_ISSUER, TEST_KID) is not None


def test_stale_keys_are_served_within_max_stale_then_dropped() -> None:
    server = Server(keys_response(**{"cache-control": "max-age=600"}))
    clocks = Clocks()
    resolver = make(server, clocks)
    resolver.get(TEST_ISSUER, TEST_KID)
    server.responses = [httpx.Response(503)]
    clocks.advance(601)
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None  # refetch failed: stale
    assert len(server.requests) == 2
    clocks.advance(100)
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None  # failure backoff: no request
    assert len(server.requests) == 2
    clocks.advance(200)
    resolver.get(TEST_ISSUER, TEST_KID)  # backoff over: retried
    assert len(server.requests) == 3
    clocks.advance(600 + 3600 - 901 + 1)  # past expiry + max_stale
    assert resolver.get(TEST_ISSUER, TEST_KID) is None
    assert resolver.snapshot() == {"version": 1, "issuers": {}}


def test_unknown_kid_refetch_failure_keeps_fresh_keys() -> None:
    server = Server(keys_response())
    resolver = make(server)
    resolver.get(TEST_ISSUER, TEST_KID)
    server.responses = [httpx.Response(500)]
    assert resolver.get(TEST_ISSUER, "test-2") is None
    assert resolver.get(TEST_ISSUER, TEST_KID) is not None


def test_prefetch() -> None:
    server = Server(keys_response())
    resolver = make(server)
    assert resolver.prefetch(TEST_ISSUER) is True
    assert resolver.prefetch(TEST_ISSUER) is True  # fresh: no request
    assert len(server.requests) == 1


# Snapshots ------------------------------------------------------------------------------


def test_snapshot_round_trip_works_offline() -> None:
    clocks = Clocks()
    source = make(Server(keys_response(**{"cache-control": "max-age=600"})), clocks)
    source.get(TEST_ISSUER, TEST_KID)
    snapshot = json.loads(json.dumps(source.snapshot()))
    assert snapshot["issuers"][TEST_ISSUER]["jwks"] == JWKS

    offline = Server(httpx.ConnectError("offline"))
    restored = make(offline, clocks)
    restored.load_snapshot(snapshot)
    key = restored.get(TEST_ISSUER, TEST_KID)
    assert key is not None and raw(key) == raw(KEY)
    assert offline.requests == []


def test_snapshot_entries_within_max_stale_load_as_stale() -> None:
    clocks = Clocks()
    source = make(Server(keys_response(**{"cache-control": "max-age=600"})), clocks)
    source.get(TEST_ISSUER, TEST_KID)
    snapshot = source.snapshot()
    clocks.advance(600 + 1800)
    offline = Server(httpx.ConnectError("offline"))
    restored = make(offline, clocks)
    restored.load_snapshot(snapshot)
    assert restored.get(TEST_ISSUER, TEST_KID) is not None  # refetch tried, stale served
    assert len(offline.requests) == 1


def test_expired_snapshot_entries_are_dropped() -> None:
    clocks = Clocks()
    source = make(Server(keys_response(**{"cache-control": "max-age=600"})), clocks)
    source.get(TEST_ISSUER, TEST_KID)
    snapshot = source.snapshot()
    clocks.advance(600 + 3600 + 1)
    restored = make(Server(httpx.ConnectError("offline")), clocks)
    restored.load_snapshot(snapshot)
    assert restored.snapshot()["issuers"] == {}
    assert restored.get(TEST_ISSUER, TEST_KID) is None


def test_load_snapshot_skips_bad_entries_and_keeps_fresher_ones() -> None:
    clocks = Clocks()
    resolver = make(Server(keys_response(**{"cache-control": "max-age=600"})), clocks)
    resolver.get(TEST_ISSUER, TEST_KID)
    good = resolver.snapshot()["issuers"]
    assert isinstance(good, dict)
    entry = dict(good[TEST_ISSUER])
    older = {**entry, "expires_at": "2027-01-15T08:00:00Z"}
    resolver.load_snapshot({"version": 1, "issuers": {TEST_ISSUER: older}})
    assert resolver.snapshot()["issuers"] == good

    fresh = make(Server(httpx.ConnectError("offline")), clocks)
    fresh.load_snapshot(
        {
            "version": 1,
            "issuers": {
                "evil.example": entry,
                TEST_ISSUER: {**entry, "jwks": {"keys": [{"kty": "OKP", "crv": "Ed25519"}]}},
            },
        }
    )
    assert fresh.snapshot()["issuers"] == {}
    for bad in [
        "x",
        {**entry, "jwks": []},
        {**entry, "fetched_at": "yesterday"},
        {**entry, "expires_at": None},
    ]:
        fresh.load_snapshot({"version": 1, "issuers": {TEST_ISSUER: bad}})
        assert fresh.snapshot()["issuers"] == {}


@pytest.mark.parametrize(
    "snapshot", [[], {"version": 2, "issuers": {}}, {"issuers": {}}, {"version": 1, "issuers": []}]
)
def test_invalid_snapshot_documents_raise(snapshot: Any) -> None:
    with pytest.raises(ValueError):
        make(Server(keys_response())).load_snapshot(snapshot)


# Concurrency, chaining, construction -----------------------------------------------------


def test_concurrent_gets_make_a_single_fetch() -> None:
    def slow(request: Any) -> Any:
        time.sleep(0.2)
        return keys_response()

    server = Server(slow)
    resolver = make(server)
    results: list[object] = []
    threads = [
        threading.Thread(target=lambda: results.append(resolver.get(TEST_ISSUER, TEST_KID)))
        for _ in range(8)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(server.requests) == 1
    assert len(results) == 8 and all(key is not None for key in results)


def test_chained_resolver_tries_in_order() -> None:
    pinned = StaticKeyResolver({TEST_ISSUER: {TEST_KID: KEY}})
    server = Server(keys_response(make_jwks({TEST_KID: KEY2, "test-2": KEY2})))
    chain = ChainedKeyResolver(pinned, make(server))
    first = chain.get(TEST_ISSUER, TEST_KID)
    assert first is not None and raw(first) == raw(KEY)
    assert server.requests == []
    second = chain.get(TEST_ISSUER, "test-2")
    assert second is not None and raw(second) == raw(KEY2)
    assert chain.get(TEST_ISSUER, "test-3") is None
    assert ChainedKeyResolver().get(TEST_ISSUER, TEST_KID) is None


@pytest.mark.parametrize(
    ("args", "kwargs", "error"),
    [
        (TEST_ISSUER, {}, TypeError),
        (["Offers.Example"], {}, ValueError),
        ([TEST_ISSUER], {"max_stale": timedelta(seconds=-1)}, ValueError),
        ([TEST_ISSUER], {"default_ttl": 600}, ValueError),
    ],
)
def test_constructor_validates(args: Any, kwargs: dict[str, Any], error: type[Exception]) -> None:
    with pytest.raises(error):
        HttpKeyResolver(args, **kwargs)


def test_close_only_closes_its_own_client() -> None:
    with HttpKeyResolver([TEST_ISSUER]) as owned:
        client = owned._client
    assert client.is_closed
    shared = httpx.Client(transport=httpx.MockTransport(Server(keys_response())))
    with HttpKeyResolver([TEST_ISSUER], client=shared):
        pass
    assert not shared.is_closed
