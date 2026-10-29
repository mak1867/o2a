"""The claim client (format spec §9). No real network: MockTransport only."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

httpx = pytest.importorskip("httpx")

from o2a_protocol import Offer  # noqa: E402
from o2a_protocol.claims import ClaimClient, ClaimError, ClaimErrorKind, ClaimResult  # noqa: E402
from o2a_protocol.testing import (  # noqa: E402
    TEST_CLAIM,
    TEST_ISSUER,
    TEST_NOW,
    make_body,
    test_signer,
    test_verifier,
)

OFFER_ID = "off_a33e5dd43a75be430b008d47"
CODE = "AGT7KQ2M9X"
EXP = datetime(2026, 11, 10, 12, tzinfo=UTC)


def verified_offer() -> Offer:
    block = test_signer().sign(make_body(), now=TEST_NOW)
    offer = test_verifier().verify_parsed(block, now=TEST_NOW).offer
    assert offer is not None
    return offer


OFFER = verified_offer()


class Server:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.requests: list[Any] = []

    def __call__(self, request: Any) -> Any:
        self.requests.append(request)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def ok(**overrides: object) -> Any:
    body = {"offer_id": OFFER_ID, "code": CODE, "exp": "2026-11-01T00:00:00Z", **overrides}
    return httpx.Response(200, content=json.dumps(body).encode())


def error(status: int, code: str, message: str = "nope", **headers: str) -> Any:
    body = json.dumps({"error": code, "message": message}).encode()
    return httpx.Response(status, content=body, headers=headers)


def make(server: Server, **kwargs: Any) -> tuple[ClaimClient, list[float]]:
    sleeps: list[float] = []
    client = ClaimClient(
        [TEST_ISSUER],
        client=httpx.Client(transport=httpx.MockTransport(server)),
        sleep=sleeps.append,
        clock=lambda: TEST_NOW,
        **kwargs,
    )
    return client, sleeps


def claim_error(server: Server, **kwargs: Any) -> ClaimError:
    client, _ = make(server)
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER, **kwargs)
    assert_secret_free(info.value)
    return info.value


def assert_secret_free(value: object) -> None:
    for rendered in (str(value), repr(value)):
        assert TEST_CLAIM not in rendered
        assert CODE not in rendered


# Success -----------------------------------------------------------------------------------


def test_successful_claim() -> None:
    server = Server(ok())
    client, sleeps = make(server)
    result = client.claim(OFFER)
    assert result == ClaimResult(OFFER_ID, CODE, datetime(2026, 11, 1, tzinfo=UTC))
    assert sleeps == []
    request = server.requests[0]
    assert str(request.url) == f"https://{TEST_ISSUER}/v0/claims"
    assert request.method == "POST"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json"
    assert request.headers["user-agent"].startswith("o2a-protocol-python/")
    assert json.loads(request.content) == {"claim": TEST_CLAIM}
    assert_secret_free(result)


def test_buyer_email_is_sent_only_when_given() -> None:
    server = Server(ok())
    make(server)[0].claim(OFFER, buyer_email="user@example.com")
    assert json.loads(server.requests[0].content) == {
        "claim": TEST_CLAIM,
        "buyer": {"email": "user@example.com"},
    }


@pytest.mark.parametrize(
    "email",
    ["no-at-sign", "a@b@c", "with space@example.com", "tab\t@example.com", "a" * 250 + "@x.io", 5],
)
def test_bad_emails_are_rejected_without_a_request(email: Any) -> None:
    server = Server()
    error_ = claim_error(server, buyer_email=email)
    assert error_.kind is ClaimErrorKind.MALFORMED_REQUEST
    assert server.requests == []


def test_explicit_now_overrides_clock() -> None:
    client, _ = make(Server(ok()))
    assert client.claim(OFFER, now=EXP - timedelta(seconds=1)).code == CODE


# Before sending ------------------------------------------------------------------------------


@pytest.mark.parametrize("now", [EXP, EXP + timedelta(days=1)])
def test_expired_offer_raises_without_a_request(now: datetime) -> None:
    server = Server()
    error_ = claim_error(server, now=now)
    assert error_.kind is ClaimErrorKind.EXPIRED
    assert server.requests == []


def test_default_clock_is_the_wall_clock() -> None:
    server = Server()
    client = ClaimClient([TEST_ISSUER], client=httpx.Client(transport=httpx.MockTransport(server)))
    # TEST_NOW's offer expires 2026-11-10; the real clock decides whether that has passed.
    if datetime.now(UTC) >= EXP:
        with pytest.raises(ClaimError):
            client.claim(OFFER)
    else:
        server.responses.append(ok())
        assert client.claim(OFFER).code == CODE


def test_untrusted_issuer_raises_without_a_request() -> None:
    server = Server()
    client = ClaimClient(
        ["other.example"], client=httpx.Client(transport=httpx.MockTransport(server))
    )
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER, now=TEST_NOW)
    assert info.value.kind is ClaimErrorKind.UNTRUSTED_ISSUER
    assert server.requests == []


def test_programmer_errors() -> None:
    client, _ = make(Server())
    with pytest.raises(TypeError):
        client.claim({"claim": TEST_CLAIM})  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        client.claim(OFFER, now=datetime(2026, 10, 27))


# Errors --------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (400, "malformed_request"),
        (400, "buyer_required"),
        (404, "unknown_claim"),
        (409, "campaign_limit_reached"),
        (410, "expired"),
        (410, "already_claimed"),
        (410, "offer_unavailable"),
    ],
)
def test_documented_errors_map_to_kinds(status: int, code: str) -> None:
    server = Server(error(status, code))
    error_ = claim_error(server)
    assert error_.kind is ClaimErrorKind(code)
    assert error_.status == status
    assert len(server.requests) == 1  # 4xx is never retried


@pytest.mark.parametrize(
    "response",
    [
        error(400, "unknown_claim"),
        error(418, "teapot"),
        error(404, "Unknown_Claim"),
        httpx.Response(400, content=b"not json"),
        httpx.Response(400, content=b'{"error":{"nested":1}}'),
        httpx.Response(403),
    ],
)
def test_undocumented_errors_are_protocol_errors(response: Any) -> None:
    error_ = claim_error(Server(response))
    assert error_.kind is ClaimErrorKind.PROTOCOL_ERROR
    assert error_.status == response.status_code


def test_server_messages_never_leak_the_claim_token() -> None:
    error_ = claim_error(Server(error(404, "unknown_claim", f"no such claim {TEST_CLAIM}\n")))
    assert "no such claim" in error_.detail
    assert "\n" not in error_.detail


@pytest.mark.parametrize("status", [301, 302, 307])
def test_redirects_are_protocol_errors(status: int) -> None:
    response = httpx.Response(status, headers={"location": "https://evil.example/claims"})
    server = Server(response)
    error_ = claim_error(server)
    assert error_.kind is ClaimErrorKind.PROTOCOL_ERROR and error_.status == status
    assert len(server.requests) == 1


# Retries -------------------------------------------------------------------------------------


def test_5xx_then_success_backs_off() -> None:
    client, sleeps = make(Server(httpx.Response(503), ok()))
    assert client.claim(OFFER).code == CODE
    assert sleeps == [0.5]


def test_5xx_exhausts_retries() -> None:
    server = Server(httpx.Response(500), httpx.Response(502), httpx.Response(503))
    client, sleeps = make(server)
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER)
    assert info.value.kind is ClaimErrorKind.PROTOCOL_ERROR and info.value.status == 503
    assert sleeps == [0.5, 1.0]


def test_network_errors_retry_then_fail() -> None:
    server = Server(
        httpx.ConnectError("down"), httpx.ReadTimeout("slow"), httpx.ConnectError("down")
    )
    client, sleeps = make(server)
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER)
    assert info.value.kind is ClaimErrorKind.NETWORK_ERROR
    assert sleeps == [0.5, 1.0]
    client, sleeps = make(Server(httpx.ConnectError("down"), ok()))
    assert client.claim(OFFER).code == CODE and sleeps == [0.5]


def test_no_retries_when_disabled() -> None:
    client, sleeps = make(Server(httpx.Response(503)), max_retries=0)
    with pytest.raises(ClaimError):
        client.claim(OFFER)
    assert sleeps == []


def test_429_with_short_retry_after_waits_and_retries() -> None:
    client, sleeps = make(Server(error(429, "rate_limited", **{"retry-after": "2"}), ok()))
    assert client.claim(OFFER).code == CODE
    assert sleeps == [2.0]


@pytest.mark.parametrize(
    ("retry_after", "expected"),
    [("120", 120.0), (None, None), ("Wed, 21 Oct 2026 07:28:00 GMT", None), ("1.5", None)],
)
def test_429_without_usable_retry_after_raises(
    retry_after: str | None, expected: float | None
) -> None:
    headers = {} if retry_after is None else {"retry-after": retry_after}
    server = Server(error(429, "rate_limited", **headers))
    client, sleeps = make(server)
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER)
    assert info.value.kind is ClaimErrorKind.RATE_LIMITED
    assert info.value.retry_after == expected
    assert sleeps == [] and len(server.requests) == 1


def test_429_shares_the_retry_budget() -> None:
    limited = error(429, "rate_limited", **{"retry-after": "1"})
    server = Server(httpx.Response(503), limited, limited)
    client, sleeps = make(server)
    with pytest.raises(ClaimError) as info:
        client.claim(OFFER)
    assert info.value.kind is ClaimErrorKind.RATE_LIMITED and info.value.retry_after == 1.0
    assert sleeps == [0.5, 1.0] and len(server.requests) == 3


# Success-response validation ---------------------------------------------------------------


@pytest.mark.parametrize(
    "response",
    [
        ok(offer_id="off_000000000000000000000000"),
        ok(extra="member"),
        httpx.Response(200, content=json.dumps({"offer_id": OFFER_ID, "code": CODE}).encode()),
        ok(code="AGT\x07KQ"),
        ok(code="AGT" + chr(0x85) + "KQ"),
        ok(code=""),
        ok(code="C" * 129),
        ok(code=12345),
        ok(exp="2026-11-01"),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, content=b"[]"),
        httpx.Response(200, content=b'{"offer_id":"x","offer_id":"y","code":"c","exp":"z"}'),
    ],
)
def test_bad_success_responses_are_protocol_errors(response: Any) -> None:
    error_ = claim_error(Server(response))
    assert error_.kind is ClaimErrorKind.PROTOCOL_ERROR and error_.status == 200


def test_code_of_128_characters_is_opaque_and_accepted() -> None:
    code = "c" * 64 + "-_.~ !@" + "Z" * 57
    client, _ = make(Server(ok(code=code)))
    assert client.claim(OFFER).code == code


# Construction --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("args", "kwargs", "error_type"),
    [
        (TEST_ISSUER, {}, TypeError),
        (["Offers.Example"], {}, ValueError),
        ([TEST_ISSUER], {"max_retries": -1}, ValueError),
        ([TEST_ISSUER], {"max_retries": True}, ValueError),
        ([TEST_ISSUER], {"max_retry_after": timedelta(seconds=-1)}, ValueError),
        ([TEST_ISSUER], {"max_retry_after": 30}, ValueError),
    ],
)
def test_constructor_validates(
    args: Any, kwargs: dict[str, Any], error_type: type[Exception]
) -> None:
    with pytest.raises(error_type):
        ClaimClient(args, **kwargs)


def test_close_only_closes_its_own_client() -> None:
    with ClaimClient([TEST_ISSUER]) as owned:
        client = owned._client
    assert client.is_closed
    shared = httpx.Client(transport=httpx.MockTransport(Server()))
    with ClaimClient([TEST_ISSUER], client=shared):
        pass
    assert not shared.is_closed
