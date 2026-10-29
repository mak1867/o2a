"""The test suite runs with networking disabled."""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest


def _no_network(*args: object, **kwargs: object) -> None:
    raise RuntimeError("network access is disabled in the test suite")


@pytest.fixture(autouse=True, scope="session")
def no_network() -> Iterator[None]:
    patch = pytest.MonkeyPatch()
    patch.setattr(socket.socket, "connect", _no_network)
    patch.setattr(socket.socket, "connect_ex", _no_network)
    patch.setattr(socket, "create_connection", _no_network)
    patch.setattr(socket, "getaddrinfo", _no_network)
    yield
    patch.undo()
