from __future__ import annotations

from collections.abc import Iterable

import httpcore
import pytest
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.secure_transport import PinnedNetworkBackend
from test_input_fetcher import StaticResolver


class RecordingConnector(httpcore.NetworkBackend):
    def __init__(self) -> None:
        self.hosts: list[str] = []

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del timeout, local_address, socket_options
        assert port == 443
        self.hosts.append(host)
        return httpcore.MockStream([])

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise AssertionError("Unix sockets must never be delegated")


def test_connect_time_dns_is_pinned_to_validated_literal_ip() -> None:
    connector = RecordingConnector()
    backend = PinnedNetworkBackend(
        resolver=StaticResolver({"objects.example.test": ("8.8.8.8",)}),
        allowed_hosts=frozenset({"objects.example.test"}),
        connector=connector,
    )

    backend.connect_tcp("objects.example.test", 443)

    assert connector.hosts == ["8.8.8.8"]


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254"])
def test_connect_time_dns_rebinding_to_prohibited_ip_is_rejected(address: str) -> None:
    connector = RecordingConnector()
    backend = PinnedNetworkBackend(
        resolver=StaticResolver({"objects.example.test": (address,)}),
        allowed_hosts=frozenset({"objects.example.test"}),
        connector=connector,
    )

    with pytest.raises(WorkerError) as raised:
        backend.connect_tcp("objects.example.test", 443)

    assert raised.value.code == WorkerErrorCode.INPUT_HOST_REJECTED
    assert connector.hosts == []


def test_pinned_backend_rejects_unapproved_host_and_port() -> None:
    backend = PinnedNetworkBackend(
        resolver=StaticResolver(),
        allowed_hosts=frozenset({"objects.example.test"}),
        connector=RecordingConnector(),
    )
    with pytest.raises(WorkerError):
        backend.connect_tcp("unapproved.example.test", 443)
    with pytest.raises(WorkerError):
        backend.connect_tcp("objects.example.test", 8443)


def test_pinned_backend_prohibits_unix_sockets() -> None:
    backend = PinnedNetworkBackend(
        resolver=StaticResolver(),
        allowed_hosts=frozenset({"objects.example.test"}),
        connector=RecordingConnector(),
    )
    with pytest.raises(WorkerError) as raised:
        backend.connect_unix_socket("prohibited.sock")
    assert raised.value.code == WorkerErrorCode.INPUT_HOST_REJECTED
