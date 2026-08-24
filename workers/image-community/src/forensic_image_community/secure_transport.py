"""HTTPX transport that pins connections to policy-validated DNS addresses."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from types import TracebackType
from typing import Any, cast

import httpcore
import httpx

from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.input_fetcher import HostResolver, _address_is_forbidden


class PinnedNetworkBackend(httpcore.NetworkBackend):
    """Resolve at connect time and connect only to the validated literal IP."""

    def __init__(
        self,
        *,
        resolver: HostResolver,
        allowed_hosts: frozenset[str],
        connector: httpcore.NetworkBackend | None = None,
    ) -> None:
        self.resolver = resolver
        self.allowed_hosts = allowed_hosts
        self.connector = connector or httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        normalized_host = host.lower().rstrip(".")
        if normalized_host not in self.allowed_hosts or port != 443:
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Input destination is not approved.",
            )
        addresses = tuple(self.resolver.resolve(normalized_host, port))
        if not addresses or any(_address_is_forbidden(address) for address in addresses):
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Input destination resolved to a prohibited address.",
            )
        last_error: Exception | None = None
        for address in sorted(set(addresses)):
            try:
                return self.connector.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except (httpcore.NetworkError, OSError) as exc:
                last_error = exc
        raise httpcore.ConnectError("approved input destination was unreachable") from last_error

    def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.NetworkStream:
        del path, timeout, socket_options
        raise WorkerError(
            WorkerErrorCode.INPUT_HOST_REJECTED,
            "Unix-socket input transport is prohibited.",
        )


class _CoreResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Iterable[bytes], request: httpx.Request) -> None:
        self.stream = stream
        self.request = request

    def __iter__(self) -> Iterator[bytes]:
        try:
            yield from self.stream
        except httpcore.TimeoutException as exc:
            raise httpx.ReadTimeout(
                "Secure input transport timed out.", request=self.request
            ) from exc
        except httpcore.NetworkError as exc:
            raise httpx.ReadError("Secure input transport failed.", request=self.request) from exc

    def close(self) -> None:
        close = getattr(self.stream, "close", None)
        if close is not None:
            close()


class PinnedHTTPTransport(httpx.BaseTransport):
    """Public HTTPX adapter around an httpcore pinned connection pool."""

    def __init__(
        self,
        *,
        resolver: HostResolver,
        allowed_hosts: frozenset[str],
        max_connections: int = 4,
        max_keepalive_connections: int = 2,
    ) -> None:
        self.pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=False),
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            http1=True,
            http2=False,
            retries=0,
            network_backend=PinnedNetworkBackend(
                resolver=resolver,
                allowed_hosts=allowed_hosts,
            ),
        )

    def __enter__(self) -> PinnedHTTPTransport:
        self.pool.__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        self.pool.__exit__(exc_type, exc_value, traceback)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.SyncByteStream):
            raise TypeError("secure transport requires a synchronous request stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        try:
            response = self.pool.handle_request(core_request)
        except WorkerError:
            raise
        except httpcore.TimeoutException as exc:
            raise httpx.ConnectTimeout(
                "Secure input transport timed out.", request=request
            ) from exc
        except httpcore.NetworkError as exc:
            raise httpx.ConnectError("Secure input transport failed.", request=request) from exc
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_CoreResponseStream(cast(Iterable[bytes], response.stream), request),
            extensions=cast(dict[str, Any], response.extensions),
        )

    def close(self) -> None:
        self.pool.close()
