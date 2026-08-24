"""Injectable, bounded input retrieval with fail-closed SSRF controls."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import socket
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

import httpx
from forensic_contracts import DetectorJob

from forensic_image_community.contracts import FetchedInput
from forensic_image_community.errors import WorkerError, WorkerErrorCode

ALLOWED_MIME_TYPES = frozenset({"image/jpeg", "image/png", "image/webp"})
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class InputFetcher(Protocol):
    def fetch(self, job: DetectorJob) -> FetchedInput: ...


class HostResolver(Protocol):
    def resolve(self, hostname: str, port: int) -> Sequence[str]: ...


class SocketHostResolver:
    def resolve(self, hostname: str, port: int) -> Sequence[str]:
        try:
            records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Input hostname could not be validated.",
                internal_detail=type(exc).__name__,
            ) from exc
        return tuple(sorted({str(record[4][0]) for record in records}))


def _normalized_content_type(value: str | None) -> str:
    if value is None:
        return ""
    return value.split(";", 1)[0].strip().lower()


def _address_is_forbidden(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return not address.is_global


def _create_temporary_file(temp_root: Path, *, prefix: str) -> tuple[int, Path]:
    try:
        descriptor, raw_path = tempfile.mkstemp(prefix=prefix, suffix=".part", dir=temp_root)
    except OSError as exc:
        raise WorkerError(
            WorkerErrorCode.INPUT_FETCH_FAILED,
            "Input temporary storage is unavailable.",
            retryable=True,
            internal_detail=type(exc).__name__,
        ) from exc
    return descriptor, Path(raw_path)


class HttpsInputFetcher:
    """Fetch an exact allowlisted HTTPS object into a unique temporary file."""

    def __init__(
        self,
        *,
        client: httpx.Client,
        resolver: HostResolver,
        allowed_hosts: frozenset[str],
        temp_root: Path,
        max_bytes: int,
        chunk_bytes: int,
        connect_timeout_seconds: float,
        read_timeout_seconds: float,
        total_timeout_seconds: float,
        allow_redirects: bool,
        max_redirects: int,
    ) -> None:
        if max_bytes < 1 or chunk_bytes < 1 or chunk_bytes > max_bytes:
            raise ValueError("invalid download size limits")
        if allow_redirects != (max_redirects > 0):
            raise ValueError("redirect policy is inconsistent")
        self.client = client
        self.resolver = resolver
        self.allowed_hosts = allowed_hosts
        self.temp_root = temp_root
        self.max_bytes = max_bytes
        self.chunk_bytes = chunk_bytes
        self.total_timeout_seconds = total_timeout_seconds
        self.allow_redirects = allow_redirects
        self.max_redirects = max_redirects
        self.timeout = httpx.Timeout(
            connect=connect_timeout_seconds,
            read=read_timeout_seconds,
            write=read_timeout_seconds,
            pool=connect_timeout_seconds,
        )

    def _validate_destination(self, url: httpx.URL) -> None:
        host = (url.host or "").lower().rstrip(".")
        if (
            url.scheme != "https"
            or not host
            or url.username
            or url.password
            or url.port not in {None, 443}
            or host not in self.allowed_hosts
        ):
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Input destination is not approved.",
            )
        addresses = self.resolver.resolve(host, 443)
        if not addresses or any(_address_is_forbidden(address) for address in addresses):
            raise WorkerError(
                WorkerErrorCode.INPUT_HOST_REJECTED,
                "Input destination resolved to a prohibited address.",
            )

    def fetch(self, job: DetectorJob) -> FetchedInput:
        expected_mime = job.expected_mime_type.lower()
        if expected_mime not in ALLOWED_MIME_TYPES:
            raise WorkerError(
                WorkerErrorCode.UNSUPPORTED_MIME_TYPE,
                "Input MIME type is not supported by this worker.",
            )
        if job.expected_byte_length < 1 or job.expected_byte_length > self.max_bytes:
            raise WorkerError(
                WorkerErrorCode.INPUT_TOO_LARGE,
                "Expected input length is outside the configured limit.",
            )

        current = httpx.URL(str(job.download_url))
        deadline = time.monotonic() + self.total_timeout_seconds
        redirects = 0
        while True:
            self._validate_destination(current)
            try:
                with self.client.stream(
                    "GET",
                    current,
                    follow_redirects=False,
                    timeout=self.timeout,
                    headers={"Accept-Encoding": "identity"},
                ) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        if not self.allow_redirects or redirects >= self.max_redirects:
                            raise WorkerError(
                                WorkerErrorCode.INPUT_REDIRECT_REJECTED,
                                "Input redirect was rejected by policy.",
                            )
                        location = response.headers.get("location")
                        if not location:
                            raise WorkerError(
                                WorkerErrorCode.INPUT_REDIRECT_REJECTED,
                                "Input redirect did not provide a destination.",
                            )
                        current = current.join(location)
                        redirects += 1
                        continue
                    if response.status_code != 200:
                        raise WorkerError(
                            WorkerErrorCode.INPUT_FETCH_FAILED,
                            "Input provider returned an unsuccessful response.",
                            retryable=response.status_code >= 500,
                        )
                    return self._consume_response(response, job, expected_mime, deadline)
            except WorkerError:
                raise
            except (httpx.TimeoutException, httpx.NetworkError, httpx.ProtocolError) as exc:
                raise WorkerError(
                    WorkerErrorCode.INPUT_FETCH_FAILED,
                    "Input could not be retrieved within the configured policy.",
                    retryable=True,
                    internal_detail=type(exc).__name__,
                ) from exc

    def _consume_response(
        self,
        response: httpx.Response,
        job: DetectorJob,
        expected_mime: str,
        deadline: float,
    ) -> FetchedInput:
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in {"", "identity"}:
            raise WorkerError(
                WorkerErrorCode.INPUT_FETCH_FAILED,
                "Encoded input responses are not accepted.",
                retryable=False,
            )
        response_mime = _normalized_content_type(response.headers.get("content-type"))
        if response_mime not in ALLOWED_MIME_TYPES or response_mime != expected_mime:
            raise WorkerError(
                WorkerErrorCode.UNSUPPORTED_MIME_TYPE,
                "Input MIME metadata does not match the approved job.",
            )
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                declared_length = int(content_length)
            except ValueError as exc:
                raise WorkerError(
                    WorkerErrorCode.INPUT_LENGTH_MISMATCH,
                    "Input provider returned an invalid content length.",
                ) from exc
            if declared_length != job.expected_byte_length or declared_length > self.max_bytes:
                raise WorkerError(
                    WorkerErrorCode.INPUT_LENGTH_MISMATCH,
                    "Input byte length did not match the approved job.",
                )

        descriptor, path = _create_temporary_file(self.temp_root, prefix="image-community-")
        digest = hashlib.sha256()
        total = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                for chunk in response.iter_bytes(chunk_size=self.chunk_bytes):
                    if time.monotonic() > deadline:
                        raise WorkerError(
                            WorkerErrorCode.INPUT_FETCH_FAILED,
                            "Input retrieval exceeded the total timeout.",
                            retryable=True,
                        )
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > self.max_bytes or total > job.expected_byte_length:
                        raise WorkerError(
                            WorkerErrorCode.INPUT_TOO_LARGE,
                            "Input exceeded the approved byte length.",
                        )
                    digest.update(chunk)
                    if output.write(chunk) != len(chunk):
                        raise OSError("short temporary-file write")
                output.flush()
                os.fsync(output.fileno())
            if total != job.expected_byte_length:
                raise WorkerError(
                    WorkerErrorCode.INPUT_LENGTH_MISMATCH,
                    "Input byte length did not match the approved job.",
                )
            actual_hash = digest.hexdigest()
            if actual_hash != job.expected_sha256:
                raise WorkerError(
                    WorkerErrorCode.INPUT_HASH_MISMATCH,
                    "Input SHA-256 did not match the approved job.",
                )
            return FetchedInput(
                path=path,
                sha256=actual_hash,
                byte_length=total,
                response_mime_type=response_mime,
            )
        except WorkerError:
            path.unlink(missing_ok=True)
            raise
        except httpx.HTTPError as exc:
            path.unlink(missing_ok=True)
            raise WorkerError(
                WorkerErrorCode.INPUT_FETCH_FAILED,
                "Input stream failed before integrity verification completed.",
                retryable=True,
                internal_detail=type(exc).__name__,
            ) from exc
        except Exception as exc:
            path.unlink(missing_ok=True)
            raise WorkerError(
                WorkerErrorCode.INPUT_FETCH_FAILED,
                "Input temporary storage failed.",
                internal_detail=type(exc).__name__,
            ) from exc


class MemoryInputFetcher:
    """Controlled test/local fetcher that performs the same integrity checks."""

    def __init__(self, objects: Mapping[str, tuple[bytes, str]], temp_root: Path) -> None:
        self.objects = objects
        self.temp_root = temp_root

    def fetch(self, job: DetectorJob) -> FetchedInput:
        key = str(job.download_url)
        try:
            content, mime_type = self.objects[key]
        except KeyError as exc:
            raise WorkerError(
                WorkerErrorCode.INPUT_FETCH_FAILED,
                "Controlled input is unavailable.",
            ) from exc
        digest = hashlib.sha256(content).hexdigest()
        if len(content) != job.expected_byte_length:
            raise WorkerError(
                WorkerErrorCode.INPUT_LENGTH_MISMATCH,
                "Input byte length did not match the approved job.",
            )
        if digest != job.expected_sha256:
            raise WorkerError(
                WorkerErrorCode.INPUT_HASH_MISMATCH,
                "Input SHA-256 did not match the approved job.",
            )
        if mime_type != job.expected_mime_type or mime_type not in ALLOWED_MIME_TYPES:
            raise WorkerError(
                WorkerErrorCode.UNSUPPORTED_MIME_TYPE,
                "Input MIME metadata does not match the approved job.",
            )
        descriptor, path = _create_temporary_file(self.temp_root, prefix="image-community-memory-")
        try:
            with os.fdopen(descriptor, "wb") as output:
                if output.write(content) != len(content):
                    raise OSError("short temporary-file write")
                output.flush()
                os.fsync(output.fileno())
        except Exception as exc:
            try:
                os.close(descriptor)
            except OSError:
                pass
            path.unlink(missing_ok=True)
            raise WorkerError(
                WorkerErrorCode.INPUT_FETCH_FAILED,
                "Controlled input temporary storage failed.",
                internal_detail=type(exc).__name__,
            ) from exc
        return FetchedInput(
            path=path,
            sha256=digest,
            byte_length=len(content),
            response_mime_type=mime_type,
        )
