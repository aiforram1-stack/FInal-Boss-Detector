from __future__ import annotations

import hashlib
from collections.abc import Iterator, Sequence
from pathlib import Path

import httpx
import pytest
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.input_fetcher import HttpsInputFetcher
from helpers import detector_job


class StaticResolver:
    def __init__(self, addresses: dict[str, Sequence[str]] | None = None) -> None:
        self.addresses = addresses or {"objects.example.test": ("8.8.8.8",)}
        self.seen: list[str] = []

    def resolve(self, hostname: str, port: int) -> Sequence[str]:
        assert port == 443
        self.seen.append(hostname)
        return self.addresses.get(hostname, ())


def fetcher(
    tmp_path: Path,
    handler: httpx.MockTransport,
    *,
    resolver: StaticResolver | None = None,
    allowed_hosts: frozenset[str] = frozenset({"objects.example.test"}),
    max_bytes: int = 4096,
    allow_redirects: bool = False,
    max_redirects: int = 0,
) -> HttpsInputFetcher:
    return HttpsInputFetcher(
        client=httpx.Client(transport=handler, trust_env=False),
        resolver=resolver or StaticResolver(),
        allowed_hosts=allowed_hosts,
        temp_root=tmp_path,
        max_bytes=max_bytes,
        chunk_bytes=min(7, max_bytes),
        connect_timeout_seconds=1,
        read_timeout_seconds=1,
        total_timeout_seconds=2,
        allow_redirects=allow_redirects,
        max_redirects=max_redirects,
    )


def response_transport(
    content: bytes,
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
) -> httpx.MockTransport:
    response_headers = {"content-type": "image/png"}
    response_headers.update(headers or {})
    return httpx.MockTransport(
        lambda _: httpx.Response(status, headers=response_headers, content=content)
    )


def test_valid_bounded_download_verifies_hash_length_and_cleans_on_caller(
    tmp_path: Path,
) -> None:
    content = b"\x89PNG\r\n\x1a\ncontrolled"
    job = detector_job(
        content,
        url="https://objects.example.test/object?X-Amz-Signature=secret",
    )
    retrieved = fetcher(tmp_path, response_transport(content)).fetch(job)
    assert retrieved.path.read_bytes() == content
    assert retrieved.sha256 == hashlib.sha256(content).hexdigest()
    assert retrieved.byte_length == len(content)
    assert retrieved.response_mime_type == "image/png"
    retrieved.cleanup()
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("job_change", "response", "maximum", "code"),
    [
        ({}, b"12345", 4, WorkerErrorCode.INPUT_TOO_LARGE),
        ({"expected_sha256": "a" * 64}, b"1234", 8, WorkerErrorCode.INPUT_HASH_MISMATCH),
        ({"expected_byte_length": 5}, b"1234", 8, WorkerErrorCode.INPUT_LENGTH_MISMATCH),
    ],
)
def test_length_size_and_hash_failures_remove_partial_files(
    tmp_path: Path,
    job_change: dict[str, object],
    response: bytes,
    maximum: int,
    code: WorkerErrorCode,
) -> None:
    job = detector_job(
        response,
        url="https://objects.example.test/object",
        **job_change,
    )
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, response_transport(response), max_bytes=maximum).fetch(job)
    assert raised.value.code == code
    assert list(tmp_path.iterdir()) == []


def test_declared_content_length_mismatch_is_rejected_before_write(tmp_path: Path) -> None:
    content = b"1234"
    job = detector_job(content, url="https://objects.example.test/object")
    transport = response_transport(content, headers={"content-length": "99"})
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, transport).fetch(job)
    assert raised.value.code == WorkerErrorCode.INPUT_LENGTH_MISMATCH
    assert list(tmp_path.iterdir()) == []


def test_timeout_is_sanitized_and_retryable(tmp_path: Path) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("signed-url-secret", request=request)

    job = detector_job(b"x", url="https://objects.example.test/object?token=secret")
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, httpx.MockTransport(timeout)).fetch(job)
    assert raised.value.code == WorkerErrorCode.INPUT_FETCH_FAILED
    assert raised.value.retryable is True
    assert "secret" not in str(raised.value)
    assert "token" not in str(raised.value.external_dict())


def test_redirect_is_rejected_by_default(tmp_path: Path) -> None:
    transport = response_transport(
        b"", status=302, headers={"location": "https://objects.example.test/next"}
    )
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, transport).fetch(
            detector_job(b"x", url="https://objects.example.test/object")
        )
    assert raised.value.code == WorkerErrorCode.INPUT_REDIRECT_REJECTED


def test_redirect_destination_is_revalidated(tmp_path: Path) -> None:
    def redirect(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://internal.example.test/object"})

    resolver = StaticResolver(
        {
            "objects.example.test": ("8.8.8.8",),
            "internal.example.test": ("10.0.0.8",),
        }
    )
    with pytest.raises(WorkerError) as raised:
        fetcher(
            tmp_path,
            httpx.MockTransport(redirect),
            resolver=resolver,
            allowed_hosts=frozenset({"objects.example.test", "internal.example.test"}),
            allow_redirects=True,
            max_redirects=1,
        ).fetch(detector_job(b"x", url="https://objects.example.test/object"))
    assert raised.value.code == WorkerErrorCode.INPUT_HOST_REJECTED
    assert resolver.seen == ["objects.example.test", "internal.example.test"]


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "169.254.1.2", "169.254.169.254"],
)
def test_loopback_private_linklocal_and_metadata_addresses_are_blocked(
    tmp_path: Path, address: str
) -> None:
    resolver = StaticResolver({"objects.example.test": (address,)})
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, response_transport(b"x"), resolver=resolver).fetch(
            detector_job(b"x", url="https://objects.example.test/object")
        )
    assert raised.value.code == WorkerErrorCode.INPUT_HOST_REJECTED


def test_disallowed_host_and_unsupported_scheme_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, response_transport(b"x")).fetch(
            detector_job(b"x", url="https://other.example.test/object")
        )
    assert raised.value.code == WorkerErrorCode.INPUT_HOST_REJECTED

    with pytest.raises(WorkerError):
        fetcher(tmp_path, response_transport(b"x")).fetch(
            detector_job(b"x", url="http://objects.example.test/object")
        )


def test_content_type_and_encoding_must_match_policy(tmp_path: Path) -> None:
    job = detector_job(b"x", url="https://objects.example.test/object")
    for headers in (
        {"content-type": "image/jpeg"},
        {"content-encoding": "gzip"},
    ):
        with pytest.raises(WorkerError):
            fetcher(tmp_path, response_transport(b"x", headers=headers)).fetch(job)
        assert list(tmp_path.iterdir()) == []


class FailingStream(httpx.SyncByteStream):
    def __init__(self, failure: Exception) -> None:
        self.failure = failure

    def __iter__(self) -> Iterator[bytes]:
        yield b"abc"
        raise self.failure


@pytest.mark.parametrize("failure_type", [httpx.ReadError, RuntimeError])
def test_stream_failure_removes_partial_file_and_redacts_detail(
    tmp_path: Path, failure_type: type[Exception]
) -> None:
    def response(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "image/png"},
            stream=FailingStream(failure_type("private-token")),
        )

    with pytest.raises(WorkerError) as raised:
        fetcher(tmp_path, httpx.MockTransport(response)).fetch(
            detector_job(b"abcdef", url="https://objects.example.test/object?token=private")
        )
    assert raised.value.code == WorkerErrorCode.INPUT_FETCH_FAILED
    assert "private" not in str(raised.value.external_dict())
    assert list(tmp_path.iterdir()) == []
