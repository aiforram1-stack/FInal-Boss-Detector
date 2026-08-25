"""Fail-closed resolver for RunPod's host-cached Hugging Face snapshots."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from forensic_image_community.errors import WorkerError, WorkerErrorCode

HASH_CHUNK_BYTES = 1024 * 1024
MAX_SAFETENSORS_HEADER_BYTES = 16 * 1024 * 1024
MAX_REVISION_REF_BYTES = 128
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
REVISION_RE = re.compile(r"^[a-f0-9]{40}$")
WEIGHT_SUFFIXES = frozenset({".bin", ".ckpt", ".pt", ".pth", ".safetensors"})
SAFETENSORS_DTYPE_BYTES = {
    "BOOL": 1,
    "F8_E4M3": 1,
    "F8_E5M2": 1,
    "I8": 1,
    "U8": 1,
    "BF16": 2,
    "F16": 2,
    "I16": 2,
    "U16": 2,
    "F32": 4,
    "I32": 4,
    "U32": 4,
    "F64": 8,
    "I64": 8,
    "U64": 8,
}


@dataclass(frozen=True, slots=True)
class CachedCheckpoint:
    repository: str
    requested_revision: str
    resolved_revision: str
    snapshot_path: Path
    logical_checkpoint_path: Path
    checkpoint_path: Path
    filename: str
    byte_length: int
    sha256: str
    checkpoint_format: str
    tensor_count: int
    hash_verification_ms: int
    cache_layout: Literal[
        "HUGGINGFACE_BLOB_SYMLINK",
        "RUNPOD_MATERIALIZED_SNAPSHOT",
    ] = "HUGGINGFACE_BLOB_SYMLINK"


def _within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            while chunk := source.read(HASH_CHUNK_BYTES):
                digest.update(chunk)
    except OSError as exc:
        raise WorkerError(
            WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
            "Cached checkpoint could not be hashed.",
            internal_detail=type(exc).__name__,
        ) from exc
    return digest.hexdigest()


def inspect_safetensors(path: Path) -> int:
    """Validate the bounded safetensors header without deserializing tensor data."""

    try:
        file_size = path.stat().st_size
        with path.open("rb") as source:
            prefix = source.read(8)
            if len(prefix) != 8:
                raise ValueError("truncated safetensors prefix")
            header_length = struct.unpack("<Q", prefix)[0]
            if not 1 <= header_length <= MAX_SAFETENSORS_HEADER_BYTES:
                raise ValueError("invalid safetensors header length")
            if header_length % 8 != 0:
                raise ValueError("unaligned safetensors header length")
            if 8 + header_length > file_size:
                raise ValueError("truncated safetensors header")
            header_bytes = source.read(header_length)

        def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate safetensors header key")
                result[key] = value
            return result

        header = json.loads(header_bytes, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError, struct.error) as exc:
        raise WorkerError(
            WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
            "Cached checkpoint is not a valid bounded safetensors file.",
            internal_detail=type(exc).__name__,
        ) from exc
    if not isinstance(header, dict):
        raise WorkerError(
            WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
            "Cached checkpoint has an invalid safetensors header.",
        )
    tensor_count = 0
    data_bytes = file_size - 8 - header_length
    byte_ranges: list[tuple[int, int]] = []
    for name, record in header.items():
        if name == "__metadata__":
            if not isinstance(record, dict):
                raise WorkerError(
                    WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                    "Cached checkpoint metadata is invalid.",
                )
            continue
        if not isinstance(name, str) or not name or not isinstance(record, dict):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached checkpoint tensor metadata is invalid.",
            )
        dtype = record.get("dtype")
        shape = record.get("shape")
        offsets = record.get("data_offsets")
        if (
            not isinstance(dtype, str)
            or not isinstance(shape, list)
            or not all(type(value) is int and value >= 0 for value in shape)
            or not isinstance(offsets, list)
            or len(offsets) != 2
            or not all(type(value) is int for value in offsets)
            or offsets[0] < 0
            or offsets[0] > offsets[1]
            or offsets[1] > data_bytes
        ):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached checkpoint tensor metadata is invalid.",
            )
        dtype_bytes = SAFETENSORS_DTYPE_BYTES.get(dtype)
        if dtype_bytes is None:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached checkpoint tensor dtype is unsupported.",
            )
        element_count = 1
        for dimension in shape:
            element_count *= dimension
            if element_count * dtype_bytes > data_bytes:
                raise WorkerError(
                    WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                    "Cached checkpoint tensor shape exceeds the data section.",
                )
        if offsets[1] - offsets[0] != element_count * dtype_bytes:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached checkpoint tensor byte range is inconsistent with its shape.",
            )
        byte_ranges.append((offsets[0], offsets[1]))
        tensor_count += 1
    if tensor_count == 0:
        raise WorkerError(
            WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
            "Cached checkpoint contains no tensors.",
        )
    expected_start = 0
    for start, end in sorted(byte_ranges):
        if start != expected_start:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached checkpoint tensor byte ranges are not contiguous.",
            )
        expected_start = end
    if expected_start != data_bytes:
        raise WorkerError(
            WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
            "Cached checkpoint data section contains unreferenced bytes.",
        )
    return tensor_count


class RunPodModelCacheResolver:
    """Resolve one exact Hugging Face snapshot from RunPod's standard cache."""

    def __init__(self, cache_root: Path) -> None:
        self.cache_root = cache_root

    def resolve(
        self,
        *,
        repository: str,
        revision: str,
        filename: str,
        expected_byte_length: int | None,
        expected_sha256: str | None,
    ) -> CachedCheckpoint:
        if not REPOSITORY_RE.fullmatch(repository):
            raise WorkerError(
                WorkerErrorCode.MODEL_MANIFEST_INVALID,
                "Model repository must use the exact organization/name form.",
            )
        if not REVISION_RE.fullmatch(revision):
            raise WorkerError(
                WorkerErrorCode.MODEL_MANIFEST_INVALID,
                "Model revision must be an immutable commit.",
            )
        if Path(filename).name != filename or filename in {"", ".", ".."}:
            raise WorkerError(
                WorkerErrorCode.MODEL_MANIFEST_INVALID,
                "Checkpoint filename is invalid.",
            )
        unresolved_root = self.cache_root.expanduser()
        if unresolved_root.is_symlink():
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Model cache root cannot be a symbolic link.",
            )
        try:
            root = unresolved_root.resolve(strict=True)
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "RunPod model cache root is unavailable.",
                internal_detail=type(exc).__name__,
            ) from exc
        if not root.is_dir():
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "RunPod model cache root is unavailable.",
            )
        organization, model_name = repository.split("/", 1)
        model_root = root / f"models--{organization}--{model_name}"
        snapshot = model_root / "snapshots" / revision
        try:
            resolved_model_root = model_root.resolve(strict=True)
            resolved_snapshot = snapshot.resolve(strict=True)
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Pinned model snapshot is unavailable in the RunPod cache.",
                internal_detail=type(exc).__name__,
            ) from exc
        if model_root.is_symlink() or snapshot.is_symlink() or not resolved_snapshot.is_dir():
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Pinned model snapshot is not a safe directory.",
            )
        if not _within(resolved_model_root, root) or not _within(
            resolved_snapshot, resolved_model_root
        ):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Pinned model snapshot escaped the cache root.",
            )
        for ref_name in ("main", revision):
            ref = resolved_model_root / "refs" / ref_name
            if ref.exists():
                try:
                    if ref.is_symlink() or not ref.is_file():
                        raise ValueError("unsafe revision reference")
                    if ref.stat().st_size > MAX_REVISION_REF_BYTES:
                        raise ValueError("oversized revision reference")
                    ref_value = ref.read_text(encoding="utf-8").strip()
                except (OSError, UnicodeError, ValueError) as exc:
                    raise WorkerError(
                        WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                        "Cached model revision reference could not be read.",
                        internal_detail=type(exc).__name__,
                    ) from exc
                if ref_value != revision:
                    raise WorkerError(
                        WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                        "Cached model resolved to a different revision.",
                    )
        logical_checkpoint = resolved_snapshot / filename
        unexpected_weights: list[str] = []
        for current_root, directory_names, file_names in os.walk(
            resolved_snapshot,
            topdown=True,
            followlinks=False,
        ):
            current = Path(current_root)
            for directory_name in directory_names:
                if (current / directory_name).is_symlink():
                    raise WorkerError(
                        WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                        "Cached model snapshot contains an unsafe directory link.",
                    )
            for file_name in file_names:
                candidate = current / file_name
                if candidate != logical_checkpoint and candidate.suffix.lower() in WEIGHT_SUFFIXES:
                    unexpected_weights.append(candidate.relative_to(resolved_snapshot).as_posix())
        unexpected_weights.sort()
        if unexpected_weights:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Cached model snapshot contains an ambiguous checkpoint set.",
            )
        try:
            checkpoint = logical_checkpoint.resolve(strict=True)
            stat = checkpoint.stat()
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Expected cached checkpoint is unavailable.",
                internal_detail=type(exc).__name__,
            ) from exc
        if logical_checkpoint.is_symlink():
            blobs_root = resolved_model_root / "blobs"
            try:
                resolved_blobs_root = blobs_root.resolve(strict=True)
            except OSError as exc:
                raise WorkerError(
                    WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                    "Cached model blob directory is unavailable.",
                    internal_detail=type(exc).__name__,
                ) from exc
            if (
                not _within(checkpoint, resolved_blobs_root)
                or not _within(resolved_blobs_root, resolved_model_root)
                or not checkpoint.is_file()
                or checkpoint.is_symlink()
            ):
                raise WorkerError(
                    WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                    "Expected cached checkpoint is not backed by the pinned model blob cache.",
                )
            cache_layout: Literal[
                "HUGGINGFACE_BLOB_SYMLINK",
                "RUNPOD_MATERIALIZED_SNAPSHOT",
            ] = "HUGGINGFACE_BLOB_SYMLINK"
        else:
            if (
                checkpoint != logical_checkpoint
                or checkpoint.parent != resolved_snapshot
                or not checkpoint.is_file()
                or checkpoint.is_symlink()
            ):
                raise WorkerError(
                    WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                    "Expected cached checkpoint is not a safe materialized snapshot file.",
                )
            cache_layout = "RUNPOD_MATERIALIZED_SNAPSHOT"
        hash_started = time.perf_counter_ns()
        actual_sha256 = _sha256(checkpoint)
        hash_verification_ms = max(
            0,
            round((time.perf_counter_ns() - hash_started) / 1_000_000),
        )
        if expected_byte_length is not None and stat.st_size != expected_byte_length:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Checkpoint length does not match the pinned manifest.",
            )
        if expected_sha256 is not None and actual_sha256 != expected_sha256:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Checkpoint SHA-256 does not match the pinned manifest.",
            )
        if Path(filename).suffix.lower() != ".safetensors":
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Only the pinned safetensors checkpoint format is supported.",
            )
        tensor_count = inspect_safetensors(checkpoint)
        return CachedCheckpoint(
            repository=repository,
            requested_revision=revision,
            resolved_revision=revision,
            snapshot_path=resolved_snapshot,
            logical_checkpoint_path=logical_checkpoint,
            checkpoint_path=checkpoint,
            filename=filename,
            byte_length=stat.st_size,
            sha256=actual_sha256,
            checkpoint_format="safetensors",
            tensor_count=tensor_count,
            hash_verification_ms=hash_verification_ms,
            cache_layout=cache_layout,
        )
