from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

import pytest
from forensic_image_community.cache_resolver import RunPodModelCacheResolver, inspect_safetensors
from forensic_image_community.errors import WorkerError, WorkerErrorCode

REPOSITORY = "OwensLab/commfor-model-384"
REVISION = "6076002bf0d9dd37537f965ee2f06f826c333b61"
FILENAME = "model.safetensors"


def safetensors_bytes() -> bytes:
    header = json.dumps(
        {"vit.head.weight": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}},
        separators=(",", ":"),
    ).encode("utf-8")
    padding = b" " * ((8 - len(header) % 8) % 8)
    bounded_header = header + padding
    return struct.pack("<Q", len(bounded_header)) + bounded_header + b"\x00\x00\x00\x00"


def cached_snapshot(tmp_path: Path) -> tuple[Path, Path, bytes]:
    root = tmp_path / "hub"
    model_root = root / "models--OwensLab--commfor-model-384"
    snapshot = model_root / "snapshots" / REVISION
    blobs = model_root / "blobs"
    refs = model_root / "refs"
    snapshot.mkdir(parents=True)
    blobs.mkdir()
    refs.mkdir()
    content = safetensors_bytes()
    blob = blobs / hashlib.sha256(content).hexdigest()
    blob.write_bytes(content)
    (snapshot / FILENAME).symlink_to(Path("../../blobs") / blob.name)
    (refs / "main").write_text(REVISION, encoding="utf-8")
    return root, snapshot, content


def test_resolves_exact_cached_snapshot_and_observes_checkpoint(tmp_path: Path) -> None:
    root, snapshot, content = cached_snapshot(tmp_path)
    resolved = RunPodModelCacheResolver(root).resolve(
        repository=REPOSITORY,
        revision=REVISION,
        filename=FILENAME,
        expected_byte_length=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
    )
    assert resolved.snapshot_path == snapshot.resolve()
    assert resolved.resolved_revision == REVISION
    assert resolved.byte_length == len(content)
    assert resolved.tensor_count == 1
    assert resolved.hash_verification_ms >= 0
    assert resolved.checkpoint_path.parent.name == "blobs"


@pytest.mark.parametrize("field", ["sha256", "length"])
def test_rejects_expected_checkpoint_identity_mismatch(tmp_path: Path, field: str) -> None:
    root, _, content = cached_snapshot(tmp_path)
    expected_hash = hashlib.sha256(content).hexdigest()
    expected_length = len(content)
    if field == "sha256":
        expected_hash = "0" * 64
    else:
        expected_length += 1
    with pytest.raises(WorkerError) as raised:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=expected_length,
            expected_sha256=expected_hash,
        )
    assert raised.value.code is WorkerErrorCode.CHECKPOINT_HASH_MISMATCH


def test_rejects_revision_mismatch_and_ambiguous_weights(tmp_path: Path) -> None:
    root, snapshot, _ = cached_snapshot(tmp_path)
    refs = snapshot.parents[1] / "refs"
    (refs / "main").write_text("0" * 40, encoding="utf-8")
    with pytest.raises(WorkerError) as revision_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert revision_error.value.code is WorkerErrorCode.CHECKPOINT_HASH_MISMATCH

    (refs / "main").write_text(REVISION, encoding="utf-8")
    (snapshot / "unexpected.bin").write_bytes(b"other")
    with pytest.raises(WorkerError) as ambiguous_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert ambiguous_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE


def test_rejects_nested_weights_and_snapshot_directory_links(tmp_path: Path) -> None:
    root, snapshot, _ = cached_snapshot(tmp_path)
    nested = snapshot / "nested"
    nested.mkdir()
    (nested / "unexpected.pth").write_bytes(b"other")
    with pytest.raises(WorkerError) as nested_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert nested_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE

    (nested / "unexpected.pth").unlink()
    nested.rmdir()
    external = tmp_path / "external-directory"
    external.mkdir()
    (snapshot / "linked-directory").symlink_to(external, target_is_directory=True)
    with pytest.raises(WorkerError) as linked_directory_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert linked_directory_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE


def test_rejects_checkpoint_symlink_escape_and_unsafe_ref(tmp_path: Path) -> None:
    root, snapshot, _ = cached_snapshot(tmp_path)
    logical = snapshot / FILENAME
    logical.unlink()
    outside = tmp_path / "outside.safetensors"
    outside.write_bytes(safetensors_bytes())
    logical.symlink_to(outside)
    with pytest.raises(WorkerError) as escape_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert escape_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE

    logical.unlink()
    model_root = snapshot.parents[1]
    blob = next((model_root / "blobs").iterdir())
    logical.symlink_to(Path("../../blobs") / blob.name)
    ref = model_root / "refs" / "main"
    ref.unlink()
    ref.symlink_to(tmp_path / "external-ref")
    (tmp_path / "external-ref").write_text(REVISION, encoding="utf-8")
    with pytest.raises(WorkerError) as ref_error:
        RunPodModelCacheResolver(root).resolve(
            repository=REPOSITORY,
            revision=REVISION,
            filename=FILENAME,
            expected_byte_length=None,
            expected_sha256=None,
        )
    assert ref_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE


def test_bounded_safetensors_inspection_rejects_duplicate_or_inconsistent_metadata(
    tmp_path: Path,
) -> None:
    duplicate = (
        b'{"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]},'
        b'"weight":{"dtype":"F32","shape":[1],"data_offsets":[0,4]}}'
    )
    duplicate += b" " * ((8 - len(duplicate) % 8) % 8)
    path = tmp_path / "duplicate.safetensors"
    path.write_bytes(struct.pack("<Q", len(duplicate)) + duplicate + b"\0" * 4)
    with pytest.raises(WorkerError) as duplicate_error:
        inspect_safetensors(path)
    assert duplicate_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE

    inconsistent = json.dumps(
        {"weight": {"dtype": "F32", "shape": [2], "data_offsets": [0, 4]}},
        separators=(",", ":"),
    ).encode("utf-8")
    inconsistent += b" " * ((8 - len(inconsistent) % 8) % 8)
    path.write_bytes(struct.pack("<Q", len(inconsistent)) + inconsistent + b"\0" * 4)
    with pytest.raises(WorkerError) as inconsistent_error:
        inspect_safetensors(path)
    assert inconsistent_error.value.code is WorkerErrorCode.CHECKPOINT_UNAVAILABLE
