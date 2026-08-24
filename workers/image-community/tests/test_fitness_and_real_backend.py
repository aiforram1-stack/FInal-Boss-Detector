from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from forensic_contracts import DetectorIdentity
from forensic_image_community.community_backend import CommunityForensicsBackend
from forensic_image_community.contracts import BackendOutput, PreprocessedImage
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.factory import build_job_service
from forensic_image_community.fitness import WorkerFitnessCheck
from helpers import manifest, settings


def test_mock_mode_fitness_is_healthy_and_complete(tmp_path: Path) -> None:
    configured = settings(tmp_path)
    _, fitness = build_job_service(configured)
    result = fitness.check()
    assert result.ready is True
    assert result.mode == "mock"
    assert all(result.checks.values())


class FailingRealBackend:
    mock_backend = False

    def identity(self) -> DetectorIdentity:
        return DetectorIdentity(
            schema_version="1.0",
            detector_name="community-forensics-384",
            detector_version="1.0.0",
            repository_url="https://github.com/JeongsooP/Community-Forensics",
            repository_commit="e" * 40,
            container_digest=f"sha256:{'f' * 64}",
            model_revision="a" * 40,
            checkpoint_sha256="b" * 64,
        )

    def infer(self, _: PreprocessedImage) -> BackendOutput:
        raise WorkerError(
            WorkerErrorCode.CUDA_UNAVAILABLE,
            "CUDA is required by the real Community Forensics backend.",
        )


def test_real_fitness_reports_cuda_unavailable_without_importing_gpu_runtime(
    tmp_path: Path,
) -> None:
    configured = settings(
        tmp_path,
        backend="community",
        container_digest=f"sha256:{'f' * 64}",
    )
    fitness = WorkerFitnessCheck(
        settings=configured,
        manifest=manifest(),
        backend=FailingRealBackend(),
    )
    result = fitness.check()
    assert result.ready is False
    assert result.error_code == "CUDA_UNAVAILABLE"


def test_real_backend_rejects_missing_checkpoint_before_model_import(tmp_path: Path) -> None:
    backend = CommunityForensicsBackend(
        manifest=manifest(),
        checkpoint_path=tmp_path / "missing.safetensors",
        container_digest=f"sha256:{'f' * 64}",
        min_free_vram_bytes=0,
    )
    with pytest.raises(WorkerError) as raised:
        backend.verify_checkpoint()
    assert raised.value.code == WorkerErrorCode.CHECKPOINT_UNAVAILABLE
    configured = settings(
        tmp_path,
        backend="community",
        container_digest=f"sha256:{'f' * 64}",
    )
    readiness = WorkerFitnessCheck(
        settings=configured,
        manifest=manifest(),
        backend=backend,
    ).check()
    assert readiness.ready is False
    assert readiness.error_code == WorkerErrorCode.CHECKPOINT_UNAVAILABLE.value


def test_real_backend_rejects_checkpoint_hash_mismatch(tmp_path: Path) -> None:
    content = b"not the pinned checkpoint"
    path = tmp_path / "model.safetensors"
    path.write_bytes(content)
    original = manifest()
    changed_model = original.model.model_copy(
        update={
            "checkpoint_byte_length": len(content),
            "checkpoint_sha256": hashlib.sha256(b"different").hexdigest(),
        }
    )
    changed_manifest = original.model_copy(update={"model": changed_model})
    backend = CommunityForensicsBackend(
        manifest=changed_manifest,
        checkpoint_path=path,
        container_digest=f"sha256:{'f' * 64}",
        min_free_vram_bytes=0,
    )
    with pytest.raises(WorkerError) as raised:
        backend.verify_checkpoint()
    assert raised.value.code == WorkerErrorCode.CHECKPOINT_HASH_MISMATCH
    configured = settings(
        tmp_path,
        backend="community",
        container_digest=f"sha256:{'f' * 64}",
    )
    readiness = WorkerFitnessCheck(
        settings=configured,
        manifest=changed_manifest,
        backend=backend,
    ).check()
    assert readiness.ready is False
    assert readiness.error_code == WorkerErrorCode.CHECKPOINT_HASH_MISMATCH.value


def test_real_identity_requires_container_digest(tmp_path: Path) -> None:
    backend = CommunityForensicsBackend(
        manifest=manifest(),
        checkpoint_path=tmp_path / "missing.safetensors",
        container_digest=None,
        min_free_vram_bytes=0,
    )
    with pytest.raises(WorkerError) as raised:
        backend.identity()
    assert raised.value.code == WorkerErrorCode.WORKER_NOT_READY
