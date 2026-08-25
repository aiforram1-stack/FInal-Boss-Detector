from __future__ import annotations

import hashlib
from pathlib import Path

import forensic_image_community.handler as handler_module
import pytest
from forensic_contracts import DetectorIdentity
from forensic_image_community.cache_resolver import CachedCheckpoint
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.contracts import BackendOutput, FitnessResult, PreprocessedImage
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.handler import _phase6_handle
from forensic_image_community.image_decoder import PillowImageDecoder
from forensic_image_community.manifest import ModelManifest
from forensic_image_community.phase6_contracts import (
    CheckpointBootstrapRequest,
    GpuValidationRequest,
)
from forensic_image_community.phase6_validation import Phase6ValidationService
from forensic_image_community.preprocessing import CommunityForensicsPreprocessor
from helpers import manifest

SOURCE_COMMIT = "a" * 40
CONTAINER_DIGEST = f"sha256:{'b' * 64}"
ENDPOINT_RELEASE = "phase6-test-release"


class FakeBackend:
    mock_backend = False

    def __init__(self, pinned_manifest: ModelManifest) -> None:
        self.manifest = pinned_manifest
        self._loaded = False
        self._training: bool | None = None
        self._model_load_ms: int | None = None
        self._checkpoint_verification_ms: int | None = None
        self.inference_count = 0

    @property
    def model_loaded(self) -> bool:
        return self._loaded

    @property
    def model_training(self) -> bool | None:
        return self._training

    @property
    def model_load_ms(self) -> int | None:
        return self._model_load_ms

    @property
    def checkpoint_verification_ms(self) -> int | None:
        return self._checkpoint_verification_ms

    def identity(self) -> DetectorIdentity:
        return DetectorIdentity(
            detector_name="community-forensics-384",
            detector_version="1.0.0",
            repository_url="https://github.com/JeongsooP/Community-Forensics",
            repository_commit=self.manifest.source.repository_commit,
            container_digest=CONTAINER_DIGEST,
            model_revision=self.manifest.model.revision,
            checkpoint_sha256=self.manifest.model.checkpoint_sha256,
        )

    def ensure_loaded(self) -> None:
        self._loaded = True
        self._training = False
        self._model_load_ms = 8
        self._checkpoint_verification_ms = 2

    def infer(self, _: PreprocessedImage) -> BackendOutput:
        self.ensure_loaded()
        self.inference_count += 1
        return BackendOutput(
            raw_logit=0.125,
            raw_outputs={"output_shape": [1, 1]},
            class_mapping={"0": "real", "1": "fake"},
            upstream_predicted_class="fake",
            mock_backend=False,
            device_metadata={
                "gpu_model": "Synthetic 24 GB Test GPU",
                "peak_allocated_vram_bytes": 100,
                "peak_reserved_vram_bytes": 120,
                "free_vram_before_inference_bytes": 20_000_000_000,
                "free_vram_after_inference_bytes": 19_999_999_000,
            },
            determinism={"random_seed": 11997733, "deterministic_algorithms": True},
            model_load_ms=8,
            inference_ms=3,
        )

    def runtime_environment(self) -> dict[str, object]:
        self.ensure_loaded()
        return {
            "gpu_model": "Synthetic 24 GB Test GPU",
            "gpu_count": 1,
            "total_vram_bytes": 24_000_000_000,
            "free_vram_bytes": 20_000_000_000,
            "cuda_version": "12.6",
            "cuda_driver_version": "test",
            "pytorch_version": "2.7.1",
            "precision": "float32",
        }

    def verify_checkpoint(
        self,
        *,
        expected_sha256: str | None = None,
        expected_byte_length: int | None = None,
    ) -> tuple[int, str]:
        if expected_sha256 is not None and expected_sha256 != self.manifest.model.checkpoint_sha256:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Expected test checkpoint hash mismatch.",
            )
        if (
            expected_byte_length is not None
            and expected_byte_length != self.manifest.model.checkpoint_byte_length
        ):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Expected test checkpoint length mismatch.",
            )
        return (
            self.manifest.model.checkpoint_byte_length,
            self.manifest.model.checkpoint_sha256,
        )


class FakeFitness:
    def __init__(self, backend: FakeBackend) -> None:
        self.backend = backend

    def check(self) -> FitnessResult:
        self.backend.ensure_loaded()
        return FitnessResult(
            ready=True,
            mode="real_gpu",
            checks={
                "configuration_valid": True,
                "manifest_valid": True,
                "contracts_import": True,
                "temporary_directory_writable": True,
                "backend_probe": True,
                "mock_disabled_in_production": True,
            },
            message="Synthetic CPU-only fitness fixture passed.",
        )


class FailingFitness:
    def check(self) -> FitnessResult:
        return FitnessResult(
            ready=False,
            mode="real_gpu",
            checks={
                "configuration_valid": True,
                "manifest_valid": True,
                "contracts_import": True,
                "temporary_directory_writable": True,
                "backend_probe": False,
                "mock_disabled_in_production": True,
            },
            error_code=WorkerErrorCode.MODEL_LOAD_FAILED.value,
            message="Synthetic model load failure.",
        )


def production_settings(
    tmp_path: Path,
    *,
    bootstrap: bool,
) -> ImageCommunitySettings:
    cache_root = tmp_path / "runpod-cache"
    cache_root.mkdir(exist_ok=True)
    return ImageCommunitySettings.model_validate(
        {
            "environment": "production",
            "backend": "community",
            "model_manifest": Path(__file__).resolve().parents[1] / "model-manifest.yaml",
            "model_cache_root": cache_root,
            "temp_root": tmp_path / "temp",
            "checkpoint_bootstrap_mode": bootstrap,
            "require_verified_checkpoint_hash": not bootstrap,
            "container_digest": CONTAINER_DIGEST,
            "project_source_commit": SOURCE_COMMIT,
            "endpoint_release_identity": ENDPOINT_RELEASE,
            "min_free_vram_bytes": 1_000_000_000,
        }
    )


def checkpoint(tmp_path: Path, pinned_manifest: ModelManifest) -> CachedCheckpoint:
    snapshot = tmp_path / "runpod-cache" / "snapshot"
    snapshot.mkdir(parents=True, exist_ok=True)
    path = snapshot / "model.safetensors"
    path.write_bytes(b"synthetic-unit-test-placeholder")
    return CachedCheckpoint(
        repository=pinned_manifest.model.repository,
        requested_revision=pinned_manifest.model.revision,
        resolved_revision=pinned_manifest.model.revision,
        snapshot_path=snapshot,
        logical_checkpoint_path=path,
        checkpoint_path=path,
        filename=pinned_manifest.model.filename,
        byte_length=pinned_manifest.model.checkpoint_byte_length,
        sha256=pinned_manifest.model.checkpoint_sha256,
        checkpoint_format="safetensors",
        tensor_count=1,
        hash_verification_ms=1,
    )


def service(
    tmp_path: Path,
    *,
    bootstrap: bool,
) -> tuple[Phase6ValidationService, ModelManifest, FakeBackend]:
    pinned_manifest = manifest()
    if not bootstrap:
        pinned_manifest = pinned_manifest.model_copy(
            update={
                "model": pinned_manifest.model.model_copy(
                    update={"checkpoint_hash_status": "OBSERVED_BOOTSTRAP_HASH"}
                )
            }
        )
    configured = production_settings(tmp_path, bootstrap=bootstrap)
    backend = FakeBackend(pinned_manifest)
    return (
        Phase6ValidationService(
            settings=configured,
            manifest=pinned_manifest,
            checkpoint=checkpoint(tmp_path, pinned_manifest),
            backend=backend,
            fitness=FakeFitness(backend),  # type: ignore[arg-type]
            decoder=PillowImageDecoder(
                max_width=16_384,
                max_height=16_384,
                max_pixels=40_000_000,
                max_decoded_memory_bytes=160_000_000,
            ),
            preprocessor=CommunityForensicsPreprocessor(pinned_manifest),
            parity_runner=lambda decoded, preprocessed, output, tolerance: {
                "decoded_dimensions": list(decoded.image.size),
                "tensor_maximum_absolute_difference": 0.0,
                "raw_output_absolute_difference": 0.0,
                "absolute_tolerance": tolerance,
                "passed": output.raw_logit == 0.125 and preprocessed.tensor.shape[0] == 1,
            },
        ),
        pinned_manifest,
        backend,
    )


def test_checkpoint_bootstrap_is_observational_and_sanitized(tmp_path: Path) -> None:
    validator, pinned_manifest, backend = service(tmp_path, bootstrap=True)
    result = validator.checkpoint_bootstrap(
        CheckpointBootstrapRequest(
            schema_version="1.0",
            operation="checkpoint_bootstrap",
            detector_id="community-forensics-384",
            expected_model_repository=pinned_manifest.model.repository,
            expected_model_revision=pinned_manifest.model.revision,
            expected_checkpoint_filename=pinned_manifest.model.filename,
            fixture_id="phase6-generated-fixture",
        ),
        runpod_job_id="bootstrap-job-1",
    )
    assert result.receipt.status == "OBSERVED_BOOTSTRAP_HASH"
    assert result.receipt.payload["checkpoint_sha256"] == pinned_manifest.model.checkpoint_sha256
    assert result.receipt.payload["basic_model_load_status"] == "PASSED"
    assert result.receipt.payload["checkpoint_cache_layout"] == "HUGGINGFACE_BLOB_SYMLINK"
    assert result.receipt.payload["runpod_job_id"] == "bootstrap-job-1"
    assert (
        result.receipt.payload["phase6_runtime_fitness_checks"][  # type: ignore[index]
            "exactly_one_gpu_visible"
        ]
        is True
    )
    assert backend.model_training is False
    assert "checkpoint_path" not in result.model_dump_json()


def test_phase6_startup_fails_closed_until_validation_only_mode_is_enabled(
    tmp_path: Path,
) -> None:
    validator, _, _ = service(tmp_path, bootstrap=True)
    with pytest.raises(WorkerError) as disabled:
        validator.assert_startup_ready()
    assert disabled.value.code is WorkerErrorCode.WORKER_NOT_READY

    validator.settings = validator.settings.model_copy(update={"phase6_only_mode": True})
    checks = validator.assert_startup_ready()
    validator.record_worker_initialization_ms(12)
    assert checks["exactly_one_gpu_visible"] is True
    assert checks["checkpoint_hash_requirement_satisfied"] is True


def test_startup_failure_exposes_only_the_safe_fitness_error_code(tmp_path: Path) -> None:
    validator, _, _ = service(tmp_path, bootstrap=False)
    validator.settings = validator.settings.model_copy(update={"phase6_only_mode": True})
    validator.fitness = FailingFitness()  # type: ignore[assignment]

    with pytest.raises(WorkerError) as raised:
        validator.assert_startup_ready()

    assert raised.value.code is WorkerErrorCode.WORKER_NOT_READY
    assert raised.value.internal_detail == WorkerErrorCode.MODEL_LOAD_FAILED.value
    assert str(raised.value) == "Phase 6 startup fitness checks failed (MODEL_LOAD_FAILED)."


def test_bootstrap_returns_the_allow_listed_fitness_error_code(tmp_path: Path) -> None:
    validator, pinned_manifest, _ = service(tmp_path, bootstrap=True)
    validator.fitness = FailingFitness()  # type: ignore[assignment]
    request = CheckpointBootstrapRequest(
        schema_version="1.0",
        operation="checkpoint_bootstrap",
        detector_id="community-forensics-384",
        expected_model_repository=pinned_manifest.model.repository,
        expected_model_revision=pinned_manifest.model.revision,
        expected_checkpoint_filename=pinned_manifest.model.filename,
        fixture_id="phase6-generated-fixture",
    )

    with pytest.raises(WorkerError) as raised:
        validator.checkpoint_bootstrap(request, runpod_job_id="bootstrap-failure-1")

    assert raised.value.code is WorkerErrorCode.MODEL_LOAD_FAILED
    assert raised.value.internal_detail == WorkerErrorCode.MODEL_LOAD_FAILED.value
    assert str(raised.value) == "Bootstrap runtime fitness checks failed (MODEL_LOAD_FAILED)."


def test_bootstrap_initialization_defers_gpu_fitness_to_the_controlled_job(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator, _, _ = service(tmp_path, bootstrap=True)
    disabled = production_settings(tmp_path, bootstrap=True)
    configured = disabled.model_copy(update={"phase6_only_mode": True})

    def unexpected_startup_probe() -> dict[str, bool]:
        raise AssertionError("bootstrap initialization must not run GPU fitness before the job")

    monkeypatch.setattr(validator, "assert_startup_ready", unexpected_startup_probe)
    monkeypatch.setattr(handler_module, "build_phase6_validation_service", lambda _: validator)

    with pytest.raises(WorkerError) as rejected:
        handler_module._initialize_phase6_worker(disabled)
    assert rejected.value.code is WorkerErrorCode.WORKER_NOT_READY

    assert handler_module._initialize_phase6_worker(configured) is validator


def test_verified_initialization_still_requires_startup_gpu_fitness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator, _, _ = service(tmp_path, bootstrap=False)
    configured = production_settings(tmp_path, bootstrap=False).model_copy(
        update={"phase6_only_mode": True}
    )
    startup_calls = 0

    def record_startup_probe() -> dict[str, bool]:
        nonlocal startup_calls
        startup_calls += 1
        return {"verified_startup_probe": True}

    monkeypatch.setattr(validator, "assert_startup_ready", record_startup_probe)
    monkeypatch.setattr(handler_module, "build_phase6_validation_service", lambda _: validator)

    assert handler_module._initialize_phase6_worker(configured) is validator
    assert startup_calls == 1


def test_complete_gpu_validation_bundle_runs_all_checks_once(tmp_path: Path) -> None:
    validator, pinned_manifest, backend = service(tmp_path, bootstrap=False)
    fixture_hash = hashlib.sha256(generated_rgb_png()).hexdigest()
    result = validator.gpu_validation(
        GpuValidationRequest(
            schema_version="1.0",
            operation="gpu_validation",
            detector_id="community-forensics-384",
            expected_model_repository=pinned_manifest.model.repository,
            expected_model_revision=pinned_manifest.model.revision,
            expected_checkpoint_filename=pinned_manifest.model.filename,
            expected_checkpoint_byte_length=pinned_manifest.model.checkpoint_byte_length,
            expected_checkpoint_sha256=pinned_manifest.model.checkpoint_sha256,
            fixture_id="phase6-generated-fixture",
            expected_fixture_sha256=fixture_hash,
            measured_repetitions=5,
        ),
        runpod_job_id="validation-job-1",
    )
    assert result.summary.status == "PASSED"
    assert result.upstream_parity.payload["passed"] is True
    assert result.detector_result.payload["calibrated_score"] is None
    assert result.detector_result.payload["mock_backend"] is False
    assert result.repeatability.payload["run_count"] == 5
    assert result.negative_tests.payload["passed"] is True
    assert result.fitness.payload["phase6_checks"]["exactly_one_gpu_visible"] is True
    assert result.performance.payload["production_throughput_claimed"] is False
    assert backend.inference_count == 7


def test_gpu_validation_rejects_wrong_fixture_hash_before_inference(tmp_path: Path) -> None:
    validator, pinned_manifest, backend = service(tmp_path, bootstrap=False)
    with pytest.raises(WorkerError) as raised:
        validator.gpu_validation(
            GpuValidationRequest(
                schema_version="1.0",
                operation="gpu_validation",
                detector_id="community-forensics-384",
                expected_model_repository=pinned_manifest.model.repository,
                expected_model_revision=pinned_manifest.model.revision,
                expected_checkpoint_filename=pinned_manifest.model.filename,
                expected_checkpoint_byte_length=pinned_manifest.model.checkpoint_byte_length,
                expected_checkpoint_sha256=pinned_manifest.model.checkpoint_sha256,
                fixture_id="phase6-generated-fixture",
                expected_fixture_sha256="0" * 64,
            ),
            runpod_job_id="validation-job-2",
        )
    assert raised.value.code is WorkerErrorCode.INPUT_HASH_MISMATCH
    assert backend.inference_count == 0


def test_phase6_handler_dispatches_bootstrap_and_rejects_unsafe_job_id(tmp_path: Path) -> None:
    validator, pinned_manifest, _ = service(tmp_path, bootstrap=True)
    request = CheckpointBootstrapRequest(
        schema_version="1.0",
        operation="checkpoint_bootstrap",
        detector_id="community-forensics-384",
        expected_model_repository=pinned_manifest.model.repository,
        expected_model_revision=pinned_manifest.model.revision,
        expected_checkpoint_filename=pinned_manifest.model.filename,
        fixture_id="phase6-generated-fixture",
    )
    response = _phase6_handle(
        {"id": "bootstrap-job-3", "input": request.model_dump(mode="json")},
        validator,
    )
    assert response["operation"] == "checkpoint_bootstrap"
    with pytest.raises(WorkerError) as raised:
        _phase6_handle(
            {"id": "unsafe/job/id", "input": request.model_dump(mode="json")},
            validator,
        )
    assert raised.value.code is WorkerErrorCode.INVALID_JOB
    with pytest.raises(WorkerError) as missing_id:
        _phase6_handle({"input": request.model_dump(mode="json")}, validator)
    assert missing_id.value.code is WorkerErrorCode.INVALID_JOB


def test_phase6_only_endpoint_rejects_ordinary_detector_jobs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator, _, _ = service(tmp_path, bootstrap=True)
    configured = production_settings(tmp_path, bootstrap=True).model_copy(
        update={"phase6_only_mode": True}
    )
    monkeypatch.setattr(handler_module, "ImageCommunitySettings", lambda: configured)
    monkeypatch.setattr(handler_module, "_phase6_service", validator)
    monkeypatch.setattr(handler_module, "_default_handler", None)
    response = handler_module.runpod_handler(
        {"input": {"schema_version": "1.0", "operation": "ordinary_detector_job"}}
    )
    assert response["status"] == "WORKER_ERROR"
    assert "error" not in response
    assert response["worker_error"]["code"] == "INVALID_JOB"  # type: ignore[index]
    assert "Phase 6" in str(response["worker_error"])
