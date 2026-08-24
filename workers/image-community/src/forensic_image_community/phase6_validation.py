"""Controlled checkpoint-bootstrap and complete GPU-validation operations."""

from __future__ import annotations

import hashlib
import math
import os
import statistics
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, cast

import numpy as np
from forensic_contracts import DetectorIdentity
from pydantic import JsonValue

from forensic_image_community.cache_resolver import CachedCheckpoint
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.contracts import (
    BackendOutput,
    DecodedImage,
    FetchedInput,
    FitnessResult,
    PreprocessedImage,
)
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.fitness import WorkerFitnessCheck
from forensic_image_community.fixture_data import generated_rgb_png
from forensic_image_community.image_decoder import PillowImageDecoder
from forensic_image_community.manifest import ModelManifest
from forensic_image_community.mock_backend import MockCommunityBackend
from forensic_image_community.phase6_contracts import (
    ArtifactEnvelope,
    CheckpointBootstrapRequest,
    CheckpointBootstrapResponse,
    GpuValidationRequest,
    GpuValidationResponse,
    ReleaseIdentity,
    build_artifact_envelope,
    utc_now,
)
from forensic_image_community.preprocessing import CommunityForensicsPreprocessor

ParityRunner = Callable[
    [DecodedImage, PreprocessedImage, BackendOutput, float],
    dict[str, JsonValue],
]


class ValidationBackend(Protocol):
    @property
    def mock_backend(self) -> bool: ...

    @property
    def model_loaded(self) -> bool: ...

    @property
    def model_training(self) -> bool | None: ...

    @property
    def model_load_ms(self) -> int | None: ...

    @property
    def checkpoint_verification_ms(self) -> int | None: ...

    def identity(self) -> DetectorIdentity: ...

    def ensure_loaded(self) -> None: ...

    def infer(self, preprocessed: PreprocessedImage) -> BackendOutput: ...

    def runtime_environment(self) -> dict[str, object]: ...

    def verify_checkpoint(
        self,
        *,
        expected_sha256: str | None = None,
        expected_byte_length: int | None = None,
    ) -> tuple[int, str]: ...


def _json_dict(value: dict[str, object]) -> dict[str, JsonValue]:
    return cast(dict[str, JsonValue], value)


class Phase6ValidationService:
    def __init__(
        self,
        *,
        settings: ImageCommunitySettings,
        manifest: ModelManifest,
        checkpoint: CachedCheckpoint,
        backend: ValidationBackend,
        fitness: WorkerFitnessCheck,
        decoder: PillowImageDecoder,
        preprocessor: CommunityForensicsPreprocessor,
        parity_runner: ParityRunner | None = None,
    ) -> None:
        self.settings = settings
        self.manifest = manifest
        self.checkpoint = checkpoint
        self.backend = backend
        self.fitness = fitness
        self.decoder = decoder
        self.preprocessor = preprocessor
        self.parity_runner = parity_runner or self._official_parity
        self._startup_readiness: FitnessResult | None = None
        self._startup_runtime: dict[str, JsonValue] | None = None
        self._startup_phase6_checks: dict[str, bool] | None = None
        self._worker_initialization_ms: int | None = None

    def assert_startup_ready(self) -> dict[str, bool]:
        """Fail before the RunPod loop if this release cannot accept Phase 6 work."""

        if not self.settings.phase6_only_mode:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Phase 6 worker startup requires validation-only mode.",
            )
        readiness = self.fitness.check()
        if not readiness.ready:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Phase 6 startup fitness checks failed.",
                internal_detail=readiness.error_code,
            )
        runtime = self._runtime_versions(load=True)
        checks = self._detailed_fitness_checks(
            basic_checks=readiness.checks,
            runtime=runtime,
            require_manifest_hash_match=not self.settings.checkpoint_bootstrap_mode,
        )
        self._startup_readiness = readiness
        self._startup_runtime = runtime
        self._startup_phase6_checks = checks
        return checks

    def record_worker_initialization_ms(self, duration_ms: int) -> None:
        if duration_ms < 0:
            raise ValueError("worker initialization duration cannot be negative")
        self._worker_initialization_ms = duration_ms

    def _identity(self) -> ReleaseIdentity:
        if (
            self.settings.project_source_commit is None
            or self.settings.container_digest is None
            or self.settings.endpoint_release_identity is None
        ):
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Phase 6 release identity is incomplete.",
            )
        return ReleaseIdentity(
            schema_version="1.0",
            project_source_commit=self.settings.project_source_commit,
            container_digest=self.settings.container_digest,
            endpoint_release_identity=self.settings.endpoint_release_identity,
            detector_id="community-forensics-384",
            upstream_repository_commit=self.manifest.source.repository_commit,
            model_repository=self.manifest.model.repository,
            model_revision=self.manifest.model.revision,
            checkpoint_sha256=self.checkpoint.sha256,
        )

    def _runtime_versions(self, *, load: bool) -> dict[str, JsonValue]:
        runtime: dict[str, object] = {
            "python_version": self.manifest.runtime.python_version,
            "pytorch_version": self.manifest.runtime.pytorch_version,
            "torchvision_version": self.manifest.runtime.torchvision_version,
            "timm_version": self.manifest.runtime.timm_version,
            "cuda_version": self.manifest.runtime.cuda_version,
            "target_platform": self.manifest.runtime.target_platform,
        }
        if load:
            runtime.update(self.backend.runtime_environment())
        return _json_dict(runtime)

    def _validate_common(
        self,
        *,
        detector_id: str,
        repository: str,
        revision: str,
        filename: str,
    ) -> None:
        if detector_id != self.manifest.detector.detector_id:
            raise WorkerError(WorkerErrorCode.INVALID_JOB, "Validation requested another detector.")
        if repository != self.manifest.model.repository:
            raise WorkerError(WorkerErrorCode.INVALID_JOB, "Validation requested another model.")
        if (
            revision != self.manifest.model.revision
            or revision != self.checkpoint.resolved_revision
        ):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Validation model revision does not match the cached snapshot.",
            )
        if filename != self.manifest.model.filename or filename != self.checkpoint.filename:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Validation checkpoint filename does not match the pinned manifest.",
            )

    @staticmethod
    def _require_fixture_hash(actual: str, expected: str) -> None:
        if actual != expected:
            raise WorkerError(
                WorkerErrorCode.INPUT_HASH_MISMATCH,
                "Generated validation fixture hash did not match the request.",
            )

    @staticmethod
    def _require_real_backend(backend: object) -> None:
        if bool(getattr(backend, "mock_backend", True)):
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Mock backend is prohibited for GPU validation.",
            )

    def checkpoint_bootstrap(
        self, request: CheckpointBootstrapRequest, *, runpod_job_id: str
    ) -> CheckpointBootstrapResponse:
        self._validate_common(
            detector_id=request.detector_id,
            repository=request.expected_model_repository,
            revision=request.expected_model_revision,
            filename=request.expected_checkpoint_filename,
        )
        if not self.settings.checkpoint_bootstrap_mode:
            raise WorkerError(
                WorkerErrorCode.INVALID_JOB,
                "Checkpoint bootstrap is disabled for this endpoint release.",
            )
        if self.settings.require_verified_checkpoint_hash:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Bootstrap release cannot require a previously observed checkpoint hash.",
            )
        self._require_real_backend(self.backend)
        load_status = "NOT_RUN"
        readiness_checks: dict[str, bool] = {}
        phase6_readiness_checks: dict[str, bool] = {}
        runtime_versions = self._runtime_versions(load=False)
        if request.perform_basic_load:
            readiness = self.fitness.check()
            if not readiness.ready:
                raise WorkerError(
                    WorkerErrorCode.WORKER_NOT_READY,
                    "Bootstrap runtime fitness checks failed.",
                    internal_detail=readiness.error_code,
                )
            readiness_checks = readiness.checks
            runtime_versions = self._runtime_versions(load=True)
            phase6_readiness_checks = self._detailed_fitness_checks(
                basic_checks=readiness.checks,
                runtime=runtime_versions,
                require_manifest_hash_match=False,
            )
            if not self.backend.model_loaded or self.backend.model_training is not False:
                raise WorkerError(
                    WorkerErrorCode.MODEL_LOAD_FAILED,
                    "Basic checkpoint model-load verification failed.",
                )
            load_status = "PASSED"
        fixture_sha256 = hashlib.sha256(generated_rgb_png()).hexdigest()
        receipt = build_artifact_envelope(
            artifact_type="checkpoint_bootstrap_receipt",
            created_at=utc_now(),
            identity=self._identity(),
            fixture_sha256=fixture_sha256,
            runtime_versions=runtime_versions,
            status="OBSERVED_BOOTSTRAP_HASH",
            warnings=(
                "Observed bootstrap hash is not final production GPU validation.",
                "Raw detector output was not produced by this bootstrap receipt.",
            ),
            payload=_json_dict(
                {
                    "runpod_job_id": runpod_job_id,
                    "requested_model_revision": self.checkpoint.requested_revision,
                    "resolved_snapshot_revision": self.checkpoint.resolved_revision,
                    "checkpoint_filename": self.checkpoint.filename,
                    "checkpoint_byte_length": self.checkpoint.byte_length,
                    "checkpoint_sha256": self.checkpoint.sha256,
                    "checkpoint_format": self.checkpoint.checkpoint_format,
                    "safetensors_tensor_count": self.checkpoint.tensor_count,
                    "checkpoint_hash_status": "OBSERVED_BOOTSTRAP_HASH",
                    "basic_model_load_status": load_status,
                    "basic_runtime_fitness_checks": readiness_checks,
                    "phase6_runtime_fitness_checks": phase6_readiness_checks,
                    "preprocessing_sha256": self.preprocessor.fingerprint(),
                    "model_load_duration_ms": self.backend.model_load_ms,
                    "worker_initialization_ms": self._worker_initialization_ms,
                    "fixture_id": request.fixture_id,
                }
            ),
        )
        return CheckpointBootstrapResponse(schema_version="1.0", receipt=receipt)

    def _decode_generated_fixture(self) -> tuple[bytes, DecodedImage, int]:
        fixture = generated_rgb_png()
        temp_root = self.settings.ensure_temp_root()
        descriptor, name = tempfile.mkstemp(prefix="phase6-fixture-", suffix=".png", dir=temp_root)
        path = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(fixture)
                output.flush()
                os.fsync(output.fileno())
            fetched = FetchedInput(
                path=path,
                sha256=hashlib.sha256(fixture).hexdigest(),
                byte_length=len(fixture),
                response_mime_type="image/png",
            )
            started = time.perf_counter_ns()
            decoded = self.decoder.decode(fetched, expected_mime_type="image/png")
            decode_ms = max(0, round((time.perf_counter_ns() - started) / 1_000_000))
            return fixture, decoded, decode_ms
        finally:
            path.unlink(missing_ok=True)

    def _official_parity(
        self,
        decoded: DecodedImage,
        preprocessed: PreprocessedImage,
        adapter_output: BackendOutput,
        tolerance: float,
    ) -> dict[str, JsonValue]:
        try:
            import timm  # type: ignore[import-not-found]
            import torch  # type: ignore[import-not-found]
            from safetensors.torch import load_model  # type: ignore[import-not-found]
            from torchvision import transforms  # type: ignore[import-not-found]
        except ImportError as exc:
            raise WorkerError(
                WorkerErrorCode.MODEL_LOAD_FAILED,
                "Official parity runtime dependencies are unavailable.",
                internal_detail=type(exc).__name__,
            ) from exc
        image = decoded.image.copy()
        reference_model = None
        try:
            transform = transforms.Compose(
                [
                    transforms.Resize(
                        self.manifest.preprocessing.resize_short_edge,
                        interpolation=transforms.InterpolationMode.BILINEAR,
                        antialias=True,
                    ),
                    transforms.CenterCrop(self.manifest.preprocessing.input_resolution),
                    transforms.ToTensor(),
                    transforms.Normalize(
                        mean=self.manifest.preprocessing.normalization_mean,
                        std=self.manifest.preprocessing.normalization_std,
                    ),
                    transforms.ConvertImageDtype(torch.float32),
                ]
            )
            reference_tensor = transform(image).unsqueeze(0)
            reference_array = reference_tensor.detach().cpu().numpy().astype(np.float32)
            adapter_array = preprocessed.tensor.astype(np.float32, copy=False)
            tensor_maximum_difference = float(np.max(np.abs(reference_array - adapter_array)))

            class OfficialViTClassifier(torch.nn.Module):  # type: ignore[misc]
                def __init__(self) -> None:
                    super().__init__()
                    self.vit = timm.create_model(
                        "vit_small_patch16_384.augreg_in21k_ft_in1k",
                        pretrained=False,
                    )
                    self.vit.head = torch.nn.Linear(384, 1, bias=True)

                def forward(self, tensor: object) -> object:
                    return self.vit(tensor)

            reference_model = OfficialViTClassifier()
            load_model(
                reference_model,
                str(self.checkpoint.checkpoint_path),
                strict=True,
                device="cpu",
            )
            reference_model.to("cuda")
            reference_model.eval()
            with torch.inference_mode():
                reference_output = reference_model(reference_tensor.to("cuda", dtype=torch.float32))
            torch.cuda.synchronize()
            if tuple(reference_output.shape) != (1, 1):
                raise WorkerError(
                    WorkerErrorCode.INFERENCE_FAILED,
                    "Official parity output shape was invalid.",
                )
            reference_logit = float(reference_output.detach().cpu().float().item())
            output_difference = abs(reference_logit - adapter_output.raw_logit)
            passed = tensor_maximum_difference <= tolerance and output_difference <= tolerance
            if not passed:
                raise WorkerError(
                    WorkerErrorCode.INFERENCE_FAILED,
                    "Official-upstream numeric parity failed.",
                )
            return _json_dict(
                {
                    "decoded_dimensions": list(decoded.image.size),
                    "adapter_tensor_shape": list(adapter_array.shape),
                    "reference_tensor_shape": list(reference_array.shape),
                    "adapter_tensor_minimum": float(adapter_array.min()),
                    "adapter_tensor_maximum": float(adapter_array.max()),
                    "adapter_tensor_mean": float(adapter_array.mean()),
                    "adapter_tensor_standard_deviation": float(adapter_array.std()),
                    "reference_tensor_minimum": float(reference_array.min()),
                    "reference_tensor_maximum": float(reference_array.max()),
                    "reference_tensor_mean": float(reference_array.mean()),
                    "reference_tensor_standard_deviation": float(reference_array.std()),
                    "tensor_maximum_absolute_difference": tensor_maximum_difference,
                    "normalization_mean": list(self.manifest.preprocessing.normalization_mean),
                    "normalization_std": list(self.manifest.preprocessing.normalization_std),
                    "adapter_raw_output_shape": adapter_output.raw_outputs.get("output_shape"),
                    "reference_raw_output_shape": list(reference_output.shape),
                    "adapter_raw_logit": adapter_output.raw_logit,
                    "reference_raw_logit": reference_logit,
                    "raw_output_absolute_difference": output_difference,
                    "class_ordering": self.manifest.output.class_mapping,
                    "adapter_selected_class": adapter_output.upstream_predicted_class,
                    "reference_selected_class": "fake" if reference_logit >= 0 else "real",
                    "absolute_tolerance": tolerance,
                    "pretrained_secondary_download": False,
                    "passed": True,
                }
            )
        except WorkerError:
            raise
        except Exception as exc:
            raise WorkerError(
                WorkerErrorCode.INFERENCE_FAILED,
                "Official-upstream parity execution failed.",
                internal_detail=type(exc).__name__,
            ) from exc
        finally:
            image.close()
            if reference_model is not None:
                del reference_model

    def _negative_tests(self, fixture_sha256: str) -> dict[str, JsonValue]:
        wrong_input_hash_rejected = False
        try:
            self._require_fixture_hash(fixture_sha256, "0" * 64)
        except WorkerError as exc:
            wrong_input_hash_rejected = exc.code is WorkerErrorCode.INPUT_HASH_MISMATCH
        wrong_checkpoint_hash_rejected = False
        try:
            self.backend.verify_checkpoint(expected_sha256="0" * 64)
        except WorkerError as exc:
            wrong_checkpoint_hash_rejected = exc.code is WorkerErrorCode.CHECKPOINT_HASH_MISMATCH
        mock_mode_rejected = False
        try:
            self._require_real_backend(MockCommunityBackend())
        except WorkerError as exc:
            mock_mode_rejected = exc.code is WorkerErrorCode.WORKER_NOT_READY
        if not all((wrong_input_hash_rejected, wrong_checkpoint_hash_rejected, mock_mode_rejected)):
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "One or more Phase 6 negative tests failed.",
            )
        return {
            "wrong_input_hash_rejected": wrong_input_hash_rejected,
            "wrong_expected_checkpoint_hash_rejected": wrong_checkpoint_hash_rejected,
            "checkpoint_modified": False,
            "mock_backend_rejected_in_production": mock_mode_rejected,
            "passed": True,
        }

    def _detailed_fitness_checks(
        self,
        *,
        basic_checks: dict[str, bool],
        runtime: dict[str, JsonValue],
        require_manifest_hash_match: bool = True,
    ) -> dict[str, bool]:
        gpu_count = runtime.get("gpu_count")
        total_vram = runtime.get("total_vram_bytes")
        free_vram = runtime.get("free_vram_bytes")
        phase6_checks = {
            "cuda_available": isinstance(gpu_count, int) and gpu_count >= 1,
            "exactly_one_gpu_visible": gpu_count == 1,
            "gpu_memory_meets_minimum": (
                isinstance(total_vram, int)
                and isinstance(free_vram, int)
                and total_vram >= self.settings.min_total_vram_bytes
                and free_vram >= self.settings.min_free_vram_bytes
            ),
            "model_cache_path_exists": self.settings.model_cache_root.is_dir(),
            "model_repository_present": self.checkpoint.snapshot_path.is_dir(),
            "resolved_revision_valid": (
                self.checkpoint.resolved_revision == self.manifest.model.revision
            ),
            "manifest_valid": True,
            "checkpoint_exists": self.checkpoint.checkpoint_path.is_file(),
            "checkpoint_hash_requirement_satisfied": (
                not require_manifest_hash_match
                or self.checkpoint.sha256 == self.manifest.model.checkpoint_sha256
            ),
            "mock_backend_disabled": not self.backend.mock_backend,
            "temporary_directory_writable": basic_checks.get("temporary_directory_writable", False),
            "preprocessing_configuration_valid": len(self.preprocessor.fingerprint()) == 64,
            "model_loaded": self.backend.model_loaded,
            "evaluation_mode": self.backend.model_training is False,
            "downloads_disabled": not self.settings.allow_model_download,
        }
        if not all(phase6_checks.values()):
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "One or more detailed Phase 6 fitness checks failed.",
            )
        return phase6_checks

    def gpu_validation(
        self, request: GpuValidationRequest, *, runpod_job_id: str
    ) -> GpuValidationResponse:
        total_started = time.perf_counter_ns()
        self._validate_common(
            detector_id=request.detector_id,
            repository=request.expected_model_repository,
            revision=request.expected_model_revision,
            filename=request.expected_checkpoint_filename,
        )
        if self.settings.checkpoint_bootstrap_mode:
            raise WorkerError(
                WorkerErrorCode.INVALID_JOB,
                "GPU validation is disabled in bootstrap mode.",
            )
        if not self.settings.require_verified_checkpoint_hash:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "GPU validation requires an observed checkpoint hash.",
            )
        if self.manifest.model.checkpoint_hash_status != "OBSERVED_BOOTSTRAP_HASH":
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Checked-in model manifest lacks an observed bootstrap hash.",
            )
        self._require_real_backend(self.backend)
        if (
            request.expected_checkpoint_sha256 != self.manifest.model.checkpoint_sha256
            or request.expected_checkpoint_sha256 != self.checkpoint.sha256
            or request.expected_checkpoint_byte_length != self.manifest.model.checkpoint_byte_length
            or request.expected_checkpoint_byte_length != self.checkpoint.byte_length
        ):
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "GPU validation checkpoint identity is inconsistent.",
            )
        fixture, decoded, decode_ms = self._decode_generated_fixture()
        fixture_sha256 = hashlib.sha256(fixture).hexdigest()
        self._require_fixture_hash(fixture_sha256, request.expected_fixture_sha256)
        preprocessing_started = time.perf_counter_ns()
        try:
            preprocessed = self.preprocessor.preprocess(decoded)
            preprocessing_ms = max(
                0, round((time.perf_counter_ns() - preprocessing_started) / 1_000_000)
            )
            fitness_started = time.perf_counter_ns()
            readiness = self.fitness.check()
            fitness_ms = max(
                0,
                round((time.perf_counter_ns() - fitness_started) / 1_000_000),
            )
            if not readiness.ready:
                raise WorkerError(
                    WorkerErrorCode.WORKER_NOT_READY,
                    "GPU fitness checks did not pass.",
                    internal_detail=readiness.error_code,
                )
            adapter_output = self.backend.infer(preprocessed)
            parity_payload = self.parity_runner(
                decoded,
                preprocessed,
                adapter_output,
                request.parity_absolute_tolerance,
            )
            self.backend.infer(preprocessed)
            measured_outputs = [
                self.backend.infer(preprocessed) for _ in range(request.measured_repetitions)
            ]
        finally:
            decoded.close()
        logits = [output.raw_logit for output in measured_outputs]
        inference_ms = [output.inference_ms for output in measured_outputs]
        maximum_output_difference = max(logits) - min(logits)
        if not all(math.isfinite(value) for value in logits) or maximum_output_difference > 1e-6:
            raise WorkerError(
                WorkerErrorCode.INFERENCE_FAILED,
                "Repeated identical inference was not sufficiently stable.",
            )
        negative_payload = self._negative_tests(fixture_sha256)
        runtime_versions = self._runtime_versions(load=True)
        phase6_fitness_checks = self._detailed_fitness_checks(
            basic_checks=readiness.checks,
            runtime=runtime_versions,
        )
        identity = self._identity()
        created_at = utc_now()

        def artifact(
            artifact_type: str,
            *,
            status: str,
            warnings: tuple[str, ...],
            payload: dict[str, JsonValue],
        ) -> ArtifactEnvelope:
            return build_artifact_envelope(
                artifact_type=artifact_type,
                created_at=created_at,
                identity=identity,
                fixture_sha256=fixture_sha256,
                runtime_versions=runtime_versions,
                status=status,
                warnings=warnings,
                payload=payload,
            )

        fitness_artifact = artifact(
            "gpu_fitness_result",
            status="PASSED",
            warnings=(),
            payload=_json_dict(
                {
                    "runpod_job_id": runpod_job_id,
                    "mode": readiness.mode,
                    "checks": readiness.checks,
                    "phase6_checks": phase6_fitness_checks,
                    "message": readiness.message,
                    "fitness_duration_ms": fitness_ms,
                }
            ),
        )
        parity_artifact = artifact(
            "upstream_parity_result",
            status="PASSED",
            warnings=(
                "Parity is proven only for the pinned runtime, GPU, checkpoint, and fixture.",
            ),
            payload=parity_payload,
        )
        detector_artifact = artifact(
            "real_detector_result",
            status="PASSED",
            warnings=("Raw logit is uncalibrated and is not a probability or verdict.",),
            payload=_json_dict(
                {
                    "raw_score": adapter_output.raw_logit,
                    "raw_score_semantics": "uncalibrated_pre_sigmoid_binary_logit",
                    "calibrated_score": None,
                    "calibrator": None,
                    "upstream_predicted_class": adapter_output.upstream_predicted_class,
                    "class_mapping": adapter_output.class_mapping,
                    "mock_backend": False,
                    "fixture_id": request.fixture_id,
                    "preprocessing_sha256": preprocessed.record.preprocessing_sha256,
                }
            ),
        )
        performance_payload = _json_dict(
            {
                "worker_initialization_ms": self._worker_initialization_ms,
                "checkpoint_hash_verification_included": True,
                "checkpoint_cache_hash_verification_ms": self.checkpoint.hash_verification_ms,
                "checkpoint_backend_hash_verification_ms": (
                    self.backend.checkpoint_verification_ms
                ),
                "fitness_checks_ms": fitness_ms,
                "model_load_ms": self.backend.model_load_ms,
                "image_decode_ms": decode_ms,
                "preprocessing_ms": preprocessing_ms,
                "cold_inference_ms": readiness.telemetry.get("backend_probe_inference_ms"),
                "first_fixture_inference_ms": adapter_output.inference_ms,
                "warm_inference_run_count": len(inference_ms),
                "warm_inference_minimum_ms": min(inference_ms),
                "warm_inference_mean_ms": statistics.fmean(inference_ms),
                "warm_inference_median_ms": statistics.median(inference_ms),
                "warm_inference_maximum_ms": max(inference_ms),
                "complete_handler_execution_ms": max(
                    0, round((time.perf_counter_ns() - total_started) / 1_000_000)
                ),
                "device_metadata": measured_outputs[-1].device_metadata,
                "production_throughput_claimed": False,
            }
        )
        performance_artifact = artifact(
            "performance_result",
            status="PASSED",
            warnings=("One controlled fixture does not establish production throughput.",),
            payload=performance_payload,
        )
        repeatability_artifact = artifact(
            "repeatability_result",
            status="PASSED",
            warnings=("Cross-GPU determinism is not claimed.",),
            payload=_json_dict(
                {
                    "run_count": len(logits),
                    "raw_logits": logits,
                    "maximum_output_difference": maximum_output_difference,
                    "tolerance": 1e-6,
                    "determinism": measured_outputs[-1].determinism,
                    "passed": True,
                }
            ),
        )
        negative_artifact = artifact(
            "negative_tests_result",
            status="PASSED",
            warnings=(),
            payload=negative_payload,
        )
        summary_artifact = artifact(
            "phase6_serverless_validation_summary",
            status="PASSED",
            warnings=(
                "One detector and one controlled fixture were tested.",
                "Detector remains uncalibrated and is not connected to the main API.",
            ),
            payload=_json_dict(
                {
                    "runpod_job_id": runpod_job_id,
                    "cuda_fitness": "PASSED",
                    "official_upstream_parity": "PASSED",
                    "real_inference": "PASSED",
                    "repeatability": "PASSED",
                    "negative_tests": "PASSED",
                    "downloads_disabled": not self.settings.allow_model_download,
                    "checkpoint_hash_status": self.manifest.model.checkpoint_hash_status,
                    "calibrated_score": None,
                }
            ),
        )
        return GpuValidationResponse(
            schema_version="1.0",
            fitness=fitness_artifact,
            upstream_parity=parity_artifact,
            detector_result=detector_artifact,
            performance=performance_artifact,
            repeatability=repeatability_artifact,
            negative_tests=negative_artifact,
            summary=summary_artifact,
        )
