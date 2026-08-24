"""Fail-closed real Community Forensics CUDA backend.

PyTorch, timm and safetensors are imported only when this backend is explicitly
loaded. Ordinary macOS imports and tests therefore require no CUDA stack.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from types import ModuleType
from typing import Any

from forensic_contracts import DetectorIdentity

from forensic_image_community.contracts import BackendOutput, PreprocessedImage
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.manifest import ModelManifest

HASH_CHUNK_BYTES = 1024 * 1024


class CommunityForensicsBackend:
    def __init__(
        self,
        *,
        manifest: ModelManifest,
        checkpoint_path: Path,
        container_digest: str | None,
        min_free_vram_bytes: int,
        checkpoint_expected_sha256: str | None = None,
        checkpoint_expected_byte_length: int | None = None,
        random_seed: int = 11997733,
    ) -> None:
        self.manifest = manifest
        self.checkpoint_path = checkpoint_path
        self.container_digest = container_digest
        self.min_free_vram_bytes = min_free_vram_bytes
        self.checkpoint_expected_sha256 = (
            checkpoint_expected_sha256 or manifest.model.checkpoint_sha256
        )
        self.checkpoint_expected_byte_length = (
            checkpoint_expected_byte_length or manifest.model.checkpoint_byte_length
        )
        self.random_seed = random_seed
        self._torch: ModuleType | None = None
        self._model: Any | None = None
        self._model_load_ms: int | None = None
        self._checkpoint_sha256: str | None = None
        self._checkpoint_byte_length: int | None = None
        self._checkpoint_verification_ms: int | None = None

    @property
    def mock_backend(self) -> bool:
        return False

    def identity(self) -> DetectorIdentity:
        if self.container_digest is None:
            raise WorkerError(
                WorkerErrorCode.WORKER_NOT_READY,
                "Real detector identity requires a container digest.",
            )
        return DetectorIdentity(
            schema_version="1.0",
            detector_name=self.manifest.detector.detector_id,
            detector_version=self.manifest.detector.version,
            repository_url=self.manifest.source.repository_url,
            repository_commit=self.manifest.source.repository_commit,
            container_digest=self.container_digest,
            model_revision=self.manifest.model.revision,
            checkpoint_sha256=self.checkpoint_expected_sha256,
        )

    @property
    def model_loaded(self) -> bool:
        return self._model is not None

    @property
    def model_training(self) -> bool | None:
        if self._model is None:
            return None
        return bool(self._model.training)

    @property
    def model_load_ms(self) -> int | None:
        return self._model_load_ms

    @property
    def checkpoint_verification_ms(self) -> int | None:
        return self._checkpoint_verification_ms

    def verify_checkpoint(
        self,
        *,
        expected_sha256: str | None = None,
        expected_byte_length: int | None = None,
    ) -> tuple[int, str]:
        verification_started = time.perf_counter_ns()
        try:
            stat = self.checkpoint_path.stat()
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Verified checkpoint is unavailable.",
                internal_detail=type(exc).__name__,
            ) from exc
        if not self.checkpoint_path.is_file() or self.checkpoint_path.is_symlink():
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Verified checkpoint is unavailable.",
            )
        required_byte_length = (
            self.checkpoint_expected_byte_length
            if expected_byte_length is None
            else expected_byte_length
        )
        required_sha256 = (
            self.checkpoint_expected_sha256 if expected_sha256 is None else expected_sha256
        )
        if stat.st_size != required_byte_length:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Checkpoint length does not match the pinned manifest.",
            )
        digest = hashlib.sha256()
        try:
            with self.checkpoint_path.open("rb") as checkpoint:
                while chunk := checkpoint.read(HASH_CHUNK_BYTES):
                    digest.update(chunk)
        except OSError as exc:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_UNAVAILABLE,
                "Checkpoint could not be verified.",
                internal_detail=type(exc).__name__,
            ) from exc
        actual_sha256 = digest.hexdigest()
        if actual_sha256 != required_sha256:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Checkpoint SHA-256 does not match the pinned manifest.",
            )
        self._checkpoint_byte_length = stat.st_size
        self._checkpoint_sha256 = actual_sha256
        self._checkpoint_verification_ms = max(
            0,
            round((time.perf_counter_ns() - verification_started) / 1_000_000),
        )
        return stat.st_size, actual_sha256

    def ensure_loaded(self) -> None:
        if self._model is not None:
            return
        self.verify_checkpoint()
        try:
            import timm  # type: ignore[import-not-found]
            import torch  # type: ignore[import-not-found]
            from safetensors.torch import load_model  # type: ignore[import-not-found]
        except ImportError as exc:
            raise WorkerError(
                WorkerErrorCode.MODEL_LOAD_FAILED,
                "Required GPU runtime dependencies are unavailable.",
                internal_detail=type(exc).__name__,
            ) from exc
        if not torch.cuda.is_available():
            raise WorkerError(
                WorkerErrorCode.CUDA_UNAVAILABLE,
                "CUDA is required by the real Community Forensics backend.",
            )

        class PinnedViTClassifier(torch.nn.Module):  # type: ignore[misc]
            def __init__(self) -> None:
                super().__init__()
                self.vit = timm.create_model(
                    "vit_small_patch16_384.augreg_in21k_ft_in1k",
                    pretrained=False,
                )
                self.vit.head = torch.nn.Linear(384, 1, bias=True)

            def forward(self, tensor: Any) -> Any:
                return self.vit(tensor)

        started = time.perf_counter()
        try:
            torch.manual_seed(self.random_seed)
            torch.cuda.manual_seed_all(self.random_seed)
            torch.use_deterministic_algorithms(True)
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
            model = PinnedViTClassifier()
            load_model(model, str(self.checkpoint_path), strict=True, device="cpu")
            model.to("cuda")
            model.eval()
        except WorkerError:
            raise
        except Exception as exc:
            raise WorkerError(
                WorkerErrorCode.MODEL_LOAD_FAILED,
                "Community Forensics model could not be loaded.",
                internal_detail=type(exc).__name__,
            ) from exc
        self._model_load_ms = max(0, round((time.perf_counter() - started) * 1000))
        self._torch = torch
        self._model = model

    def runtime_environment(self) -> dict[str, object]:
        self.ensure_loaded()
        torch = self._torch
        if torch is None:
            raise WorkerError(WorkerErrorCode.WORKER_NOT_READY, "GPU runtime is not ready.")
        device_index = torch.cuda.current_device()
        properties = torch.cuda.get_device_properties(device_index)
        free_vram, total_vram = torch.cuda.mem_get_info()
        try:
            driver_version: str | None = str(torch._C._cuda_getDriverVersion())
        except (AttributeError, RuntimeError):
            driver_version = None
        return {
            "gpu_model": str(properties.name),
            "gpu_count": int(torch.cuda.device_count()),
            "total_vram_bytes": int(total_vram),
            "free_vram_bytes": int(free_vram),
            "cuda_version": str(torch.version.cuda),
            "cuda_driver_version": driver_version,
            "pytorch_version": str(torch.__version__),
            "precision": "float32",
            "random_seed": self.random_seed,
            "deterministic_algorithms": True,
            "cudnn_deterministic": True,
            "cudnn_benchmark": False,
        }

    def infer(self, preprocessed: PreprocessedImage) -> BackendOutput:
        self.ensure_loaded()
        torch = self._torch
        model = self._model
        if torch is None or model is None:
            raise WorkerError(WorkerErrorCode.WORKER_NOT_READY, "Model is not ready.")
        if tuple(preprocessed.tensor.shape) != (1, 3, 384, 384):
            raise WorkerError(
                WorkerErrorCode.PREPROCESSING_FAILED,
                "Preprocessed tensor shape does not match the pinned model.",
            )
        try:
            torch.cuda.synchronize()
            free_before, total_vram = torch.cuda.mem_get_info()
            if int(free_before) < self.min_free_vram_bytes:
                raise WorkerError(
                    WorkerErrorCode.WORKER_NOT_READY,
                    "Available GPU memory is below the configured readiness threshold.",
                )
            torch.cuda.reset_peak_memory_stats()
            started = time.perf_counter()
            tensor = torch.from_numpy(preprocessed.tensor).to(device="cuda", dtype=torch.float32)
            with torch.inference_mode():
                output = model(tensor)
            torch.cuda.synchronize()
            inference_ms = max(0, round((time.perf_counter() - started) * 1000))
            if tuple(output.shape) != (1, 1):
                raise WorkerError(
                    WorkerErrorCode.INFERENCE_FAILED,
                    "Model output shape did not match the pinned contract.",
                )
            raw_logit = float(output.detach().to(device="cpu", dtype=torch.float32).item())
            peak_vram = int(torch.cuda.max_memory_allocated())
            peak_reserved_vram = int(torch.cuda.max_memory_reserved())
            free_after, _ = torch.cuda.mem_get_info()
            device_index = torch.cuda.current_device()
            properties = torch.cuda.get_device_properties(device_index)
            try:
                driver_version: str | None = str(torch._C._cuda_getDriverVersion())
            except (AttributeError, RuntimeError):
                driver_version = None
            device_metadata = {
                "device_type": "cuda",
                "gpu_model": properties.name,
                "gpu_count": int(torch.cuda.device_count()),
                "cuda_version": str(torch.version.cuda),
                "cuda_driver_version": driver_version,
                "pytorch_version": str(torch.__version__),
                "total_vram_bytes": int(total_vram),
                "free_vram_before_inference_bytes": int(free_before),
                "free_vram_after_inference_bytes": int(free_after),
                "peak_allocated_vram_bytes": peak_vram,
                "peak_reserved_vram_bytes": peak_reserved_vram,
            }
            del output
            del tensor
        except WorkerError:
            raise
        except Exception as exc:
            raise WorkerError(
                WorkerErrorCode.INFERENCE_FAILED,
                "Community Forensics inference failed.",
                internal_detail=type(exc).__name__,
            ) from exc
        return BackendOutput(
            raw_logit=raw_logit,
            raw_outputs={
                "raw_logit": raw_logit,
                "output_shape": [1, 1],
                "mock_backend": False,
                "score_semantics": "uncalibrated_pre_sigmoid_binary_logit",
            },
            class_mapping=self.manifest.output.class_mapping,
            upstream_predicted_class="fake" if raw_logit >= 0 else "real",
            mock_backend=False,
            device_metadata=device_metadata,
            determinism={
                "random_seed": self.random_seed,
                "deterministic_algorithms": True,
                "cudnn_deterministic": True,
                "cudnn_benchmark": False,
                "precision": "float32",
                "device_type": "cuda",
                "cross_device_bitwise_determinism_claimed": False,
            },
            model_load_ms=self._model_load_ms,
            inference_ms=inference_ms,
        )
