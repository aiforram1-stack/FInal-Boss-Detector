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
        random_seed: int = 11997733,
    ) -> None:
        self.manifest = manifest
        self.checkpoint_path = checkpoint_path
        self.container_digest = container_digest
        self.min_free_vram_bytes = min_free_vram_bytes
        self.random_seed = random_seed
        self._torch: ModuleType | None = None
        self._model: Any | None = None
        self._model_load_ms: int | None = None

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
            checkpoint_sha256=self.manifest.model.checkpoint_sha256,
        )

    def verify_checkpoint(self) -> None:
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
        if stat.st_size != self.manifest.model.checkpoint_byte_length:
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
        if digest.hexdigest() != self.manifest.model.checkpoint_sha256:
            raise WorkerError(
                WorkerErrorCode.CHECKPOINT_HASH_MISMATCH,
                "Checkpoint SHA-256 does not match the pinned manifest.",
            )

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
            device_index = torch.cuda.current_device()
            properties = torch.cuda.get_device_properties(device_index)
            device_metadata = {
                "device_type": "cuda",
                "gpu_model": properties.name,
                "cuda_version": str(torch.version.cuda),
                "pytorch_version": str(torch.__version__),
                "total_vram_bytes": int(total_vram),
                "free_vram_before_inference_bytes": int(free_before),
                "peak_allocated_vram_bytes": peak_vram,
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
