"""Structured startup readiness checks for mock and future GPU modes."""

from __future__ import annotations

import tempfile

import numpy as np
from forensic_contracts import DetectorJob, DetectorResult

from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.contracts import (
    FitnessResult,
    PreprocessedImage,
    PreprocessingRecord,
)
from forensic_image_community.errors import WorkerError
from forensic_image_community.manifest import ModelManifest
from forensic_image_community.model_backend import DetectorBackend


class WorkerFitnessCheck:
    def __init__(
        self,
        *,
        settings: ImageCommunitySettings,
        manifest: ModelManifest,
        backend: DetectorBackend,
    ) -> None:
        self.settings = settings
        self.manifest = manifest
        self.backend = backend

    @staticmethod
    def _probe_input() -> PreprocessedImage:
        record = PreprocessingRecord(
            input_resolution=384,
            resize_short_edge=440,
            resize_strategy="preserve_aspect_ratio_short_edge",
            resize_interpolation="pillow_bilinear_antialias",
            crop_strategy="center_384x384",
            color_conversion="RGB",
            tensor_layout="NCHW",
            value_scaling="uint8_to_float32_0_1",
            normalization_mean=(0.485, 0.456, 0.406),
            normalization_std=(0.229, 0.224, 0.225),
            batch_dimension=1,
            output_shape=(1, 3, 384, 384),
            upstream_repository="fitness-probe",
            upstream_revision="0" * 40,
            upstream_transform_version="fitness-probe",
            preprocessing_sha256="0" * 64,
        )
        return PreprocessedImage(tensor=np.zeros((1, 3, 384, 384), dtype=np.float32), record=record)

    def check(self) -> FitnessResult:
        checks = {
            "configuration_valid": True,
            "manifest_valid": True,
            "contracts_import": DetectorJob is not None and DetectorResult is not None,
            "temporary_directory_writable": False,
            "backend_probe": False,
            "mock_disabled_in_production": not (
                self.settings.environment == "production" and self.backend.mock_backend
            ),
        }
        try:
            temp_root = self.settings.ensure_temp_root()
            with tempfile.NamedTemporaryFile(dir=temp_root, prefix="fitness-", delete=True):
                checks["temporary_directory_writable"] = True
            if not checks["mock_disabled_in_production"]:
                raise ValueError("mock backend is prohibited in production")
            output = self.backend.infer(self._probe_input())
            if output.mock_backend != self.backend.mock_backend:
                raise ValueError("backend probe identity mismatch")
            self.backend.identity()
            checks["backend_probe"] = True
        except WorkerError as exc:
            return FitnessResult(
                ready=False,
                mode="mock" if self.backend.mock_backend else "real_gpu",
                checks=checks,
                error_code=exc.code.value,
                message=exc.safe_message,
            )
        except (OSError, ValueError):
            return FitnessResult(
                ready=False,
                mode="mock" if self.backend.mock_backend else "real_gpu",
                checks=checks,
                error_code="WORKER_NOT_READY",
                message="Worker readiness validation failed.",
            )
        return FitnessResult(
            ready=all(checks.values()),
            mode="mock" if self.backend.mock_backend else "real_gpu",
            checks=checks,
            message="Worker readiness checks passed.",
        )
