"""Exact pinned Community Forensics 384px evaluation preprocessing."""

from __future__ import annotations

import hashlib
import json
from typing import Protocol

import numpy as np
from PIL import Image

from forensic_image_community.contracts import (
    DecodedImage,
    PreprocessedImage,
    PreprocessingRecord,
)
from forensic_image_community.errors import WorkerError, WorkerErrorCode
from forensic_image_community.manifest import ModelManifest


class ImagePreprocessor(Protocol):
    def preprocess(self, decoded: DecodedImage) -> PreprocessedImage: ...


class CommunityForensicsPreprocessor:
    """Reproduce torchvision 0.22.1 Resize(int) and CenterCrop(int) on PIL."""

    def __init__(self, manifest: ModelManifest) -> None:
        self.definition = manifest.preprocessing

    def _configuration(self) -> dict[str, object]:
        return {
            "input_resolution": self.definition.input_resolution,
            "resize_short_edge": self.definition.resize_short_edge,
            "resize_strategy": "preserve_aspect_ratio_short_edge",
            "resize_interpolation": self.definition.resize_interpolation,
            "resize_long_edge_rounding": self.definition.resize_long_edge_rounding,
            "crop_strategy": self.definition.crop,
            "color_conversion": self.definition.color_conversion,
            "tensor_layout": self.definition.tensor_layout,
            "value_scaling": self.definition.value_scaling,
            "normalization_mean": list(self.definition.normalization_mean),
            "normalization_std": list(self.definition.normalization_std),
            "batch_dimension": self.definition.batch_dimension,
            "upstream_repository": self.definition.repository,
            "upstream_revision": self.definition.revision,
            "upstream_transform_version": self.definition.upstream_transform_version,
        }

    def fingerprint(self) -> str:
        normalized = json.dumps(
            self._configuration(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return hashlib.sha256(normalized).hexdigest()

    def preprocess(self, decoded: DecodedImage) -> PreprocessedImage:
        image = decoded.image
        if image.mode != "RGB":
            raise WorkerError(
                WorkerErrorCode.PREPROCESSING_FAILED,
                "Preprocessing requires a decoded RGB image.",
            )
        try:
            width, height = image.size
            short_edge = min(width, height)
            long_edge = max(width, height)
            requested = int(self.definition.resize_short_edge)
            new_long = int(requested * long_edge / short_edge)
            resized_width: int
            resized_height: int
            if width <= height:
                resized_width, resized_height = requested, new_long
            else:
                resized_width, resized_height = new_long, requested
            resized = image.resize(
                (resized_width, resized_height), resample=Image.Resampling.BILINEAR
            )
            try:
                crop_size = self.definition.input_resolution
                top = round((resized_height - crop_size) / 2.0)
                left = round((resized_width - crop_size) / 2.0)
                cropped = resized.crop((left, top, left + crop_size, top + crop_size))
                try:
                    pixels = np.asarray(cropped, dtype=np.float32) / np.float32(255.0)
                finally:
                    cropped.close()
            finally:
                resized.close()
            mean = np.asarray(self.definition.normalization_mean, dtype=np.float32)
            std = np.asarray(self.definition.normalization_std, dtype=np.float32)
            normalized = (pixels - mean) / std
            tensor = np.ascontiguousarray(normalized.transpose(2, 0, 1)[None, ...])
        except WorkerError:
            raise
        except (MemoryError, OSError, ValueError, FloatingPointError) as exc:
            raise WorkerError(
                WorkerErrorCode.PREPROCESSING_FAILED,
                "Image preprocessing failed.",
                internal_detail=type(exc).__name__,
            ) from exc

        record = PreprocessingRecord(
            input_resolution=self.definition.input_resolution,
            resize_short_edge=self.definition.resize_short_edge,
            resize_strategy="preserve_aspect_ratio_short_edge",
            resize_interpolation=self.definition.resize_interpolation,
            crop_strategy=self.definition.crop,
            color_conversion=self.definition.color_conversion,
            tensor_layout=self.definition.tensor_layout,
            value_scaling=self.definition.value_scaling,
            normalization_mean=self.definition.normalization_mean,
            normalization_std=self.definition.normalization_std,
            batch_dimension=self.definition.batch_dimension,
            output_shape=tuple(int(value) for value in tensor.shape),
            upstream_repository=self.definition.repository,
            upstream_revision=self.definition.revision,
            upstream_transform_version=self.definition.upstream_transform_version,
            preprocessing_sha256=self.fingerprint(),
        )
        return PreprocessedImage(tensor=tensor, record=record)
