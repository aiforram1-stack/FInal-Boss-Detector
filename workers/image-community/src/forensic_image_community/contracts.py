"""Internal typed records used between injected worker services."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image
from pydantic import BaseModel, ConfigDict, Field, JsonValue


class InternalRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)


class DecodeMetadata(InternalRecord):
    decoder_name: str
    decoder_version: str
    detected_format: str
    detected_mime_type: str
    original_width: int = Field(gt=0)
    original_height: int = Field(gt=0)
    original_color_mode: str
    orientation_handling: str
    output_color_mode: str
    warnings: tuple[str, ...] = ()


class PreprocessingRecord(InternalRecord):
    input_resolution: int
    resize_short_edge: int
    resize_strategy: str
    resize_interpolation: str
    crop_strategy: str
    color_conversion: str
    tensor_layout: str
    value_scaling: str
    normalization_mean: tuple[float, float, float]
    normalization_std: tuple[float, float, float]
    batch_dimension: int
    output_shape: tuple[int, int, int, int]
    upstream_repository: str
    upstream_revision: str
    upstream_transform_version: str
    preprocessing_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class BackendOutput(InternalRecord):
    raw_logit: float
    raw_outputs: dict[str, JsonValue]
    class_mapping: dict[str, str]
    upstream_predicted_class: str
    mock_backend: bool
    device_metadata: dict[str, JsonValue]
    determinism: dict[str, JsonValue]
    model_load_ms: int | None = Field(default=None, ge=0)
    inference_ms: int = Field(ge=0)


class FitnessResult(InternalRecord):
    schema_version: str = "1.0"
    ready: bool
    mode: str
    checks: dict[str, bool]
    error_code: str | None = None
    message: str
    telemetry: dict[str, JsonValue] = Field(default_factory=dict)


@dataclass(slots=True)
class FetchedInput:
    path: Path
    sha256: str
    byte_length: int
    response_mime_type: str

    def cleanup(self) -> None:
        self.path.unlink(missing_ok=True)


@dataclass(slots=True)
class DecodedImage:
    image: Image.Image
    metadata: DecodeMetadata

    def close(self) -> None:
        self.image.close()


@dataclass(frozen=True, slots=True)
class PreprocessedImage:
    tensor: np.ndarray
    record: PreprocessingRecord
