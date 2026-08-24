"""Validated immutable Community Forensics model manifest."""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

SHA256_PATTERN = r"^[a-f0-9]{64}$"
COMMIT_PATTERN = r"^[a-f0-9]{40}$"
DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
EXPECTED_SOURCE_REPOSITORY = "https://github.com/JeongsooP/Community-Forensics"
EXPECTED_SOURCE_COMMIT = "ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4"
EXPECTED_MODEL_REPOSITORY = "OwensLab/commfor-model-384"
EXPECTED_MODEL_REVISION = "6076002bf0d9dd37537f965ee2f06f826c333b61"
EXPECTED_CHECKPOINT_SHA256 = "b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387"
EXPECTED_PREPROCESSOR_REPOSITORY = "OwensLab/commfor-data-preprocessor"
EXPECTED_PREPROCESSOR_REVISION = "3540a3f0d688f8bf492a8aed48613b891f88047e"
EXPECTED_BASE_IMAGE = "pytorch/pytorch:2.7.1-cuda12.6-cudnn9-runtime"
EXPECTED_BASE_DIGEST = "sha256:2b59b1b91885677814f78be1f8df48a25d5dc952eb6580eaecfefca510f9afd3"
EXPECTED_ARCHITECTURE = "vit_small_patch16_384.augreg_in21k_ft_in1k with one-logit head"
EXPECTED_TRANSFORM_VERSION = "torchvision-0.22.1-eval-transform-at-ee5b71d"


class ManifestRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )


class DetectorDefinition(ManifestRecord):
    detector_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]+$")
    version: str = Field(min_length=1, max_length=128)
    modality: Literal["image"]
    task: Literal["synthetic_image_detection"]
    calibrated: Literal[False]


class SourceDefinition(ManifestRecord):
    repository_url: HttpUrl
    repository_commit: str = Field(pattern=COMMIT_PATTERN)
    license: Literal["MIT"]
    third_party_notice: str = Field(min_length=1, max_length=255)
    integration_strategy: Literal["minimal_verified_model_wrapper"]


class ModelDefinition(ManifestRecord):
    repository: str = Field(min_length=1, max_length=255)
    revision: str = Field(pattern=COMMIT_PATTERN)
    filename: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    format: Literal["safetensors"]
    checkpoint_sha256: str = Field(pattern=SHA256_PATTERN)
    checkpoint_byte_length: int = Field(gt=0)
    checkpoint_hash_status: Literal["verified_from_huggingface_lfs_oid", "OBSERVED_BOOTSTRAP_HASH"]
    input_resolution: Literal[384]
    architecture: str = Field(min_length=1, max_length=255)


class PreprocessingDefinition(ManifestRecord):
    repository: str = Field(min_length=1, max_length=255)
    revision: str = Field(pattern=COMMIT_PATTERN)
    input_resolution: Literal[384]
    resize_short_edge: Literal[440]
    resize_interpolation: Literal["pillow_bilinear_antialias"]
    resize_long_edge_rounding: Literal["floor"]
    crop: Literal["center_384x384"]
    color_conversion: Literal["RGB"]
    tensor_layout: Literal["NCHW"]
    value_scaling: Literal["uint8_to_float32_0_1"]
    normalization_mean: tuple[float, float, float]
    normalization_std: tuple[float, float, float]
    batch_dimension: Literal[1]
    upstream_transform_version: str = Field(min_length=1, max_length=255)


class RuntimeDefinition(ManifestRecord):
    python_version: Literal["3.11"]
    pytorch_version: Literal["2.7.1"]
    torchvision_version: Literal["0.22.1"]
    timm_version: Literal["1.0.15"]
    cuda_version: Literal["12.6.3"]
    target_platform: Literal["linux/amd64"]
    base_image: str = Field(min_length=1, max_length=255)
    base_image_digest: str = Field(pattern=DIGEST_PATTERN)
    upstream_python_minimum: None = None


class OutputDefinition(ManifestRecord):
    raw_output_type: Literal["binary_classification_logit"]
    tensor_shape: tuple[Literal["batch"], Literal[1]]
    class_mapping: dict[str, str]
    positive_class: Literal["fake"]
    score_semantics: str = Field(min_length=1, max_length=1000)
    probability: Literal[False]
    calibrated: Literal[False]

    @model_validator(mode="after")
    def validate_mapping(self) -> Self:
        if self.class_mapping != {"0": "real", "1": "fake"}:
            raise ValueError("class_mapping must preserve the upstream real=0,fake=1 labels")
        return self


class ModelManifest(ManifestRecord):
    schema_version: Literal["1.0"]
    detector: DetectorDefinition
    source: SourceDefinition
    model: ModelDefinition
    preprocessing: PreprocessingDefinition
    runtime: RuntimeDefinition
    output: OutputDefinition
    limitations: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_resolution_alignment(self) -> Self:
        if self.model.input_resolution != self.preprocessing.input_resolution:
            raise ValueError("model and preprocessing input resolution must match")
        if self.detector.calibrated or self.output.calibrated or self.output.probability:
            raise ValueError("Phase 4 output must remain uncalibrated and non-probabilistic")
        actual_pins = {
            "detector_id": self.detector.detector_id,
            "detector_version": self.detector.version,
            "source_repository": str(self.source.repository_url).rstrip("/"),
            "source_commit": self.source.repository_commit,
            "model_repository": self.model.repository,
            "model_revision": self.model.revision,
            "checkpoint_filename": self.model.filename,
            "checkpoint_sha256": self.model.checkpoint_sha256,
            "checkpoint_byte_length": self.model.checkpoint_byte_length,
            "architecture": self.model.architecture,
            "preprocessor_repository": self.preprocessing.repository,
            "preprocessor_revision": self.preprocessing.revision,
            "normalization_mean": self.preprocessing.normalization_mean,
            "normalization_std": self.preprocessing.normalization_std,
            "transform_version": self.preprocessing.upstream_transform_version,
            "base_image": self.runtime.base_image,
            "base_digest": self.runtime.base_image_digest,
        }
        expected_pins = {
            "detector_id": "community-forensics-384",
            "detector_version": "1.0.0+ee5b71d",
            "source_repository": EXPECTED_SOURCE_REPOSITORY,
            "source_commit": EXPECTED_SOURCE_COMMIT,
            "model_repository": EXPECTED_MODEL_REPOSITORY,
            "model_revision": EXPECTED_MODEL_REVISION,
            "checkpoint_filename": "model.safetensors",
            "checkpoint_sha256": EXPECTED_CHECKPOINT_SHA256,
            "checkpoint_byte_length": 87_262_324,
            "architecture": EXPECTED_ARCHITECTURE,
            "preprocessor_repository": EXPECTED_PREPROCESSOR_REPOSITORY,
            "preprocessor_revision": EXPECTED_PREPROCESSOR_REVISION,
            "normalization_mean": (0.485, 0.456, 0.406),
            "normalization_std": (0.229, 0.224, 0.225),
            "transform_version": EXPECTED_TRANSFORM_VERSION,
            "base_image": EXPECTED_BASE_IMAGE,
            "base_digest": EXPECTED_BASE_DIGEST,
        }
        if actual_pins != expected_pins:
            raise ValueError("manifest values do not match the reviewed Phase 4 pins")
        return self


def load_model_manifest(path: Path) -> ModelManifest:
    try:
        payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError("model manifest could not be read") from exc
    return ModelManifest.model_validate(payload)
