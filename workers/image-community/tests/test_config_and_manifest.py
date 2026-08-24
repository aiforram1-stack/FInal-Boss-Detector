from __future__ import annotations

import json
from pathlib import Path

import pytest
from forensic_image_community.config import ImageCommunitySettings
from forensic_image_community.factory import validated_manifest
from forensic_image_community.manifest import ModelManifest, load_model_manifest
from helpers import WORKER_ROOT, manifest, settings
from pydantic import ValidationError


def test_safe_local_configuration_defaults_and_host_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IMAGE_COMMUNITY_ALLOWED_INPUT_HOSTS", "one.example,two.example.")
    configured = ImageCommunitySettings(temp_root=tmp_path / "temp")
    assert configured.backend == "mock"
    assert configured.allow_model_download is False
    assert configured.allow_redirects is False
    assert configured.allowed_input_hosts == {"one.example", "two.example"}
    assert configured.require_cuda is True
    assert configured.ensure_temp_root().is_dir()


@pytest.mark.parametrize(
    "overrides",
    [
        {"environment": "production", "backend": "mock"},
        {"environment": "production", "backend": "community", "container_digest": None},
        {
            "environment": "production",
            "backend": "community",
            "container_digest": f"sha256:{'a' * 64}",
            "project_source_commit": None,
        },
        {
            "environment": "production",
            "backend": "community",
            "container_digest": f"sha256:{'a' * 64}",
            "project_source_commit": "b" * 40,
            "endpoint_release_identity": None,
        },
        {"backend": "community", "require_cuda": False},
        {"checkpoint_bootstrap_mode": True, "require_verified_checkpoint_hash": True},
        {"allow_redirects": True, "max_redirects": 0},
        {"download_chunk_bytes": 1024, "max_input_bytes": 512},
        {"allowed_input_hosts": {"https://bad.example"}},
    ],
)
def test_invalid_or_unsafe_configuration_is_rejected(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        ImageCommunitySettings.model_validate(overrides)


def test_manifest_pins_every_identity_and_is_not_calibrated() -> None:
    loaded = manifest()
    assert loaded.source.repository_commit == "ee5b71d43db0f3779e1edd64ee927b13f2dd6ad4"
    assert loaded.model.revision == "6076002bf0d9dd37537f965ee2f06f826c333b61"
    assert loaded.model.filename == "model.safetensors"
    assert loaded.model.checkpoint_sha256 == (
        "b89f36275f3bf5e2b040eee36597a8f19db051bff9a473a9cf7b2466284fb387"
    )
    assert loaded.preprocessing.resize_short_edge == 440
    assert loaded.output.class_mapping == {"0": "real", "1": "fake"}
    assert loaded.output.probability is False
    assert loaded.output.calibrated is False
    assert loaded.detector.calibrated is False


def test_manifest_json_schema_generation_and_round_trip() -> None:
    schema = ModelManifest.model_json_schema()
    assert schema["additionalProperties"] is False
    assert "checkpoint_sha256" in json.dumps(schema)
    loaded = manifest()
    restored = ModelManifest.model_validate_json(loaded.model_dump_json())
    assert restored == loaded


@pytest.mark.parametrize(
    ("current", "replacement"),
    [
        ("probability: false", "probability: true"),
        ("normalization_mean: [0.485, 0.456, 0.406]", "normalization_mean: [0, 0, 0]"),
        ("repository: OwensLab/commfor-model-384", "repository: unreviewed/model"),
    ],
)
def test_invalid_or_unreviewed_manifest_fails_closed(
    tmp_path: Path, current: str, replacement: str
) -> None:
    source = (WORKER_ROOT / "model-manifest.yaml").read_text(encoding="utf-8")
    invalid = tmp_path / "manifest.yaml"
    invalid.write_text(source.replace(current, replacement), encoding="utf-8")
    with pytest.raises(ValidationError):
        load_model_manifest(invalid)
    with pytest.raises(Exception, match="Pinned model manifest is invalid"):
        validated_manifest(invalid)


def test_manifest_path_and_temp_root_are_configurable(tmp_path: Path) -> None:
    configured = settings(tmp_path)
    assert configured.model_manifest == WORKER_ROOT / "model-manifest.yaml"
    assert configured.ensure_temp_root() == (tmp_path / "worker-temp").resolve()


def test_phase6_bootstrap_and_verified_production_modes_are_mutually_exclusive(
    tmp_path: Path,
) -> None:
    common = {
        "environment": "production",
        "backend": "community",
        "container_digest": f"sha256:{'a' * 64}",
        "project_source_commit": "b" * 40,
        "endpoint_release_identity": "phase6-test-release",
        "temp_root": tmp_path / "temp",
    }
    bootstrap = ImageCommunitySettings.model_validate(
        {
            **common,
            "checkpoint_bootstrap_mode": True,
            "require_verified_checkpoint_hash": False,
        }
    )
    verified = ImageCommunitySettings.model_validate(common)
    assert bootstrap.checkpoint_bootstrap_mode is True
    assert bootstrap.require_verified_checkpoint_hash is False
    assert verified.checkpoint_bootstrap_mode is False
    assert verified.require_verified_checkpoint_hash is True
