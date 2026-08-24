from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest
from forensic_contracts import ContainerReleaseManifest, ReleaseCheckStatus
from pydantic import ValidationError

from scripts.generate_container_release import build_manifest, write_manifest

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "docs" / "examples" / "example-container-release.json"


def example_data() -> dict[str, object]:
    loaded = json.loads(EXAMPLE.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_example_release_manifest_validates_and_round_trips() -> None:
    release = ContainerReleaseManifest.model_validate(example_data())
    restored = ContainerReleaseManifest.model_validate_json(release.model_dump_json())
    assert restored == release
    assert release.container.platform == "linux/amd64"
    assert release.model.checkpoint_included is False
    assert release.verification.real_gpu_inference == ReleaseCheckStatus.NOT_RUN


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("source", "git_commit"), "short"),
        (("container", "digest"), "sha256:bad"),
        (("container", "platform"), "linux/arm64"),
        (("container", "repository"), "ghcr.io/Upper/worker"),
        (("model", "checkpoint_included"), True),
        (("verification", "real_gpu_inference"), "passed"),
    ],
)
def test_invalid_release_identity_is_rejected(path: tuple[str, str], value: object) -> None:
    data = example_data()
    component = data[path[0]]
    assert isinstance(component, dict)
    component[path[1]] = value
    with pytest.raises(ValidationError):
        ContainerReleaseManifest.model_validate(data)


def test_cross_component_identity_and_attestation_are_consistent() -> None:
    data = example_data()
    source = data["source"]
    supply = data["supply_chain"]
    assert isinstance(source, dict)
    assert isinstance(supply, dict)
    source["git_commit"] = "3" * 40
    with pytest.raises(ValidationError, match="complete source commit"):
        ContainerReleaseManifest.model_validate(data)

    data = example_data()
    supply = data["supply_chain"]
    assert isinstance(supply, dict)
    supply["github_attestation_created"] = False
    with pytest.raises(ValidationError, match="cannot be verified"):
        ContainerReleaseManifest.model_validate(data)


@pytest.mark.parametrize(
    "unsafe",
    [
        "/Users/developer/project",
        "/home/operator/token",
        "https://objects.example.test/item?X-Amz-Signature=prohibited",
        "RUNPOD_API_KEY=prohibited",
    ],
)
def test_release_manifest_rejects_private_developer_paths(unsafe: str) -> None:
    data = example_data()
    data["future_note"] = unsafe
    with pytest.raises(ValidationError, match="private developer path"):
        ContainerReleaseManifest.model_validate(data)


def test_unknown_future_fields_round_trip_safely() -> None:
    data = example_data()
    data["future_top_level"] = {"retained": True}
    container = data["container"]
    assert isinstance(container, dict)
    container["future_registry_field"] = "retained"
    restored = ContainerReleaseManifest.model_validate(data)
    assert restored.model_extra == {"future_top_level": {"retained": True}}
    assert restored.container.model_extra == {"future_registry_field": "retained"}


def test_container_release_json_schema_is_generated() -> None:
    schema = ContainerReleaseManifest.model_json_schema()
    serialized = json.dumps(schema)
    assert "linux/amd64" in serialized
    assert "pending_gpu_verification" in serialized
    assert "real_gpu_inference" in serialized


def test_release_generator_writes_valid_manifest_and_sha256(tmp_path: Path) -> None:
    vulnerability_summary = tmp_path / "vulnerability-summary.json"
    vulnerability_summary.write_text(
        json.dumps(
            {
                "status": "passed",
                "critical": 0,
                "high": 2,
                "excepted_critical": 0,
                "report_artifact": "image-community-vulnerability-reports",
            }
        ),
        encoding="utf-8",
    )
    args = argparse.Namespace(
        repository="example/forensic-platform",
        git_commit="1" * 40,
        workflow_run_id="123456789",
        workflow_run_attempt=1,
        workflow_run_url="https://github.com/example/forensic-platform/actions/runs/123456789",
        image_repository="ghcr.io/example/forensic-image-community",
        image_digest=f"sha256:{'2' * 64}",
        created_at="2026-08-24T12:00:00Z",
        image_size_bytes=1_000_000,
        vulnerability_summary=vulnerability_summary,
        unit_tests="passed",
        mock_container_test="passed",
        pull_by_digest_test="passed",
        architecture_check="passed",
        image_content_inspection="passed",
        package_access_check="passed",
        sbom_attached=True,
        provenance_attached=True,
        sbom="passed",
        provenance="passed",
        github_attestation_created=True,
        github_attestation_verified=True,
        github_attestation="passed",
    )
    release = build_manifest(args)
    output = tmp_path / "container-release.json"
    checksum_path, digest = write_manifest(release, output)
    assert ContainerReleaseManifest.model_validate_json(output.read_text()) == release
    assert checksum_path.read_text().startswith(digest)
    assert digest in checksum_path.read_text()
