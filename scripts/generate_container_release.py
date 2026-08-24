#!/usr/bin/env python3
"""Generate and hash a validated Phase 5 container release artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from forensic_contracts import (
    ContainerReleaseImage,
    ContainerReleaseManifest,
    ContainerReleaseModel,
    ContainerReleaseSource,
    ContainerReleaseSupplyChain,
    ContainerReleaseVerification,
    ContainerReleaseWorker,
    ReleaseCheckStatus,
    VulnerabilitySummary,
)
from forensic_image_community.manifest import load_model_manifest

ROOT = Path(__file__).resolve().parents[1]
MODEL_MANIFEST = ROOT / "workers" / "image-community" / "model-manifest.yaml"


def parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized not in {"true", "false"}:
        raise argparse.ArgumentTypeError("expected true or false")
    return normalized == "true"


def parse_status(value: str) -> ReleaseCheckStatus:
    try:
        return ReleaseCheckStatus(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid release check status: {value}") from exc


def build_manifest(args: argparse.Namespace) -> ContainerReleaseManifest:
    pinned = load_model_manifest(MODEL_MANIFEST)
    vulnerability_data = json.loads(args.vulnerability_summary.read_text(encoding="utf-8"))
    if not isinstance(vulnerability_data, dict):
        raise ValueError("vulnerability summary must be a JSON object")
    tag = f"sha-{args.git_commit}"
    digest_reference = f"{args.image_repository}@{args.image_digest}"
    source_url = f"https://github.com/{args.repository}"
    labels = {
        "org.opencontainers.image.title": "Community Forensics image worker",
        "org.opencontainers.image.description": (
            "Pinned Community Forensics worker; GPU inference is not yet verified"
        ),
        "org.opencontainers.image.source": source_url,
        "org.opencontainers.image.revision": args.git_commit,
        "org.opencontainers.image.created": args.created_at,
        "org.opencontainers.image.version": tag,
        "org.opencontainers.image.licenses": "LicenseRef-Proprietary",
        "org.opencontainers.image.vendor": args.repository.split("/", maxsplit=1)[0],
    }
    return ContainerReleaseManifest(
        schema_version="1.0",
        worker=ContainerReleaseWorker(
            worker_id="image-community",
            detector_id=pinned.detector.detector_id,
        ),
        source=ContainerReleaseSource(
            repository=args.repository,
            repository_url=source_url,
            git_commit=args.git_commit,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            workflow_run_url=args.workflow_run_url,
        ),
        container=ContainerReleaseImage(
            repository=args.image_repository,
            tag=tag,
            tag_reference=f"{args.image_repository}:{tag}",
            digest=args.image_digest,
            digest_reference=digest_reference,
            platform="linux/amd64",
            architecture="amd64",
            created_at=args.created_at,
            image_size_bytes=args.image_size_bytes,
            base_image=f"{pinned.runtime.base_image}@{pinned.runtime.base_image_digest}",
            base_image_digest=pinned.runtime.base_image_digest,
            oci_labels=labels,
        ),
        model=ContainerReleaseModel(
            model_revision=pinned.model.revision,
            detector_repository_commit=pinned.source.repository_commit,
            expected_checkpoint_sha256=pinned.model.checkpoint_sha256,
            checkpoint_included=False,
            checkpoint_sha256=None,
            checkpoint_status="pending_gpu_verification",
        ),
        vulnerability=VulnerabilitySummary.model_validate(vulnerability_data),
        supply_chain=ContainerReleaseSupplyChain(
            sbom_attached=args.sbom_attached,
            sbom_reference=digest_reference,
            provenance_attached=args.provenance_attached,
            provenance_reference=digest_reference,
            github_attestation_created=args.github_attestation_created,
            github_attestation_verified=args.github_attestation_verified,
            github_attestation_subject=f"oci://{digest_reference}",
            github_attestation_repository=args.repository,
        ),
        verification=ContainerReleaseVerification(
            unit_tests=args.unit_tests,
            mock_container_test=args.mock_container_test,
            pull_by_digest_test=args.pull_by_digest_test,
            architecture_check=args.architecture_check,
            image_content_inspection=args.image_content_inspection,
            package_access_check=args.package_access_check,
            vulnerability_scan=parse_status(str(vulnerability_data["status"])),
            sbom=args.sbom,
            provenance=args.provenance,
            github_attestation=args.github_attestation,
            real_gpu_inference=ReleaseCheckStatus.NOT_RUN,
        ),
    )


def write_manifest(manifest: ContainerReleaseManifest, output: Path) -> tuple[Path, str]:
    body = manifest.model_dump_json(indent=2) + "\n"
    output.write_text(body, encoding="utf-8")
    digest = hashlib.sha256(body.encode()).hexdigest()
    checksum_path = output.with_name(f"{output.stem}.sha256")
    checksum_path.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    return checksum_path, digest


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--repository", required=True)
    cli.add_argument("--git-commit", required=True)
    cli.add_argument("--workflow-run-id", required=True)
    cli.add_argument("--workflow-run-attempt", required=True, type=int)
    cli.add_argument("--workflow-run-url", required=True)
    cli.add_argument("--image-repository", required=True)
    cli.add_argument("--image-digest", required=True)
    cli.add_argument("--created-at", required=True)
    cli.add_argument("--image-size-bytes", required=True, type=int)
    cli.add_argument("--vulnerability-summary", required=True, type=Path)
    cli.add_argument("--unit-tests", required=True, type=parse_status)
    cli.add_argument("--mock-container-test", required=True, type=parse_status)
    cli.add_argument("--pull-by-digest-test", required=True, type=parse_status)
    cli.add_argument("--architecture-check", required=True, type=parse_status)
    cli.add_argument("--image-content-inspection", required=True, type=parse_status)
    cli.add_argument("--package-access-check", required=True, type=parse_status)
    cli.add_argument("--sbom-attached", required=True, type=parse_bool)
    cli.add_argument("--provenance-attached", required=True, type=parse_bool)
    cli.add_argument("--sbom", required=True, type=parse_status)
    cli.add_argument("--provenance", required=True, type=parse_status)
    cli.add_argument("--github-attestation-created", required=True, type=parse_bool)
    cli.add_argument("--github-attestation-verified", required=True, type=parse_bool)
    cli.add_argument("--github-attestation", required=True, type=parse_status)
    cli.add_argument("--output", default=Path("container-release.json"), type=Path)
    return cli


def main() -> None:
    args = parser().parse_args()
    manifest = build_manifest(args)
    checksum_path, digest = write_manifest(manifest, args.output)
    print(f"release manifest: {args.output}")
    print(f"release manifest sha256: {digest}")
    print(f"checksum file: {checksum_path}")


if __name__ == "__main__":
    main()
