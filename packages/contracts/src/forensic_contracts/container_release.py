"""Versioned contract for one immutable worker-container publication."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

from forensic_contracts.models import Sha256, UtcDateTime, VersionedContract

OCI_DIGEST_PATTERN = r"^sha256:[a-f0-9]{64}$"
GIT_COMMIT_PATTERN = r"^[a-f0-9]{40}$"
GHCR_REPOSITORY_PATTERN = r"^ghcr\.io/[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._/-]*$"
REPOSITORY_PATTERN = r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
TAG_PATTERN = r"^sha-[a-f0-9]{40}$"

OciDigest = Annotated[str, Field(pattern=OCI_DIGEST_PATTERN)]
GitCommit = Annotated[str, Field(pattern=GIT_COMMIT_PATTERN)]


class ReleaseCheckStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_RUN = "not_run"
    UNAVAILABLE = "unavailable"


class ReleaseComponent(BaseModel):
    """Immutable nested component that preserves compatible future fields."""

    model_config = ConfigDict(
        extra="allow",
        frozen=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class ContainerReleaseWorker(ReleaseComponent):
    worker_id: Literal["image-community"]
    detector_id: Literal["community-forensics-384"]


class ContainerReleaseSource(ReleaseComponent):
    repository: str = Field(pattern=REPOSITORY_PATTERN)
    repository_url: HttpUrl
    git_commit: GitCommit
    workflow_run_id: str = Field(pattern=r"^[0-9]+$")
    workflow_run_attempt: int = Field(ge=1)
    workflow_run_url: HttpUrl


class ContainerReleaseImage(ReleaseComponent):
    repository: str = Field(pattern=GHCR_REPOSITORY_PATTERN)
    tag: str = Field(pattern=TAG_PATTERN)
    tag_reference: str
    digest: OciDigest
    digest_reference: str
    platform: Literal["linux/amd64"]
    architecture: Literal["amd64"]
    created_at: UtcDateTime
    image_size_bytes: int = Field(gt=0)
    base_image: str
    base_image_digest: OciDigest
    oci_labels: dict[str, str]

    @model_validator(mode="after")
    def validate_references_and_labels(self) -> Self:
        if self.tag_reference != f"{self.repository}:{self.tag}":
            raise ValueError("tag reference must match repository and tag")
        if self.digest_reference != f"{self.repository}@{self.digest}":
            raise ValueError("digest reference must match repository and digest")
        if not self.base_image.endswith(f"@{self.base_image_digest}"):
            raise ValueError("base image must end with its immutable digest")
        required_labels = {
            "org.opencontainers.image.title",
            "org.opencontainers.image.description",
            "org.opencontainers.image.source",
            "org.opencontainers.image.revision",
            "org.opencontainers.image.created",
            "org.opencontainers.image.version",
            "org.opencontainers.image.licenses",
            "org.opencontainers.image.vendor",
        }
        missing = required_labels - self.oci_labels.keys()
        if missing:
            raise ValueError(f"required OCI labels are missing: {', '.join(sorted(missing))}")
        return self


class ContainerReleaseModel(ReleaseComponent):
    model_revision: GitCommit
    detector_repository_commit: GitCommit
    expected_checkpoint_sha256: Sha256
    checkpoint_included: Literal[False]
    checkpoint_sha256: None = None
    checkpoint_status: Literal["pending_gpu_verification"]


class VulnerabilitySummary(ReleaseComponent):
    status: ReleaseCheckStatus
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    excepted_critical: int = Field(ge=0)
    report_artifact: str = Field(min_length=1)


class ContainerReleaseSupplyChain(ReleaseComponent):
    sbom_attached: bool
    sbom_reference: str
    provenance_attached: bool
    provenance_reference: str
    github_attestation_created: bool
    github_attestation_verified: bool
    github_attestation_subject: str
    github_attestation_repository: str = Field(pattern=REPOSITORY_PATTERN)

    @model_validator(mode="after")
    def validate_attestation_state(self) -> Self:
        if self.github_attestation_verified and not self.github_attestation_created:
            raise ValueError("an attestation cannot be verified before it is created")
        return self


class ContainerReleaseVerification(ReleaseComponent):
    unit_tests: ReleaseCheckStatus
    mock_container_test: ReleaseCheckStatus
    pull_by_digest_test: ReleaseCheckStatus
    architecture_check: ReleaseCheckStatus
    image_content_inspection: ReleaseCheckStatus
    package_access_check: ReleaseCheckStatus
    vulnerability_scan: ReleaseCheckStatus
    sbom: ReleaseCheckStatus
    provenance: ReleaseCheckStatus
    github_attestation: ReleaseCheckStatus
    real_gpu_inference: Literal[ReleaseCheckStatus.NOT_RUN]


class ContainerReleaseManifest(VersionedContract):
    """Audit record emitted by the protected container publication workflow."""

    worker: ContainerReleaseWorker
    source: ContainerReleaseSource
    container: ContainerReleaseImage
    model: ContainerReleaseModel
    vulnerability: VulnerabilitySummary
    supply_chain: ContainerReleaseSupplyChain
    verification: ContainerReleaseVerification

    @model_validator(mode="after")
    def validate_cross_component_identity_and_safety(self) -> Self:
        expected_tag = f"sha-{self.source.git_commit}"
        if self.container.tag != expected_tag:
            raise ValueError("container tag must contain the complete source commit")
        labels = self.container.oci_labels
        if labels["org.opencontainers.image.revision"] != self.source.git_commit:
            raise ValueError("OCI revision must match the source commit")
        if labels["org.opencontainers.image.version"] != expected_tag:
            raise ValueError("OCI version must match the immutable source tag")
        if str(self.source.repository_url).rstrip("/") != labels[
            "org.opencontainers.image.source"
        ].rstrip("/"):
            raise ValueError("OCI source must match the source repository URL")
        if self.verification.github_attestation == ReleaseCheckStatus.PASSED and not (
            self.supply_chain.github_attestation_created
            and self.supply_chain.github_attestation_verified
        ):
            raise ValueError("passed GitHub attestation requires creation and verification")
        if self.verification.vulnerability_scan != self.vulnerability.status:
            raise ValueError("vulnerability summary and verification status must agree")
        if self.vulnerability.status == ReleaseCheckStatus.PASSED and (
            self.vulnerability.critical != self.vulnerability.excepted_critical
        ):
            raise ValueError(
                "passed vulnerability scan cannot contain unexcepted critical findings"
            )
        if (self.verification.sbom == ReleaseCheckStatus.PASSED) != (
            self.supply_chain.sbom_attached
        ):
            raise ValueError("SBOM verification status must match attachment state")
        if (self.verification.provenance == ReleaseCheckStatus.PASSED) != (
            self.supply_chain.provenance_attached
        ):
            raise ValueError("provenance verification status must match attachment state")
        serialized = json.dumps(self.model_dump(mode="json"), sort_keys=True)
        unsafe_patterns = (
            r"/Users/",
            r"/home/",
            r"[A-Za-z]:\\Users\\",
            r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
            r"X-Amz-Signature",
            r"RUNPOD_API_KEY",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        )
        if any(re.search(pattern, serialized, re.IGNORECASE) for pattern in unsafe_patterns):
            raise ValueError("release manifest contains a secret or private developer path")
        return self
