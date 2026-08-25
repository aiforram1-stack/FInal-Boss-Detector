"""Pure Phase 6 RunPod queue controls with approval and budget gates.

This module performs no network access. The caller must inject a transport or
use the connected RunPod control plane after the exact proposal is approved.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from decimal import Decimal
from enum import StrEnum
from typing import Literal, Protocol, Self, cast
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from forensic_image_community.phase6_contracts import (
    CheckpointBootstrapRequest,
    CheckpointBootstrapResponse,
    GpuValidationRequest,
    GpuValidationResponse,
)

APPROVAL_PHRASE = "APPROVE PHASE 6 SERVERLESS COST"
SHA256_PATTERN = r"^[a-f0-9]{64}$"
COMMIT_PATTERN = r"^[a-f0-9]{40}$"
IMAGE_DIGEST_PATTERN = r"^ghcr\.io/[a-z0-9._-]+/[a-z0-9._-]+@sha256:[a-f0-9]{64}$"
MODEL_CACHE_ROOT: Literal["/runpod-volume/huggingface-cache/hub"] = (
    "/runpod-volume/huggingface-cache/hub"
)
TERMINAL_JOB_STATES = frozenset({"COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"})
SECRET_KEY_FRAGMENTS = (
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "password",
    "private_key",
    "registry_token",
    "secret",
    "token",
)
SECRET_VALUE_FRAGMENTS = ("bearer ", "ghp_", "github_pat_", "rpa_", "x-amz-signature=")
SCHEDULER_OBSERVED_DENIED_GPU_TYPE_IDS = frozenset(
    {"NVIDIA RTX PRO 6000 Blackwell Server Edition MIG 1g.24gb"}
)


class Phase6ControlRecord(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    schema_version: Literal["1.0"]


class EndpointRuntimeEnvironment(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    environment: Literal["production"] = "production"
    backend: Literal["community"] = "community"
    model_cache_root: Literal["/runpod-volume/huggingface-cache/hub"] = MODEL_CACHE_ROOT
    allow_model_download: Literal[False] = False
    checkpoint_bootstrap_mode: bool
    require_verified_checkpoint_hash: bool
    phase6_only_mode: Literal[True] = True
    require_cuda: Literal[True] = True
    container_digest: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    project_source_commit: str = Field(pattern=COMMIT_PATTERN)
    endpoint_release_identity: str = Field(min_length=1, max_length=255)
    hf_hub_offline: Literal["1"] = "1"
    transformers_offline: Literal["1"] = "1"
    validation_output_mode: Literal["inline_sanitized"] = "inline_sanitized"
    log_level: Literal["INFO"] = "INFO"

    @model_validator(mode="after")
    def validate_checkpoint_mode(self) -> Self:
        if self.checkpoint_bootstrap_mode == self.require_verified_checkpoint_hash:
            raise ValueError("bootstrap and verified-checkpoint modes must be exact opposites")
        return self

    def as_runpod_env(self) -> dict[str, str]:
        return {
            "IMAGE_COMMUNITY_ENVIRONMENT": self.environment,
            "IMAGE_COMMUNITY_BACKEND": self.backend,
            "IMAGE_COMMUNITY_MODEL_CACHE_ROOT": self.model_cache_root,
            "IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD": str(self.allow_model_download).lower(),
            "IMAGE_COMMUNITY_CHECKPOINT_BOOTSTRAP_MODE": str(
                self.checkpoint_bootstrap_mode
            ).lower(),
            "IMAGE_COMMUNITY_REQUIRE_VERIFIED_CHECKPOINT_HASH": str(
                self.require_verified_checkpoint_hash
            ).lower(),
            "IMAGE_COMMUNITY_PHASE6_ONLY_MODE": str(self.phase6_only_mode).lower(),
            "IMAGE_COMMUNITY_REQUIRE_CUDA": str(self.require_cuda).lower(),
            "IMAGE_COMMUNITY_CONTAINER_DIGEST": self.container_digest,
            "IMAGE_COMMUNITY_PROJECT_SOURCE_COMMIT": self.project_source_commit,
            "IMAGE_COMMUNITY_ENDPOINT_RELEASE_IDENTITY": self.endpoint_release_identity,
            "HF_HUB_OFFLINE": self.hf_hub_offline,
            "TRANSFORMERS_OFFLINE": self.transformers_offline,
            "IMAGE_COMMUNITY_VALIDATION_OUTPUT_MODE": self.validation_output_mode,
            "LOG_LEVEL": self.log_level,
        }


class EndpointProposal(Phase6ControlRecord):
    # This breaking scheduler-deny policy invalidates consumed 1.0 approvals.
    schema_version: Literal["1.1"]  # type: ignore[assignment]
    name: Literal["forensic-image-community-phase6"]
    endpoint_type: Literal["QUEUE"] = "QUEUE"
    image_digest_reference: str = Field(pattern=IMAGE_DIGEST_PATTERN)
    source_commit: str = Field(pattern=COMMIT_PATTERN)
    operation: Literal["checkpoint_bootstrap", "gpu_validation"]
    endpoint_release_identity: str = Field(min_length=1, max_length=255)
    registry_credential_id: str = Field(min_length=1, max_length=255)
    runtime_environment: EndpointRuntimeEnvironment
    gpu_pool_ids: tuple[Literal["AMPERE_24"]] = ("AMPERE_24",)
    observed_gpu_type_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    approved_gpu_type_ids: tuple[str, ...] = Field(min_length=1, max_length=3)
    excluded_gpu_type_ids: tuple[str, ...] = Field(max_length=20)
    gpu_count: Literal[1] = 1
    min_cuda_version: Literal["12.4"] = "12.4"
    workers_min: Literal[0] = 0
    workers_max: Literal[0, 1] = 1
    idle_timeout_seconds: Literal[5] = 5
    scaler_type: Literal["QUEUE_DELAY"] = "QUEUE_DELAY"
    scaler_value: Literal[4] = 4
    execution_timeout_ms: Literal[600_000] = 600_000
    flashboot: Literal["FLASHBOOT"] = "FLASHBOOT"
    disk_gb: int = Field(gt=0, le=100)
    model_repository: Literal["OwensLab/commfor-model-384"]
    model_revision: Literal["6076002bf0d9dd37537f965ee2f06f826c333b61"]
    runpod_model_reference: Literal[
        "https://huggingface.co/OwensLab/commfor-model-384:6076002bf0d9dd37537f965ee2f06f826c333b61"
    ]
    model_cache_root: Literal["/runpod-volume/huggingface-cache/hub"] = (
        "/runpod-volume/huggingface-cache/hub"
    )
    network_volume_ids: tuple[()] = ()
    data_center_ids: tuple[()] = ()

    @field_validator(
        "observed_gpu_type_ids",
        "approved_gpu_type_ids",
        "excluded_gpu_type_ids",
    )
    @classmethod
    def require_unique_canonical_gpu_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("GPU type IDs must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("GPU type IDs must use canonical sorted order")
        return value

    @model_validator(mode="after")
    def validate_gpu_pool_partition(self) -> Self:
        approved_phase6_types = {
            "NVIDIA L4",
            "NVIDIA RTX A5000",
            "NVIDIA GeForce RTX 3090",
        }
        observed = set(self.observed_gpu_type_ids)
        approved = set(self.approved_gpu_type_ids)
        excluded = set(self.excluded_gpu_type_ids)
        if not approved <= approved_phase6_types:
            raise ValueError("Phase 6 permits only the approved 24 GB GPU pool")
        if approved & excluded:
            raise ValueError("approved and excluded GPU type IDs must be disjoint")
        if observed != approved | excluded:
            raise ValueError(
                "observed pool members must be completely partitioned into "
                "approved and excluded IDs"
            )
        if not SCHEDULER_OBSERVED_DENIED_GPU_TYPE_IDS <= excluded:
            raise ValueError(
                "scheduler-observed denied GPU type IDs must remain explicitly excluded"
            )
        return self

    @model_validator(mode="after")
    def validate_runtime_environment(self) -> Self:
        runtime = self.runtime_environment
        expected_digest = self.image_digest_reference.rsplit("@", maxsplit=1)[1]
        if runtime.container_digest != expected_digest:
            raise ValueError("runtime container digest must match the approved image")
        if runtime.project_source_commit != self.source_commit:
            raise ValueError("runtime source commit must match the approved image")
        if runtime.endpoint_release_identity != self.endpoint_release_identity:
            raise ValueError("runtime release identity must match the approved endpoint")
        expected_bootstrap = self.operation == "checkpoint_bootstrap"
        if runtime.checkpoint_bootstrap_mode is not expected_bootstrap:
            raise ValueError("runtime checkpoint mode must match the approved operation")
        return self

    def locked(self) -> Self:
        return self.model_copy(update={"workers_max": 0})

    def redacted_dict(self) -> dict[str, JsonValue]:
        payload = self.model_dump(mode="json")
        payload.pop("registry_credential_id")
        payload["private_registry_reference"] = "REDACTED"
        return payload

    def canonical_sha256(self) -> str:
        body = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(body).hexdigest()


class Phase6CostBudget(Phase6ControlRecord):
    # This breaking continuation budget invalidates every consumed four-job approval.
    schema_version: Literal["1.2"]  # type: ignore[assignment]
    starting_balance_usd: Decimal = Field(ge=0)
    incurred_phase6_spend_usd: Decimal = Field(ge=0)
    paid_jobs_already_submitted: Literal[3] = 3
    gpu_pool_id: Literal["AMPERE_24"] = "AMPERE_24"
    gpu_rate_per_hour_usd: Decimal = Field(gt=0)
    gpu_rate_per_second_usd: Decimal = Field(gt=0)
    expected_cold_start_seconds_per_job: int = Field(ge=0, le=1_200)
    worst_case_cold_start_seconds_per_job: int = Field(default=1_200, ge=0, le=1_800)
    expected_bootstrap_execution_seconds: int = Field(gt=0, le=600)
    expected_validation_execution_seconds: int = Field(gt=0, le=600)
    idle_seconds_per_job: Literal[5] = 5
    maximum_job_execution_seconds: Literal[600] = 600
    model_cache_download_billed_to_worker: Literal[False] = False
    estimated_container_disk_cost_usd: Decimal = Field(ge=0)
    planned_paid_jobs: Literal[2] = 2
    diagnostic_retries: Literal[0] = 0
    maximum_paid_jobs: Literal[5] = 5
    estimated_normal_cost_usd: Decimal = Field(ge=0)
    estimated_worst_case_cost_usd: Decimal = Field(ge=0)
    hard_maximum_spend_usd: Decimal = Field(default=Decimal("2.00"), gt=0, le=Decimal("2.00"))

    @model_validator(mode="after")
    def validate_budget(self) -> Self:
        derived_rate = self.gpu_rate_per_hour_usd / Decimal(3600)
        if abs(derived_rate - self.gpu_rate_per_second_usd) > Decimal("0.000000001"):
            raise ValueError("hourly and per-second GPU rates are inconsistent")
        if (
            self.paid_jobs_already_submitted + self.planned_paid_jobs + self.diagnostic_retries
            != self.maximum_paid_jobs
        ):
            raise ValueError(
                "consumed and planned jobs must exactly fill the authorized Phase 6 cap"
            )
        if self.worst_case_cold_start_seconds_per_job < self.expected_cold_start_seconds_per_job:
            raise ValueError("worst-case cold start cannot be shorter than expected")
        normal_billable_seconds = Decimal(
            self.expected_cold_start_seconds_per_job * self.planned_paid_jobs
            + self.expected_bootstrap_execution_seconds
            + self.expected_validation_execution_seconds
            + self.idle_seconds_per_job * self.planned_paid_jobs
        )
        minimum_normal_cost = (
            normal_billable_seconds * self.gpu_rate_per_second_usd
            + self.estimated_container_disk_cost_usd
            + self.incurred_phase6_spend_usd
        )
        if self.estimated_normal_cost_usd < minimum_normal_cost:
            raise ValueError("normal estimate understates the configured billable duration")
        remaining_paid_job_slots = self.maximum_paid_jobs - self.paid_jobs_already_submitted
        worst_billable_seconds = Decimal(
            remaining_paid_job_slots
            * (
                self.worst_case_cold_start_seconds_per_job
                + self.maximum_job_execution_seconds
                + self.idle_seconds_per_job
            )
        )
        minimum_worst_case_cost = (
            worst_billable_seconds * self.gpu_rate_per_second_usd
            + self.estimated_container_disk_cost_usd
            + self.incurred_phase6_spend_usd
        )
        if self.estimated_worst_case_cost_usd < minimum_worst_case_cost:
            raise ValueError("worst-case estimate understates the configured billable cap")
        if self.estimated_normal_cost_usd > self.estimated_worst_case_cost_usd:
            raise ValueError("normal estimate cannot exceed the worst-case estimate")
        if self.estimated_worst_case_cost_usd > self.hard_maximum_spend_usd:
            raise ValueError("estimated worst-case cost exceeds the Phase 6 cap")
        future_worst_case_cost = self.estimated_worst_case_cost_usd - self.incurred_phase6_spend_usd
        if self.starting_balance_usd < future_worst_case_cost:
            raise ValueError("RunPod balance does not cover the worst-case estimate")
        return self


class CostApproval(Phase6ControlRecord):
    exact_phrase: Literal["APPROVE PHASE 6 SERVERLESS COST"]
    endpoint_proposal_sha256: str = Field(pattern=SHA256_PATTERN)
    cost_budget_sha256: str = Field(pattern=SHA256_PATTERN)

    def authorizes(self, proposal: EndpointProposal, budget: Phase6CostBudget) -> bool:
        return self.endpoint_proposal_sha256 == proposal.canonical_sha256() and (
            self.cost_budget_sha256 == canonical_record_sha256(budget)
        )


class QueueJobState(StrEnum):
    IN_QUEUE = "IN_QUEUE"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"


class QueueJobReceipt(BaseModel):
    model_config = ConfigDict(extra="allow", frozen=True, str_strip_whitespace=True)

    id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")
    status: QueueJobState


class QueueJobResult(QueueJobReceipt):
    delayTime: int | None = Field(default=None, ge=0)
    executionTime: int | None = Field(default=None, ge=0)
    output: JsonValue | None = None
    error: str | None = Field(default=None, max_length=2000)


class EndpointHealth(Phase6ControlRecord):
    workers_listed: int = Field(ge=0)
    workers_idle: int = Field(ge=0)
    workers_running: int = Field(ge=0)
    jobs_in_queue: int = Field(ge=0)
    jobs_in_progress: int = Field(ge=0)

    @property
    def quiescent(self) -> bool:
        return (
            self.workers_listed == 0
            and self.workers_idle == 0
            and self.workers_running == 0
            and self.jobs_in_queue == 0
            and self.jobs_in_progress == 0
        )


class EndpointWorkerAssignment(BaseModel):
    model_config = ConfigDict(
        extra="ignore",
        frozen=True,
        str_strip_whitespace=True,
        allow_inf_nan=False,
    )

    id: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")
    status: Literal["IDLE", "INITIALIZING", "RUNNING", "THROTTLED", "UNHEALTHY"]
    gpuTypeId: str = Field(min_length=1, max_length=255)
    gpuCount: int = Field(gt=0, le=8)
    image: str = Field(pattern=IMAGE_DIGEST_PATTERN)


class Phase6QueueTransport(Protocol):
    def submit(self, payload: dict[str, JsonValue]) -> object: ...

    def status(self, job_id: str) -> object: ...

    def cancel(self, job_id: str) -> object: ...

    def retry(self, job_id: str) -> object: ...

    def purge_queue(self) -> object: ...

    def health(self) -> object: ...

    def listed_worker_count(self) -> int: ...


class ClientDeadlineExceeded(RuntimeError):
    def __init__(self, job_id: str) -> None:
        super().__init__("Phase 6 queue job exceeded the client deadline and was cancelled")
        self.job_id = job_id


def canonical_record_sha256(record: BaseModel) -> str:
    body = json.dumps(
        record.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def build_async_job_payload(
    request: CheckpointBootstrapRequest | GpuValidationRequest,
) -> dict[str, JsonValue]:
    return {
        "input": request.model_dump(mode="json"),
        "policy": {"executionTimeout": 600_000, "ttl": 1_800_000},
    }


def parse_endpoint_health(payload: object, *, listed_worker_count: int) -> EndpointHealth:
    if not isinstance(payload, dict):
        raise ValueError("RunPod health response must be an object")
    if listed_worker_count < 0:
        raise ValueError("RunPod listed worker count cannot be negative")
    workers = payload.get("workers")
    jobs = payload.get("jobs")
    if not isinstance(workers, dict) or not isinstance(jobs, dict):
        raise ValueError("RunPod health response lacks worker or job counts")
    return EndpointHealth(
        schema_version="1.0",
        workers_listed=listed_worker_count,
        workers_idle=workers.get("idle"),
        workers_running=workers.get("running"),
        jobs_in_queue=jobs.get("inQueue"),
        jobs_in_progress=jobs.get("inProgress"),
    )


def assert_final_endpoint_lock(proposal: EndpointProposal, health: EndpointHealth) -> None:
    if proposal.workers_min != 0 or proposal.workers_max != 0:
        raise ValueError("Phase 6 final endpoint worker limits are not locked at zero")
    if not health.quiescent:
        raise ValueError("Phase 6 endpoint is not quiescent")


def validate_endpoint_worker_assignments(
    proposal: EndpointProposal, payload: object
) -> tuple[EndpointWorkerAssignment, ...]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("RunPod worker-list response must contain an items array")
    assignments = tuple(EndpointWorkerAssignment.model_validate(item) for item in payload["items"])
    if len(assignments) > proposal.workers_max:
        raise ValueError("RunPod worker count exceeds the approved endpoint ceiling")
    for assignment in assignments:
        if assignment.gpuTypeId not in proposal.approved_gpu_type_ids:
            raise ValueError("RunPod assigned a GPU type outside the approved allowlist")
        if assignment.gpuCount != proposal.gpu_count:
            raise ValueError("RunPod worker GPU count differs from the approved proposal")
        if assignment.image != proposal.image_digest_reference:
            raise ValueError("RunPod worker image differs from the approved immutable digest")
    return assignments


def assert_sanitized_result(value: JsonValue) -> None:
    def visit(item: JsonValue, path: str) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                lowered = key.lower()
                if any(fragment in lowered for fragment in SECRET_KEY_FRAGMENTS):
                    raise ValueError(f"secret-like field is prohibited at {path}.{key}")
                visit(child, f"{path}.{key}")
            return
        if isinstance(item, list):
            for index, child in enumerate(item):
                visit(child, f"{path}[{index}]")
            return
        if isinstance(item, str):
            lowered = item.lower()
            if any(fragment in lowered for fragment in SECRET_VALUE_FRAGMENTS):
                raise ValueError(f"secret-like value is prohibited at {path}")
            if item.startswith("/"):
                raise ValueError(f"internal absolute path is prohibited at {path}")
            parsed = urlsplit(item)
            if parsed.scheme.lower() in {"http", "https"} and parsed.query:
                raise ValueError(f"URL query strings are prohibited at {path}")

    visit(value, "$")


def validate_completed_output(
    output: JsonValue | None,
    *,
    expected_operation: Literal["checkpoint_bootstrap", "gpu_validation"],
) -> None:
    if output is None:
        raise ValueError("completed RunPod job omitted its output")
    assert_sanitized_result(output)
    if expected_operation == "checkpoint_bootstrap":
        CheckpointBootstrapResponse.model_validate(output)
        return
    GpuValidationResponse.model_validate(output)


class Phase6QueueController:
    def __init__(
        self,
        *,
        transport: Phase6QueueTransport,
        monotonic: Callable[[], float],
        wait: Callable[[float], None],
        poll_interval_seconds: float = 5.0,
    ) -> None:
        if poll_interval_seconds < 2 or poll_interval_seconds > 30:
            raise ValueError("poll interval must remain between 2 and 30 seconds")
        self.transport = transport
        self.monotonic = monotonic
        self.wait = wait
        self.poll_interval_seconds = poll_interval_seconds

    def submit_approved(
        self,
        *,
        request: CheckpointBootstrapRequest | GpuValidationRequest,
        proposal: EndpointProposal,
        budget: Phase6CostBudget,
        approval: CostApproval,
        paid_jobs_already_submitted: int,
    ) -> QueueJobReceipt:
        if not approval.authorizes(proposal, budget):
            raise PermissionError("cost approval does not match the exact endpoint proposal")
        if request.operation != proposal.operation:
            raise PermissionError("request operation does not match the approved proposal")
        if paid_jobs_already_submitted < budget.paid_jobs_already_submitted:
            raise PermissionError(
                "paid-job count is lower than the approved Phase 6 budget baseline"
            )
        if paid_jobs_already_submitted >= budget.maximum_paid_jobs:
            raise PermissionError("Phase 6 paid-job cap has been reached")
        receipt = QueueJobReceipt.model_validate(
            self.transport.submit(build_async_job_payload(request))
        )
        assert_sanitized_result(receipt.model_dump(mode="json"))
        return receipt

    def poll_until_terminal(
        self,
        job_id: str,
        *,
        deadline_seconds: float,
        expected_operation: Literal["checkpoint_bootstrap", "gpu_validation"],
    ) -> QueueJobResult:
        if deadline_seconds <= 0 or deadline_seconds > 1_800:
            raise ValueError("client deadline must be positive and no more than 30 minutes")
        deadline = self.monotonic() + deadline_seconds
        while True:
            result = QueueJobResult.model_validate(self.transport.status(job_id))
            if result.status.value in TERMINAL_JOB_STATES:
                assert_sanitized_result(result.model_dump(mode="json"))
                if result.status is QueueJobState.COMPLETED:
                    validate_completed_output(
                        result.output,
                        expected_operation=expected_operation,
                    )
                return result
            if self.monotonic() >= deadline:
                cancelled = QueueJobReceipt.model_validate(self.transport.cancel(job_id))
                if cancelled.status is not QueueJobState.CANCELLED:
                    raise RuntimeError("RunPod did not confirm cancellation at the client deadline")
                assert_sanitized_result(cancelled.model_dump(mode="json"))
                raise ClientDeadlineExceeded(job_id)
            self.wait(self.poll_interval_seconds)

    def retry_approved_transient_failure(
        self,
        *,
        previous: QueueJobResult,
        failure_reason: Literal[
            "CAPACITY_INTERRUPTION",
            "RUNPOD_CONTROL_PLANE_UNAVAILABLE",
            "WORKER_STARTUP_INTERRUPTED",
        ],
        proposal: EndpointProposal,
        budget: Phase6CostBudget,
        approval: CostApproval,
        paid_jobs_already_submitted: int,
        diagnostic_retries_already_submitted: int,
    ) -> QueueJobReceipt:
        del failure_reason
        if not approval.authorizes(proposal, budget):
            raise PermissionError("cost approval does not match the exact endpoint proposal")
        if previous.status not in {QueueJobState.FAILED, QueueJobState.TIMED_OUT}:
            raise ValueError("RunPod permits retry only for failed or timed-out jobs")
        del paid_jobs_already_submitted, diagnostic_retries_already_submitted
        raise PermissionError("the approved Phase 6 continuation budget permits no retries")

    def purge_pending_queue(self) -> JsonValue:
        payload = self.transport.purge_queue()
        validated = cast(
            JsonValue,
            json.loads(json.dumps(payload, ensure_ascii=True, allow_nan=False)),
        )
        assert_sanitized_result(validated)
        return validated

    def endpoint_health(self) -> EndpointHealth:
        return parse_endpoint_health(
            self.transport.health(),
            listed_worker_count=self.transport.listed_worker_count(),
        )
