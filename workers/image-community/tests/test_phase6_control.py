from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from forensic_image_community.phase6_contracts import (
    CheckpointBootstrapRequest,
    CheckpointBootstrapResponse,
    ReleaseIdentity,
    build_artifact_envelope,
)
from forensic_image_community.phase6_control import (
    APPROVAL_PHRASE,
    ClientDeadlineExceeded,
    CostApproval,
    EndpointHealth,
    EndpointProposal,
    Phase6CostBudget,
    Phase6QueueController,
    QueueJobResult,
    assert_final_endpoint_lock,
    assert_sanitized_result,
    build_async_job_payload,
    canonical_record_sha256,
    parse_endpoint_health,
    validate_endpoint_worker_assignments,
)
from pydantic import ValidationError


def proposal(**overrides: object) -> EndpointProposal:
    values: dict[str, object] = {
        "schema_version": "1.1",
        "name": "forensic-image-community-phase6",
        "image_digest_reference": f"ghcr.io/owner/worker@sha256:{'a' * 64}",
        "source_commit": "b" * 40,
        "operation": "checkpoint_bootstrap",
        "endpoint_release_identity": "phase6-bootstrap-test-release",
        "registry_credential_id": "stored-credential-id",
        "runtime_environment": {
            "checkpoint_bootstrap_mode": True,
            "require_verified_checkpoint_hash": False,
            "container_digest": f"sha256:{'a' * 64}",
            "project_source_commit": "b" * 40,
            "endpoint_release_identity": "phase6-bootstrap-test-release",
        },
        "gpu_pool_ids": ("AMPERE_24",),
        "observed_gpu_type_ids": (
            "NVIDIA GeForce RTX 3090",
            "NVIDIA L4",
            "NVIDIA RTX A5000",
            "NVIDIA RTX PRO 6000 Blackwell Server Edition MIG 1g.24gb",
        ),
        "approved_gpu_type_ids": (
            "NVIDIA GeForce RTX 3090",
            "NVIDIA L4",
            "NVIDIA RTX A5000",
        ),
        "excluded_gpu_type_ids": ("NVIDIA RTX PRO 6000 Blackwell Server Edition MIG 1g.24gb",),
        "disk_gb": 20,
        "model_repository": "OwensLab/commfor-model-384",
        "model_revision": "6076002bf0d9dd37537f965ee2f06f826c333b61",
        "runpod_model_reference": (
            "https://huggingface.co/OwensLab/commfor-model-384:"
            "6076002bf0d9dd37537f965ee2f06f826c333b61"
        ),
    }
    values.update(overrides)
    return EndpointProposal.model_validate(values)


def budget(**overrides: object) -> Phase6CostBudget:
    values: dict[str, object] = {
        "schema_version": "1.1",
        "starting_balance_usd": Decimal("10"),
        "incurred_phase6_spend_usd": Decimal("0.01"),
        "paid_jobs_already_submitted": 2,
        "gpu_rate_per_hour_usd": Decimal("0.72"),
        "gpu_rate_per_second_usd": Decimal("0.0002"),
        "expected_cold_start_seconds_per_job": 120,
        "worst_case_cold_start_seconds_per_job": 300,
        "expected_bootstrap_execution_seconds": 120,
        "expected_validation_execution_seconds": 180,
        "estimated_container_disk_cost_usd": Decimal("0.01"),
        "estimated_normal_cost_usd": Decimal("0.40"),
        "estimated_worst_case_cost_usd": Decimal("0.75"),
    }
    values.update(overrides)
    return Phase6CostBudget.model_validate(values)


def bootstrap_request() -> CheckpointBootstrapRequest:
    return CheckpointBootstrapRequest(
        schema_version="1.0",
        operation="checkpoint_bootstrap",
        detector_id="community-forensics-384",
        expected_model_repository="OwensLab/commfor-model-384",
        expected_model_revision="c" * 40,
        expected_checkpoint_filename="model.safetensors",
        fixture_id="phase6-generated-fixture",
    )


def bootstrap_output() -> dict[str, object]:
    identity = ReleaseIdentity(
        schema_version="1.0",
        project_source_commit="a" * 40,
        container_digest=f"sha256:{'b' * 64}",
        endpoint_release_identity="phase6-bootstrap-test-release",
        detector_id="community-forensics-384",
        upstream_repository_commit="c" * 40,
        model_repository="OwensLab/commfor-model-384",
        model_revision="d" * 40,
        checkpoint_sha256="e" * 64,
    )
    receipt = build_artifact_envelope(
        artifact_type="checkpoint_bootstrap_receipt",
        created_at=datetime(2026, 8, 24, 12, 0, tzinfo=UTC),
        identity=identity,
        fixture_sha256="f" * 64,
        runtime_versions={"python_version": "3.11"},
        status="OBSERVED_BOOTSTRAP_HASH",
        payload={
            "runpod_job_id": "job-1",
            "checkpoint_hash_status": "OBSERVED_BOOTSTRAP_HASH",
            "checkpoint_sha256": "e" * 64,
            "requested_model_revision": "d" * 40,
            "resolved_snapshot_revision": "d" * 40,
        },
    )
    return CheckpointBootstrapResponse(
        schema_version="1.0",
        receipt=receipt,
    ).model_dump(mode="json")


def test_endpoint_proposal_is_queue_only_digest_pinned_and_lockable() -> None:
    configured = proposal()
    assert configured.workers_min == 0
    assert configured.workers_max == 1
    assert configured.network_volume_ids == ()
    assert configured.gpu_pool_ids == ("AMPERE_24",)
    assert configured.flashboot == "FLASHBOOT"
    assert configured.runpod_model_reference.endswith(configured.model_revision)
    assert (
        configured.runtime_environment.as_runpod_env()["IMAGE_COMMUNITY_PHASE6_ONLY_MODE"] == "true"
    )
    assert configured.locked().workers_max == 0
    assert "stored-credential-id" not in str(configured.redacted_dict())
    with pytest.raises(ValidationError):
        proposal(
            observed_gpu_type_ids=("NVIDIA H100 80GB HBM3",),
            approved_gpu_type_ids=("NVIDIA H100 80GB HBM3",),
            excluded_gpu_type_ids=(),
        )
    with pytest.raises(ValidationError, match="completely partitioned"):
        proposal(excluded_gpu_type_ids=())
    with pytest.raises(ValidationError, match="scheduler-observed denied"):
        proposal(
            observed_gpu_type_ids=(
                "NVIDIA GeForce RTX 3090",
                "NVIDIA L4",
                "NVIDIA RTX A5000",
            ),
            approved_gpu_type_ids=(
                "NVIDIA GeForce RTX 3090",
                "NVIDIA L4",
                "NVIDIA RTX A5000",
            ),
            excluded_gpu_type_ids=(),
        )
    legacy_values = proposal().model_dump(mode="json")
    legacy_values["schema_version"] = "1.0"
    with pytest.raises(ValidationError):
        EndpointProposal.model_validate(legacy_values)
    with pytest.raises(ValidationError):
        proposal(
            runpod_model_reference=(f"https://huggingface.co/OwensLab/commfor-model-384:{'c' * 40}")
        )
    with pytest.raises(ValidationError, match="container digest"):
        proposal(
            runtime_environment={
                "checkpoint_bootstrap_mode": True,
                "require_verified_checkpoint_hash": False,
                "container_digest": f"sha256:{'f' * 64}",
                "project_source_commit": "b" * 40,
                "endpoint_release_identity": "phase6-bootstrap-test-release",
            }
        )
    with pytest.raises(ValidationError):
        proposal(image_digest_reference="ghcr.io/owner/worker:latest")


def test_cost_budget_rejects_more_than_two_dollars_or_insufficient_balance() -> None:
    configured = budget()
    assert configured.paid_jobs_already_submitted == 2
    assert configured.planned_paid_jobs == 2
    assert configured.diagnostic_retries == 0
    assert configured.maximum_paid_jobs == 4
    legacy_values = budget().model_dump(mode="json")
    legacy_values.pop("worst_case_cold_start_seconds_per_job")
    legacy_values["estimated_worst_case_cost_usd"] = "1.50"
    assert (
        Phase6CostBudget.model_validate(legacy_values).worst_case_cold_start_seconds_per_job
        == 1_200
    )
    with pytest.raises(ValidationError, match="exceeds the Phase 6 cap"):
        budget(estimated_worst_case_cost_usd=Decimal("2.01"))
    with pytest.raises(ValidationError, match="does not cover"):
        budget(starting_balance_usd=Decimal("0.50"))
    with pytest.raises(ValidationError, match="rates are inconsistent"):
        budget(gpu_rate_per_hour_usd=Decimal("0.69"))
    with pytest.raises(ValidationError, match="normal estimate understates"):
        budget(estimated_normal_cost_usd=Decimal("0.01"))
    with pytest.raises(ValidationError, match="normal estimate understates"):
        budget(
            incurred_phase6_spend_usd=Decimal("0.50"),
            estimated_normal_cost_usd=Decimal("0.40"),
        )
    with pytest.raises(ValidationError, match="cannot be shorter"):
        budget(worst_case_cold_start_seconds_per_job=119)
    with pytest.raises(ValidationError):
        budget(paid_jobs_already_submitted=1)
    with pytest.raises(ValidationError):
        budget(diagnostic_retries=1)
    with pytest.raises(ValidationError):
        budget(schema_version="1.0")


def test_async_payload_uses_run_policy_not_runsync() -> None:
    payload = build_async_job_payload(bootstrap_request())
    request_input = payload["input"]
    assert isinstance(request_input, dict)
    assert request_input["operation"] == "checkpoint_bootstrap"
    assert payload["policy"] == {"executionTimeout": 600_000, "ttl": 1_800_000}


def test_worker_assignments_require_approved_gpu_digest_count_and_ceiling() -> None:
    configured = proposal()
    approved_worker: dict[str, object] = {
        "id": "worker-1",
        "status": "INITIALIZING",
        "gpuTypeId": "NVIDIA RTX A5000",
        "gpuCount": 1,
        "image": configured.image_digest_reference,
        "futureProviderField": "preserved-by-provider-ignored-by-contract",
    }
    approved = {"items": [approved_worker]}
    assert validate_endpoint_worker_assignments(configured, approved)[0].gpuTypeId == (
        "NVIDIA RTX A5000"
    )
    denied = {
        "items": [
            {
                **approved_worker,
                "gpuTypeId": "NVIDIA RTX PRO 6000 Blackwell Server Edition MIG 1g.24gb",
            }
        ]
    }
    with pytest.raises(ValueError, match="outside the approved allowlist"):
        validate_endpoint_worker_assignments(configured, denied)
    with pytest.raises(ValueError, match="GPU count differs"):
        validate_endpoint_worker_assignments(
            configured,
            {"items": [{**approved_worker, "gpuCount": 2}]},
        )
    with pytest.raises(ValueError, match="immutable digest"):
        validate_endpoint_worker_assignments(
            configured,
            {
                "items": [
                    {
                        **approved_worker,
                        "image": f"ghcr.io/owner/worker@sha256:{'f' * 64}",
                    }
                ]
            },
        )
    with pytest.raises(ValueError, match="worker count exceeds"):
        validate_endpoint_worker_assignments(configured.locked(), approved)


class FakeTransport:
    def __init__(self, statuses: Iterator[object]) -> None:
        self.statuses = statuses
        self.submissions: list[object] = []
        self.cancelled: list[str] = []
        self.retried: list[str] = []
        self.purged = 0

    def submit(self, payload: object) -> object:
        self.submissions.append(payload)
        return {"id": "job-1", "status": "IN_QUEUE"}

    def status(self, job_id: str) -> object:
        assert job_id == "job-1"
        return next(self.statuses)

    def cancel(self, job_id: str) -> object:
        self.cancelled.append(job_id)
        return {"id": job_id, "status": "CANCELLED"}

    def retry(self, job_id: str) -> object:
        self.retried.append(job_id)
        return {"id": job_id, "status": "IN_QUEUE"}

    def purge_queue(self) -> object:
        self.purged += 1
        return {"removed": 0, "status": "completed"}

    def health(self) -> object:
        return {
            "workers": {"idle": 0, "running": 0},
            "jobs": {"inQueue": 0, "inProgress": 0},
        }

    def listed_worker_count(self) -> int:
        return 0


def approval(configured: EndpointProposal, limits: Phase6CostBudget) -> CostApproval:
    return CostApproval(
        schema_version="1.0",
        exact_phrase=APPROVAL_PHRASE,
        endpoint_proposal_sha256=configured.canonical_sha256(),
        cost_budget_sha256=canonical_record_sha256(limits),
    )


def test_submit_and_poll_parses_current_runpod_states() -> None:
    clock = iter((0.0, 0.0, 5.0, 5.0))
    transport = FakeTransport(
        iter(
            (
                {"id": "job-1", "status": "IN_QUEUE"},
                {"id": "job-1", "status": "IN_PROGRESS"},
                {
                    "id": "job-1",
                    "status": "COMPLETED",
                    "delayTime": 2,
                    "executionTime": 10,
                    "output": bootstrap_output(),
                },
            )
        )
    )
    configured = proposal()
    limits = budget()
    controller = Phase6QueueController(
        transport=transport,
        monotonic=lambda: next(clock),
        wait=lambda _: None,
    )
    receipt = controller.submit_approved(
        request=bootstrap_request(),
        proposal=configured,
        budget=limits,
        approval=approval(configured, limits),
        paid_jobs_already_submitted=2,
    )
    assert receipt.id == "job-1"
    result = controller.poll_until_terminal(
        "job-1",
        deadline_seconds=30,
        expected_operation="checkpoint_bootstrap",
    )
    assert result.status == "COMPLETED"
    assert result.executionTime == 10


def test_deadline_cancels_and_job_cap_or_wrong_approval_blocks_submission() -> None:
    ticks = iter((0.0, 0.0, 31.0))
    transport = FakeTransport(
        iter(
            (
                {"id": "job-1", "status": "IN_PROGRESS"},
                {"id": "job-1", "status": "IN_PROGRESS"},
            )
        )
    )
    configured = proposal()
    limits = budget()
    controller = Phase6QueueController(
        transport=transport,
        monotonic=lambda: next(ticks),
        wait=lambda _: None,
    )
    with pytest.raises(ClientDeadlineExceeded):
        controller.poll_until_terminal(
            "job-1",
            deadline_seconds=30,
            expected_operation="checkpoint_bootstrap",
        )
    assert transport.cancelled == ["job-1"]
    with pytest.raises(PermissionError, match="cap"):
        controller.submit_approved(
            request=bootstrap_request(),
            proposal=configured,
            budget=limits,
            approval=approval(configured, limits),
            paid_jobs_already_submitted=4,
        )
    changed = configured.model_copy(update={"disk_gb": 21})
    with pytest.raises(PermissionError, match="does not match"):
        controller.submit_approved(
            request=bootstrap_request(),
            proposal=changed,
            budget=limits,
            approval=approval(configured, limits),
            paid_jobs_already_submitted=2,
        )
    gpu_proposal = proposal(
        operation="gpu_validation",
        runtime_environment={
            "checkpoint_bootstrap_mode": False,
            "require_verified_checkpoint_hash": True,
            "container_digest": f"sha256:{'a' * 64}",
            "project_source_commit": "b" * 40,
            "endpoint_release_identity": "phase6-bootstrap-test-release",
        },
    )
    with pytest.raises(PermissionError, match="operation"):
        controller.submit_approved(
            request=bootstrap_request(),
            proposal=gpu_proposal,
            budget=limits,
            approval=approval(gpu_proposal, limits),
            paid_jobs_already_submitted=2,
        )

    with pytest.raises(PermissionError, match="lower than"):
        controller.submit_approved(
            request=bootstrap_request(),
            proposal=configured,
            budget=limits,
            approval=approval(configured, limits),
            paid_jobs_already_submitted=1,
        )

    fourth = controller.submit_approved(
        request=bootstrap_request(),
        proposal=configured,
        budget=limits,
        approval=approval(configured, limits),
        paid_jobs_already_submitted=3,
    )
    assert fourth.status == "IN_QUEUE"


def test_health_lock_and_result_sanitization_fail_closed() -> None:
    health = parse_endpoint_health(
        {
            "workers": {"idle": 0, "running": 0},
            "jobs": {"inQueue": 0, "inProgress": 0},
        },
        listed_worker_count=0,
    )
    assert health.quiescent
    assert_final_endpoint_lock(proposal().locked(), health)
    with pytest.raises(ValueError, match="not quiescent"):
        assert_final_endpoint_lock(
            proposal().locked(),
            EndpointHealth(
                schema_version="1.0",
                workers_listed=1,
                workers_idle=0,
                workers_running=1,
                jobs_in_queue=0,
                jobs_in_progress=1,
            ),
        )
    with pytest.raises(ValueError, match="secret-like"):
        assert_sanitized_result({"api_key": "rpa_not-for-logs"})
    with pytest.raises(ValueError, match="absolute path"):
        assert_sanitized_result({"cache_path": "/runpod-volume/private/model"})
    with pytest.raises(ValueError, match="query strings"):
        assert_sanitized_result({"download": "https://example.test/object?signature=value"})


def test_continuation_budget_forbids_retries_and_queue_cleanup_is_sanitized() -> None:
    transport = FakeTransport(iter(()))
    configured = proposal()
    limits = budget()
    controller = Phase6QueueController(
        transport=transport,
        monotonic=lambda: 0.0,
        wait=lambda _: None,
    )
    previous = QueueJobResult(id="job-1", status="TIMED_OUT")
    with pytest.raises(PermissionError, match="permits no retries"):
        controller.retry_approved_transient_failure(
            previous=previous,
            failure_reason="WORKER_STARTUP_INTERRUPTED",
            proposal=configured,
            budget=limits,
            approval=approval(configured, limits),
            paid_jobs_already_submitted=2,
            diagnostic_retries_already_submitted=0,
        )
    assert transport.retried == []
    assert controller.purge_pending_queue() == {"removed": 0, "status": "completed"}
    assert controller.endpoint_health().quiescent


def test_terminal_job_error_and_future_fields_are_scanned_for_secrets() -> None:
    transport = FakeTransport(
        iter(
            (
                {
                    "id": "job-1",
                    "status": "FAILED",
                    "error": "Authorization: Bearer prohibited-value",
                    "future": {"diagnostic": "sanitized"},
                },
            )
        )
    )
    controller = Phase6QueueController(
        transport=transport,
        monotonic=lambda: 0.0,
        wait=lambda _: None,
    )
    with pytest.raises(ValueError, match="secret-like"):
        controller.poll_until_terminal(
            "job-1",
            deadline_seconds=30,
            expected_operation="checkpoint_bootstrap",
        )


def test_completed_job_requires_the_expected_versioned_output_contract() -> None:
    transport = FakeTransport(
        iter(
            (
                {
                    "id": "job-1",
                    "status": "COMPLETED",
                    "output": {"schema_version": "1.0", "status": "PASSED"},
                },
            )
        )
    )
    controller = Phase6QueueController(
        transport=transport,
        monotonic=lambda: 0.0,
        wait=lambda _: None,
    )
    with pytest.raises(ValidationError):
        controller.poll_until_terminal(
            "job-1",
            deadline_seconds=30,
            expected_operation="checkpoint_bootstrap",
        )
