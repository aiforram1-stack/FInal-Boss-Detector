PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
VENV_PIP := .venv/bin/pip
PROJECT_PYTHONPATH := .:packages/contracts/src:packages/evidence/src:packages/structural/src:apps/api/src:workers/image-community/src

.PHONY: setup schemas format lint typecheck test test-api test-structural test-tool-integration openapi db-upgrade api safety reconcile structural-check-tools structural-smoke report-smoke image-community-setup image-community-lint image-community-typecheck image-community-test image-community-mock image-community-manifest-check image-community-checkpoint-dry-run image-community-docker-lint image-community-gpu-test image-community-container-check image-community-container-build-mock image-community-container-smoke image-community-container-policy image-community-container-scan image-community-release-manifest-check image-community-attestation-verify phase6-check

setup:
	test -x $(VENV_PYTHON) || $(PYTHON) -m uv venv --python 3.11 .venv
	$(PYTHON) -m uv pip install --python $(VENV_PYTHON) -e '.[dev]'

schemas:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) scripts/generate_schemas.py

format:
	.venv/bin/ruff check --fix .
	.venv/bin/ruff format .

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .

typecheck:
	.venv/bin/mypy packages apps scripts workers/image-community/src workers/image-community/scripts

test:
	$(VENV_PYTHON) -m pytest

test-api:
	$(VENV_PYTHON) -m pytest packages/evidence/tests apps/api/tests

test-structural:
	$(VENV_PYTHON) -m pytest packages/contracts/tests/test_structural_models.py packages/structural/tests apps/api/tests/test_structural_api.py apps/api/tests/test_structural_failures.py

test-tool-integration:
	$(VENV_PYTHON) -m pytest -m tool_integration packages/structural/tests

openapi:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) scripts/validate_openapi.py

db-upgrade:
	PYTHONPATH=$(PROJECT_PYTHONPATH) .venv/bin/alembic upgrade head

api:
	PYTHONPATH=$(PROJECT_PYTHONPATH) .venv/bin/uvicorn forensic_api.main:create_app --factory --reload

reconcile:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -m forensic_api.reconcile

safety:
	$(VENV_PYTHON) scripts/check_repository_safety.py

structural-check-tools:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) scripts/check_structural_tools.py

structural-smoke:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) scripts/structural_smoke.py

report-smoke:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) scripts/report_smoke.py

image-community-setup:
	$(PYTHON) -m uv sync --frozen --extra dev

image-community-lint:
	.venv/bin/ruff check workers/image-community scripts/validate_image_worker_docker.py
	.venv/bin/ruff format --check workers/image-community scripts/validate_image_worker_docker.py

image-community-typecheck:
	PYTHONPATH=$(PROJECT_PYTHONPATH) .venv/bin/mypy workers/image-community/src workers/image-community/scripts scripts/validate_image_worker_docker.py

image-community-test:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -m pytest workers/image-community/tests -m "not gpu and not integration"

image-community-mock:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) workers/image-community/handler.py --input workers/image-community/tests/fixtures/job-valid.json

image-community-manifest-check:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) workers/image-community/scripts/verify_model_manifest.py

image-community-checkpoint-dry-run:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) workers/image-community/scripts/fetch_checkpoint.py --dry-run

image-community-docker-lint:
	$(VENV_PYTHON) scripts/validate_image_worker_docker.py

image-community-gpu-test:
	test "$${RUN_GPU_TESTS:-0}" = "1"
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -m pytest workers/image-community/tests -m "gpu and integration"

image-community-container-policy:
	$(VENV_PYTHON) scripts/validate_workflow_policy.py
	$(VENV_PYTHON) scripts/validate_image_worker_docker.py
	$(VENV_PYTHON) scripts/evaluate_vulnerabilities.py --exceptions security/vulnerability-exceptions.yaml --summary /dev/null --validate-exceptions-only

image-community-release-manifest-check:
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -c 'from pathlib import Path; from forensic_contracts import ContainerReleaseManifest; ContainerReleaseManifest.model_validate_json(Path("docs/examples/example-container-release.json").read_text())'
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -c 'from pathlib import Path; from scripts.generate_schemas import generate_schema_documents; root = Path("schemas"); assert all((root / name).read_text() == body for name, body in generate_schema_documents().items())'

image-community-container-check: image-community-container-policy image-community-release-manifest-check image-community-manifest-check image-community-checkpoint-dry-run
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -m pytest packages/contracts/tests workers/image-community/tests -m "not gpu and not integration"

image-community-container-build-mock:
	test -n "$${IMAGE:-}"
	docker buildx build --platform linux/amd64 --target mock-test --load --tag "$${IMAGE}" --file workers/image-community/Dockerfile .

image-community-container-smoke:
	test -n "$${IMAGE:-}"
	docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --tmpfs /work/tmp:rw,noexec,nosuid,size=64m,mode=1777 --entrypoint python --env IMAGE_COMMUNITY_ENVIRONMENT=test --env IMAGE_COMMUNITY_BACKEND=mock --env IMAGE_COMMUNITY_ALLOW_MODEL_DOWNLOAD=false --env IMAGE_COMMUNITY_REQUIRE_CUDA=false --env IMAGE_COMMUNITY_TEMP_ROOT=/work/tmp --env TMPDIR=/work/tmp "$${IMAGE}" /app/workers/image-community/scripts/container_smoke.py

image-community-container-scan:
	test -n "$${IMAGE:-}"
	trivy image --scanners vuln,secret --severity CRITICAL --exit-code 1 "$${IMAGE}"

image-community-attestation-verify:
	test -n "$${IMAGE_DIGEST_REFERENCE:-}"
	test -n "$${GITHUB_REPOSITORY:-}"
	gh attestation verify "oci://$${IMAGE_DIGEST_REFERENCE}" --repo "$${GITHUB_REPOSITORY}"

phase6-check: image-community-container-check
	PYTHONPATH=$(PROJECT_PYTHONPATH) $(VENV_PYTHON) -m pytest \
		workers/image-community/tests/test_phase6_cache_resolver.py \
		workers/image-community/tests/test_phase6_contracts.py \
		workers/image-community/tests/test_phase6_control.py \
		workers/image-community/tests/test_phase6_validation.py
