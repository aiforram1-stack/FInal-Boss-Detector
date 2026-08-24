PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
VENV_PIP := .venv/bin/pip
PROJECT_PYTHONPATH := .:packages/contracts/src:packages/evidence/src:packages/structural/src:apps/api/src:workers/image-community/src

.PHONY: setup schemas format lint typecheck test test-api test-structural test-tool-integration openapi db-upgrade api safety reconcile structural-check-tools structural-smoke report-smoke image-community-setup image-community-lint image-community-typecheck image-community-test image-community-mock image-community-manifest-check image-community-checkpoint-dry-run image-community-docker-lint image-community-gpu-test

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
