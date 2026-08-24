PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
VENV_PIP := .venv/bin/pip
PROJECT_PYTHONPATH := packages/contracts/src:packages/evidence/src:apps/api/src

.PHONY: setup schemas format lint typecheck test test-api openapi db-upgrade api safety reconcile

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
	.venv/bin/mypy packages apps scripts

test:
	$(VENV_PYTHON) -m pytest

test-api:
	$(VENV_PYTHON) -m pytest packages/evidence/tests apps/api/tests

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
