PYTHON ?= python3
VENV_PYTHON := .venv/bin/python
VENV_PIP := .venv/bin/pip
CONTRACTS_PYTHONPATH := packages/contracts/src

.PHONY: setup schemas lint typecheck test safety

setup:
	test -x $(VENV_PYTHON) || $(PYTHON) -m uv venv --python 3.11 .venv
	$(PYTHON) -m uv pip install --python $(VENV_PYTHON) -e '.[dev]'

schemas:
	PYTHONPATH=$(CONTRACTS_PYTHONPATH) $(VENV_PYTHON) scripts/generate_schemas.py

lint:
	.venv/bin/ruff check .
	.venv/bin/ruff format --check .

typecheck:
	.venv/bin/mypy packages/contracts scripts

test:
	$(VENV_PYTHON) -m pytest packages/contracts/tests

safety:
	$(VENV_PYTHON) scripts/check_repository_safety.py
