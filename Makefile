export PYTHONPATH := $(CURDIR)/src

.PHONY: setup lint test test-all test-integration demo bench-smoke schemas verify-export workflow-demo
setup:
	uv sync --frozen --no-editable
lint:
	uv run --frozen --no-editable ruff format --check src tests scripts
	uv run --frozen --no-editable ruff check src tests scripts
	uv run --frozen --no-editable mypy
test:
	uv run --frozen --no-editable pytest -m 'not postgres'
test-all:
	uv run --frozen --no-editable --all-extras pytest -m 'not postgres'
test-integration:
	uv run --frozen --no-editable python scripts/run_postgres_tests.py
demo:
	uv run --frozen --no-editable python scripts/demo.py
bench-smoke:
	uv run --frozen --no-editable verisoc evaluate --config config/eval-smoke.yaml --provider mock --out artifacts/runs
schemas:
	uv run --frozen --no-editable python scripts/export_schemas.py
verify-export:
	uv run --frozen --no-editable python scripts/verify_public_export.py

RUN_STAMP := $(shell date -u +%Y%m%dT%H%M%S)
WORKFLOW_DIR ?= artifacts/runs/workflow-$(RUN_STAMP)
workflow-demo:
	uv run --frozen --no-editable python scripts/prepare_v05_custody_demo.py --with-context --out $(WORKFLOW_DIR)/intake
	uv run --frozen --no-editable python scripts/research_workflow.py start --manifest $(WORKFLOW_DIR)/intake/intake.json --contamination config/contamination-index.json --plan $(WORKFLOW_DIR)/intake/plan.json --reviewer-one unassigned-reviewer-A --reviewer-two unassigned-reviewer-B --out $(WORKFLOW_DIR)/prepared
	uv run --frozen --no-editable python scripts/research_workflow.py status --workflow $(WORKFLOW_DIR)/prepared
