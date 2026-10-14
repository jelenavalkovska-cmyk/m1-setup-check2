.PHONY: verify-setup test lint-contract install run

verify-setup:
	@python --version
	@python -c "import fastapi, pydantic, httpx, pytest, schemathesis; assert pydantic.VERSION.startswith('2'), 'Pydantic v2 required'; print('packages OK')"
	@claude --version
	@test -s setup/claude-answer.md || (echo 'MISSING: setup/claude-answer.md (A0 step 6)'; exit 1)
	@pytest -q tests/test_smoke.py

test:
	pytest -q

lint-contract:
	python tools/lint_contract.py docs/openapi.yaml

install:
	pip install -r requirements.txt

run:
	uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
