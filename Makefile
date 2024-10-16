# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: default
default:
	@echo "available targets:"
	@echo ""
	@echo " fmt         run autoformatters"
	@echo " lint        run linters"
	@echo " docs        build docs"
	@echo " tests       run testsuite"
	@echo " pytest      run pytest tests"
	@echo " bats        run bats end to end tests"
	@echo " clean       delete build artifacts"

.PHONY: lint
lint:
	uv run mypy src tests
	uv run ruff check src tests
	uv run ruff format --check src tests
	find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shellcheck
	uv run reuse lint

.PHONY: lint-win32
lint-win32:
	uv run mypy --platform win32 --exclude "gallia\/log\.py" --exclude "hr" src tests
	uv run ruff check src tests

.PHONY: fmt
fmt:
	uv run ruff check --fix-only src tests/pytest
	uv run ruff format src tests/pytest
	find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shfmt -w

.PHONY: docs
docs:
	uv run $(MAKE) -C docs html

.PHONY: tests
tests: pytest bats

.PHONY: pytest
pytest:
	uv run python -m pytest -v --cov=$(PWD) --cov-report html tests/pytest

.PHONY: bats
bats:
	uv run ./tests/bats/run_bats.sh

.PHONY: clean
clean:
	uv run $(MAKE) -C docs clean
