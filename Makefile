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
	@echo " constants   generate transport constants for compat reasons"
	@echo " clean       delete build artifacts"

.PHONY: lint
lint:
	mypy --pretty src tests
	ruff check
	ruff format --check
	find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shellcheck
	reuse lint

.PHONY: lint-win32
lint-win32:
	mypy --platform win32 --exclude "gallia\/log\.py" --exclude "hr" src tests
	ruff check src tests

.PHONY: fmt
fmt:
	ruff check --fix-only
	ruff format
	find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shfmt -w

.PHONY: docs
docs:
	$(MAKE) -C docs html

.PHONY: tests
tests: pytest bats

.PHONY: pytest
pytest:
	python -m pytest -v --cov=$(PWD) --cov-report html tests/pytest

.PHONY: bats
bats:
	./tests/bats/run_bats.sh

.PHONY: constants
constants:
	./scripts/gen_constants.py | ruff format - > src/gallia/transports/_can_constants.py

.PHONY: clean
clean:
	$(MAKE) -C docs clean
