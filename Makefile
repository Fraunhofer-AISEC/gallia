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
	mypy --pretty src tests
	ruff check src tests
	ruff format --check src tests
	find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shellcheck
	reuse lint

.PHONY: lint-win32
lint-win32:
	mypy --platform win32 --exclude "gallia\/log\.py" --exclude "hr" src tests
	ruff check src tests

.PHONY: fmt
fmt:
	ruff check --fix-only src tests/pytest
	ruff format src tests/pytest
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

.PHONY: clean
clean:
	$(MAKE) -C docs clean
