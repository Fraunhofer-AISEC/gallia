# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: default
default:
	@echo "available targets:"
	@echo ""
	@echo " zipapp		build a standalone python zipapp"
	@echo " lint		run linters"
	@echo " docs		build docs"
	@echo " test		run testsuite"
	@echo " clean		delete build artifacts"

.PHONY: zipapp
TEMPDIR = $(shell mktemp -d)
zipapp:
	poetry build -f wheel
	poetry run python -m pip install --target $(TEMPDIR) gallia dist/*.whl
	poetry run python -m zipapp -o gallia.pyz -c -p "/usr/bin/env python3" -m "gallia.cli:main" $(TEMPDIR)
	$(RM) -r $(TEMPDIR)

.PHONY: lint
lint:
	flake8 --config setup.cfg src tests
	mypy --config-file pyproject.toml src tests
	pylint --rcfile pyproject.toml src tests
	black --check src tests

.PHONY: docs
docs:
	$(MAKE) -C docs html

.PHONY: test
test:
	python -m pytest -v --cov=$(PWD) --cov-report html tests

.PHONY: clean
clean:
	$(RM) gallia.pyz
	$(MAKE) -C docs clean
