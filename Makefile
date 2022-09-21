# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

.PHONY: lint
lint:
	flake8 --config setup.cfg src tests
	mypy --config-file pyproject.toml src tests
	pylint --rcfile pyproject.toml src tests
	black --check src tests

BINDIR ?= "${HOME}/bin"

.PHONY: install
install:
	pip install .

.PHONY: install-dev
install-dev:
	poetry install

.PHONY: docs
docs:
	$(MAKE) -C docs html

.PHONY: test
test: pytest

.PHONY: pytest
pytest:
	python -m pytest -v --cov=$(PWD) --cov-report html tests/python

.PHONY: clean
clean:
	$(MAKE) -C docs clean
