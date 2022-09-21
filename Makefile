# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

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
	$(MAKE) -C docs clean
