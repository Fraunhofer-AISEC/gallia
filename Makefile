.PHONY: lint
lint:
	flake8 --config setup.cfg src
	mypy --config-file pyproject.toml src
	pylint --rcfile pyproject.toml src
	shellcheck ./bin/penrun

BINDIR ?= "${HOME}/bin"

.PHONY: install
install:
	pip install .
	if [ ! -d "$(BINDIR)" ]; then mkdir -p "$(BINDIR)"; fi
	cp bin/* "$(BINDIR)"
	@echo "Don't forget to add '$(BINDIR)' to your PATH"

.PHONY: install-dev
install-dev:
	poetry install
	@echo "Don't forget to add '$(PWD)/bin' to your PATH"

.PHONY: docs
docs:
	$(MAKE) -C docs html

.PHONY: test
test: pytest

.PHONY: pytest
pytest:
	python -m pytest -v tests/python -W error::UserWarning

.PHONY: clean
clean:
	$(MAKE) -C docs clean
