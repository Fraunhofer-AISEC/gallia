.PHONY: lint
lint:
	flake8 --config setup.cfg src/gallia
	mypy --config-file pyproject.toml src/gallia
	pylint --rcfile pyproject.toml src/gallia
	shellcheck ./bin/penrun

BINDIR ?= "${HOME}/bin"

.PHONY: install
install:
	pip install .
	if [ ! -d "$(BINDIR)" ]; then mkdir -p "$(BINDIR)";fi
	cp bin/* "$(BINDIR)"
	@echo "Don't forget to add '$(BINDIR)' to your PATH"

.PHONY: install-dev
install-dev:
	poetry install
	@echo "Don't forget to add '$(PWD)/bin' to your PATH"

export BUILDDIR ?= $(PWD)/bin

.PHONY: docs
docs:
	$(MAKE) -C docs html

man:
	$(MAKE) -C docs/man man

.PHONY: test
test: pytest

.PHONY: pytest
pytest:
	python -m pytest --asyncio-mode=auto -v tests/python -W error::UserWarning

.PHONY: clean
clean:
	$(MAKE) -C docs clean
	$(MAKE) -C docs/man clean
