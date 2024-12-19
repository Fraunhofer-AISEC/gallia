# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: CC0-1.0

default:
    @just --list

[private]
lint-mypy:
    mypy --pretty src tests

[private]
lint-ruff-check:
    ruff check

[private]
lint-ruff-format:
    ruff format --check

[private]
lint-shellcheck:
    find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shellcheck

[private]
lint-reuse:
    reuse lint

lint: lint-mypy lint-ruff-check lint-ruff-format lint-ruff-format lint-shellcheck lint-reuse

win32-lint-mypy:
    mypy --platform win32 --exclude "gallia\/log\.py" --exclude "hr" src tests

fmt:
    ruff check --fix-only
    ruff format
    find tests/bats \( -iname "*.bash" -or -iname "*.bats" -or -iname "*.sh" \) | xargs shfmt -w

run-tests: run-test-pytest run-test-bats

run-test-pytest:
    python -m pytest -v --cov={{justfile_directory()}} --cov-report html tests/pytest

run-test-bats:
    ./tests/bats/run_bats.sh

gen-constants: && fmt
    ./scripts/gen_constants.py > src/gallia/transports/_can_constants.py

release increment:
    cz bump --increment {{increment}}
    git push --follow-tags
    gh release create "v$(cz version -p)"

pre-release increment premode:
    cz bump --increment {{increment}} --prerelease {{premode}}
    git push --follow-tags
    gh release create --prerelease "v$(cz version -p)"

make-docs:
    make -C docs html

clean:
    make -C docs clean
