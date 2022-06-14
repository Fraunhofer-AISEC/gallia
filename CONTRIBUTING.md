# Contributing

Just create an [issue](https://docs.github.com/en/issues) or a [pull request](https://docs.github.com/en/pull-requests) on Github.

## Setup

Please see the documentation for a [development setup](https://fraunhofer-aisec.github.io/gallia/setup.html).

## Quality Assurance

Several linters and unit tests are used to catch programming errors and regressions.
The relevant tools and their versions are specified in the `pyproject.toml`.
[Github Actions](https://docs.github.com/en/actions) are configured to run against all merge requests.

To run these checks locally, use `make lint` and `make test`.

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for structured commit messages.
