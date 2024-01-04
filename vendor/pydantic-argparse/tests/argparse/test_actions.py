"""Tests the `actions` Module.

This module provides full unit test coverage for the `actions` module, testing
all branches of all methods. These unit tests target the `SubParsersAction`
class by testing the expected nested namespace functionality.
"""


# Standard
import argparse

# Third-Party
import pytest

# Local
from pydantic_argparse.argparse import actions
from tests import conftest as conf


def test_invalid_command() -> None:
    """Tests SubParsersAction with invalid command."""
    # Construct Subparser
    subparser = conf.create_test_subparser()

    # Assert Raises
    with pytest.raises(argparse.ArgumentError):
        # Test Invalid Command
        subparser(
            parser=argparse.ArgumentParser(),
            namespace=argparse.Namespace(),
            values=["fake", "--not-real"],
        )


def test_valid_command() -> None:
    """Tests SubParsersAction with valid command."""
    # Construct Subparser
    subparser = conf.create_test_subparser()

    # Add Test Argument
    subparser.add_parser("test")

    # Create Namespace
    namespace = argparse.Namespace()

    # Test Valid Command
    subparser(
        parser=argparse.ArgumentParser(),
        namespace=namespace,
        values=["test"],
    )

    # Assert
    assert getattr(namespace, "test") == argparse.Namespace()  # noqa: B009


def test_unrecognised_args() -> None:
    """Tests SubParsersAction with unrecognised args."""
    # Construct Subparser
    subparser = conf.create_test_subparser()

    # Add Test Argument
    subparser.add_parser("test")

    # Create Namespace
    namespace = argparse.Namespace()

    # Test Unrecognised Args
    subparser(
        parser=argparse.ArgumentParser(),
        namespace=namespace,
        values=["test", "--flag"],
    )

    # Assert
    assert getattr(namespace, "test") == argparse.Namespace()  # noqa: B009
    assert getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR) == ["--flag"]


def test_deep_unrecognised_args() -> None:
    """Tests SubParsersAction with deeply nested unrecognised args."""
    # Construct Subparser
    subparser = conf.create_test_subparser()

    # Add Test Argument
    deep: argparse.ArgumentParser = subparser.add_parser("test")
    deep.add_subparsers(action=actions.SubParsersAction).add_parser("deep")

    # Create Namespace
    namespace = argparse.Namespace()

    # Test Deeply Nested Unrecognised Args
    subparser(
        parser=argparse.ArgumentParser(),
        namespace=namespace,
        values=["test", "--a", "deep", "--b"],
    )

    # Assert
    assert getattr(namespace, "test") == argparse.Namespace(deep=argparse.Namespace())  # noqa: B009
    assert getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR) == ["--a", "--b"]
