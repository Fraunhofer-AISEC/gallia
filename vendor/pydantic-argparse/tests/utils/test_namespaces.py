"""Tests the `namespaces` Module.

This module provides full unit test coverage for the `namespaces` module,
testing all branches of all functions.
"""


# Standard
import argparse

# Local
from pydantic_argparse import utils


def test_namespace_to_dict() -> None:
    """Tests `utils.namespaces.to_dict` Function."""
    # Generate Dictionary
    result = utils.namespaces.to_dict(
        argparse.Namespace(
            a="1",
            b=2,
            c=argparse.Namespace(
                d="3",
                e=4,
                f=argparse.Namespace(
                    g=5,
                    h="6",
                    i=7,
                )
            )
        )
    )

    # Assert
    assert result == {
        "a": "1",
        "b": 2,
        "c": {
            "d": "3",
            "e": 4,
            "f": {
                "g": 5,
                "h": "6",
                "i": 7,
            }
        }
    }
