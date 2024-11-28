# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Namespaces Utility Functions for Declarative Typed Argument Parsing.

The `namespaces` module contains a utility function used for recursively
converting `argparse.Namespace`s to regular Python `dict`s.
"""

import argparse
from typing import Any


def to_dict(namespace: argparse.Namespace) -> dict[str, Any]:
    """Converts a nested namespace to a dictionary recursively.

    Args:
        namespace (argparse.Namespace): Namespace object to convert.

    Returns:
        Dict[str, Any]: Nested dictionary generated from namespace.
    """
    # Get Dictionary from Namespace Vars
    dictionary = dict(vars(namespace))

    # Loop Through Dictionary
    for key, value in dictionary.items():
        # Check for Namespace Objects
        if isinstance(value, argparse.Namespace):
            # Recurse
            dictionary[key] = to_dict(value)

    return dictionary
