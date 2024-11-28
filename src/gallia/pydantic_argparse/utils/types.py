# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Types Utility Functions for Declarative Typed Argument Parsing.

The `types` module contains a utility function used for determining and
comparing the types of `pydantic fields.
"""

from collections.abc import Iterable
from typing import Any


def all_types(types: Iterable[Any]) -> bool:
    """Check if all inputs are `type`s and not instances.

    Args:
        types (Iterable): an interable of putative `type` objects

    Returns:
        bool: whether or not all inputs are `type`s
    """
    return all(isinstance(t, type) for t in types)
