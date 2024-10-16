# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Types Utility Functions for Declarative Typed Argument Parsing.

The `types` module contains a utility function used for determining and
comparing the types of `pydantic fields.
"""

import sys
from typing import Iterable

# Version-Guarded
if sys.version_info < (3, 8):  # pragma: <3.8 cover
    pass
else:  # pragma: >=3.8 cover
    pass


def all_types(types: Iterable) -> bool:
    """Check if all inputs are `type`s and not instances.

    Args:
        types (Iterable): an interable of putative `type` objects

    Returns:
        bool: whether or not all inputs are `type`s
    """
    return all(isinstance(t, type) for t in types)
