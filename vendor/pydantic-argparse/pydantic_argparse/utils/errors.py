# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Errors Utility Functions for Declarative Typed Argument Parsing.

The `errors` module contains a utility function used for formatting `pydantic`
Validation Errors to human readable messages.
"""


# Third-Party
# Typing

import pydantic

# Constants
PydanticError = pydantic.ValidationError


def format(error: PydanticError) -> str:  # noqa: A001
    """Formats a `pydantic` error into a human readable format.

    Args:
        error (PydanticError): `pydantic` error to be formatted.

    Returns:
        str: `pydantic` error in a human readable format.
    """
    # Format and Return
    return str(error)
