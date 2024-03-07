# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Literal Pydantic Fields to Command-Line Arguments.

The `literal` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses literal `pydantic` model fields to `ArgumentParser`
command-line arguments.
"""

import argparse
import sys
from typing import Optional

from pydantic_argparse import utils
from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from .utils import SupportsAddArgument

if sys.version_info < (3, 8):  # pragma: <3.8 cover
    from typing_extensions import Literal, get_args
else:  # pragma: >=3.8 cover
    from typing import Literal, get_args


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `literal`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `literal`.
    """
    # Check and Return
    return field.is_a(Literal)


def parse_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> Optional[PydanticValidator]:
    """Adds enum pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.

    Returns:
        Optional[PydanticValidator]: Possible validator method.
    """
    # Extract Choices
    choices = get_args(field.info.annotation)

    # Determine Argument Properties
    metavar = f"{{{', '.join(str(c) for c in choices)}}}"
    action = argparse._StoreAction

    # Add Literal Field
    parser.add_argument(
        *field.arg_names(),
        action=action,
        help=field.description(),
        dest=field.name,
        metavar=metavar,
        required=field.arg_required(),
        **field.arg_default(),
        **field.arg_const()
    )

    # Construct String Representation Mapping of Choices
    # This allows us O(1) parsing of choices from strings
    mapping = {str(choice): choice for choice in choices}

    # Construct and Return Validator
    return utils.pydantic.as_validator(field, lambda v: mapping[v])
