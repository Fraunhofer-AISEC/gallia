# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Boolean Pydantic Fields to Command-Line Arguments.

The `boolean` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses boolean `pydantic` model fields to `ArgumentParser`
command-line arguments.
"""

import argparse
from typing import Optional

from pydantic_argparse import utils
from pydantic_argparse.argparse import actions
from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from .utils import SupportsAddArgument


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `boolean`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `boolean`.
    """
    # Check and Return
    return field.is_a(bool)


def parse_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> Optional[PydanticValidator]:
    """Adds boolean pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.

    Returns:
        Optional[PydanticValidator]: Possible validator method.
    """
    # Compute Argument Intrinsics
    is_inverted = not field.info.is_required() and bool(field.info.get_default())

    # Determine Argument Properties
    action = (
        actions.BooleanOptionalAction
        if field.info.is_required()
        else argparse._StoreFalseAction
        if is_inverted
        else argparse._StoreTrueAction
    )

    # Add Boolean Field
    parser.add_argument(
        field.argname(is_inverted),
        action=action,
        help=field.description(),
        dest=field.name,
        required=field.info.is_required(),
    )

    # Construct and Return Validator
    return utils.pydantic.as_validator(field, lambda v: v)
