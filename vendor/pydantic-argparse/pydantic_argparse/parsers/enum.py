# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Enum Pydantic Fields to Command-Line Arguments.

The `enum` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses enum `pydantic` model fields to `ArgumentParser`
command-line arguments.
"""

import argparse
import enum
from typing import Optional, Type, cast

from pydantic_argparse import utils
from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from .utils import SupportsAddArgument


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as an `enum`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as an `enum`.
    """
    # Check and Return
    return field.is_a(enum.Enum)


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
    # Extract Enum
    enum_type = cast(Type[enum.Enum], field.info.annotation)

    # Compute Argument Intrinsics
    is_flag = len(enum_type) == 1 and not field.info.is_required()
    is_inverted = is_flag and field.info.get_default() is not None

    # Determine Argument Properties
    metavar = f"{{{', '.join(e.name for e in enum_type)}}}"
    action = argparse._StoreConstAction if is_flag else argparse._StoreAction
    const = (
        {}
        if not is_flag
        else {"const": None}
        if is_inverted
        else {"const": list(enum_type)[0]}
    )

    # Add Enum Field
    parser.add_argument(
        field.argname(is_inverted),
        action=action,
        help=field.description(),
        dest=field.name,
        metavar=metavar,
        required=field.info.is_required(),
        **const,  # type: ignore[arg-type]
    )

    # Construct and Return Validator
    return utils.pydantic.as_validator(field, lambda v: enum_type[v])
