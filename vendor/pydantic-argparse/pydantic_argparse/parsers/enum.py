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
from typing import Optional, Type, cast, TypeVar

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


EnumType = TypeVar("EnumType", bound=enum.Enum)

def auto_enum(x: str, enum_type: type[EnumType]) -> EnumType:
    try:
        return enum_type[x]
    except KeyError:
        try:
            return enum_type(x)
        except ValueError:
            try:
                return enum_type(int(x, 0))
            except ValueError:
                pass

    raise ValueError(f"{x} is not a valid key or value for {enum_type}")


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

    # Determine Argument Properties
    metavar = f"{{{', '.join(f'{e.name}({e.value})' for e in enum_type)}}}"
    action = argparse._StoreAction

    # Add Enum Field
    parser.add_argument(
        *field.arg_names(),
        action=action,
        help=field.description(),
        metavar=metavar,
        **field.arg_required(),
        **field.arg_default(),
        **field.arg_const(),
        **field.arg_dest()
    )

    # Construct and Return Validator
    # TODO: Why does this have no effect?
    return utils.pydantic.as_validator(field, lambda v: auto_enum(v, enum_type))
