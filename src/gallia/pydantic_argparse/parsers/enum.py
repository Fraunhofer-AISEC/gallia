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
from typing import Any

from gallia.pydantic_argparse.utils.field import ArgFieldInfo
from gallia.pydantic_argparse.utils.pydantic import PydanticField

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
) -> None:
    """Adds enum pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.
    """
    # Extract Enum
    types = field.get_type()
    assert types is not None

    if isinstance(types, tuple):
        enum_type = types[0]
    else:
        enum_type = types

    # Determine Argument Properties
    assert enum_type is not None
    metavar = enum_type.__name__

    if isinstance(field.info, ArgFieldInfo) and field.info.metavar is not None:
        metavar = field.info.metavar

    action = argparse._StoreAction

    args: dict[str, Any] = {}
    args.update(field.arg_required())
    args.update(field.arg_default())
    args.update(field.arg_const())
    args.update(field.arg_dest())

    # Add Enum Field
    parser.add_argument(
        *field.arg_names(), action=action, help=field.description(), metavar=metavar, **args
    )
