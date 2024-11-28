# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Boolean Pydantic Fields to Command-Line Arguments.

The `boolean` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses boolean `pydantic` model fields to `ArgumentParser`
command-line arguments.
"""

from typing import Any

from gallia.pydantic_argparse.argparse import actions
from gallia.pydantic_argparse.utils.pydantic import PydanticField

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
) -> None:
    """Adds boolean pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.
    """
    # Determine Argument Properties
    action = actions.BooleanOptionalAction

    args: dict[str, Any] = {}
    args.update(field.arg_required())
    args.update(field.arg_default())
    args.update(field.arg_const())
    args.update(field.arg_dest())

    # Add Boolean Field
    parser.add_argument(*field.arg_names(), action=action, help=field.description(), **args)
