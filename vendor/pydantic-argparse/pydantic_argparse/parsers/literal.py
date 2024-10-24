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

from pydantic_argparse.utils.pydantic import PydanticField

from .utils import SupportsAddArgument
from ..utils.field import ArgFieldInfo

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
) -> None:
    """Adds enum pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.
    """
    # Extract Choices
    choices = get_args(field.info.annotation)

    metavar = f"{{{', '.join(str(c) for c in choices)}}}"

    if isinstance(field.info, ArgFieldInfo) and field.info.metavar is not None:
        metavar = field.info.metavar

    action = argparse._StoreAction

    # Add Literal Field
    parser.add_argument(
        *field.arg_names(),
        action=action,
        help=field.description(),
        metavar=metavar,
        **field.arg_required(),
        **field.arg_default(),
        **field.arg_const(),
        **field.arg_dest(),
    )
