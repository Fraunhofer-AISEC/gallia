# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Container Pydantic Fields to Command-Line Arguments.

The `container` module contains the `should_parse` function, which checks
whether this module should be used to parse the field, as well as the
`parse_field` function, which parses container `pydantic` model fields to
`ArgumentParser` command-line arguments.
"""

import argparse
import collections.abc
import enum

from pydantic_argparse.utils.pydantic import PydanticField

from .utils import SupportsAddArgument


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `container`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `container`.
    """
    # Check and Return
    return field.is_a(collections.abc.Container) and not field.is_a((enum.Enum, str, bytes))


def parse_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> None:
    """Adds container pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.
    """
    parser.add_argument(
        *field.arg_names(),
        action=argparse._StoreAction,
        nargs=argparse.ONE_OR_MORE,
        help=field.description(),
        metavar=field.metavar(),
        **field.arg_required(),
        **field.arg_default(),
        **field.arg_const(),
        **field.arg_dest(),
    )

