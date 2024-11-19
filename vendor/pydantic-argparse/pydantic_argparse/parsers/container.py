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
from typing import Optional

from pydantic_argparse import utils
from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from .utils import SupportsAddArgument


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `container`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `container`.
    """
    # Check and Return
    return field.is_a(collections.abc.Container) and not field.is_a(
        (collections.abc.Mapping, enum.Enum, str, bytes)
    )


def parse_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> Optional[PydanticValidator]:
    """Adds container pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.

    Returns:
        Optional[PydanticValidator]: Possible validator method.
    """
    parser.add_argument(
        field.argname(),
        action=argparse._StoreAction,
        nargs=argparse.ONE_OR_MORE,
        help=field.description(),
        dest=field.name,
        metavar=field.metavar(),
        required=field.info.is_required(),
    )

    # Construct and Return Validator
    # TODO: this is basically useless?
    return utils.pydantic.as_validator(field, lambda v: v)
