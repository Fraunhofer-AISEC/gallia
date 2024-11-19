# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Mapping Pydantic Fields to Command-Line Arguments.

The `mapping` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses mapping `pydantic` model fields to `ArgumentParser`
command-line arguments.
"""

import argparse
import ast
import collections.abc
from typing import Optional

from pydantic_argparse import utils
from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from .utils import SupportsAddArgument


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `mapping`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `mapping`.
    """
    # Check and Return
    return field.is_a(collections.abc.Mapping)


def parse_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> Optional[PydanticValidator]:
    """Adds mapping pydantic field to argument parser.

    Args:
        parser (argparse.ArgumentParser): Argument parser to add to.
        field (PydanticField): Field to be added to parser.

    Returns:
        Optional[PydanticValidator]: Possible validator method.
    """
    # Add Mapping Field
    parser.add_argument(
        field.argname(),
        action=argparse._StoreAction,
        help=field.description(),
        dest=field.name,
        metavar=field.metavar(),
        required=field.info.is_required(),
    )

    # Construct and Return Validator
    # TODO: this doesn't seem safe?
    return utils.pydantic.as_validator(field, lambda v: ast.literal_eval(v))
