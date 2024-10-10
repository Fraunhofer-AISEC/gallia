# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Nested Pydantic Model Fields to Sub-Commands.

The `command` module contains the `should_parse` function, which checks whether
this module should be used to parse the field, as well as the `parse_field`
function, which parses nested `pydantic` model fields to `ArgumentParser`
sub-commands.
"""

import argparse
from typing import Optional, Type, Any

from pydantic_argparse.utils.pydantic import (
    PydanticField,
    PydanticValidator,
)


def should_parse(field: PydanticField) -> bool:
    """Checks whether the field should be parsed as a `command`.

    Args:
        field (PydanticField): Field to check.

    Returns:
        bool: Whether the field should be parsed as a `command`.
    """
    # Check and Return
    return field.is_subcommand()


def parse_field(
    subparser: argparse._SubParsersAction,
    field: PydanticField,
    extra_defaults: dict[Type, dict[str, Any]] | None = None,
) -> Optional[PydanticValidator]:
    """Adds command pydantic field to argument parser.

    Args:
        subparser (argparse._SubParsersAction): Sub-parser to add to.
        field (PydanticField): Field to be added to parser.

    Returns:
        Optional[PydanticValidator]: Possible validator method.
    """
    # Add Command
    subparser.add_parser(
        field.info.title or field.info.alias or field.name,
        help=field.info.description,
        model=field.model_type,  # type: ignore[call-arg]
        exit_on_error=False,  # Allow top level parser to handle exiting
        extra_defaults=extra_defaults,
    )

    # Return
    return None
