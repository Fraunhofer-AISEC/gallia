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
from typing import Any

from gallia.pydantic_argparse.utils.pydantic import (
    PydanticField,
)


def parse_field(
    subparser: argparse._SubParsersAction,  # type: ignore
    field: PydanticField,
    extra_defaults: dict[type, dict[str, Any]] | None = None,
) -> None:
    """Adds command pydantic field to argument parser.

    Args:
        subparser (argparse._SubParsersAction): Sub-parser to add to.
        field (PydanticField): Field to be added to parser.
        extra_defaults: Defaults coming from external sources, such as environment variables or config files.
    """
    # Add Command
    subparser.add_parser(
        field.info.title or field.info.alias or field.name,
        help=field.info.description,
        model=field.model_type,
        exit_on_error=False,  # Allow top level parser to handle exiting
        extra_defaults=extra_defaults,
    )
