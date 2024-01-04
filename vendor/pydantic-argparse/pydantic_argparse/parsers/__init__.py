# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Pydantic Fields to Command-Line Arguments.

This package contains the functions required for parsing `pydantic` model
fields to `ArgumentParser` command-line arguments.

The public interface exposed by this package is the `parsing` modules, which
each contain the `should_parse()` and `parse_field()` functions.
"""

from typing import Optional

from pydantic_argparse.utils.pydantic import PydanticField, PydanticValidator

from . import (
    boolean,
    command,
    container,
    enum,
    literal,
    mapping,
    standard,
)
from .utils import SupportsAddArgument


def add_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> Optional[PydanticValidator]:
    """Parses pydantic field type, and then adds it to argument parser.

    Args:
        parser (argparse.ArgumentParser | argparse._ArgumentGroup): Sub-parser to add to.
        field (pydantic.fields.ModelField): Field to be added to parser.

    Returns:
        Optional[utils.pydantic.PydanticValidator]: Possible validator method.
    """
    # Switch on Field Type -- for fields that are pydantic models
    # this gets handled at the top level to distinguish
    # subcommands from arg groups
    if boolean.should_parse(field):
        return boolean.parse_field(parser, field)

    if container.should_parse(field):
        return container.parse_field(parser, field)

    if mapping.should_parse(field):
        return mapping.parse_field(parser, field)

    if literal.should_parse(field):
        return literal.parse_field(parser, field)

    if enum.should_parse(field):
        return enum.parse_field(parser, field)

    return standard.parse_field(parser, field)
