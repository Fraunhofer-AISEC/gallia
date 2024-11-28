# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Parses Pydantic Fields to Command-Line Arguments.

This package contains the functions required for parsing `pydantic` model
fields to `ArgumentParser` command-line arguments.

The public interface exposed by this package is the `parsing` modules, which
each contain the `should_parse()` and `parse_field()` functions.
"""

from gallia.pydantic_argparse.utils.pydantic import PydanticField

from . import (
    boolean,
    container,
    enum,
    literal,
    standard,
)
from .utils import SupportsAddArgument


def add_field(
    parser: SupportsAddArgument,
    field: PydanticField,
) -> None:
    """Parses pydantic field type, and then adds it to argument parser.

    Args:
        parser (argparse.ArgumentParser | argparse._ArgumentGroup): Sub-parser to add to.
        field (pydantic.fields.ModelField): Field to be added to parser.
    """
    # Switch on Field Type -- for fields that are pydantic models
    # this gets handled at the top level to distinguish
    # subcommands from arg groups
    if boolean.should_parse(field):
        boolean.parse_field(parser, field)
    elif container.should_parse(field):
        container.parse_field(parser, field)
    elif literal.should_parse(field):
        literal.parse_field(parser, field)
    elif enum.should_parse(field):
        enum.parse_field(parser, field)
    else:
        standard.parse_field(parser, field)
