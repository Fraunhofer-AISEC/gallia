# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Declarative Typed Argument Parsing with Pydantic Models.

This is the `pydantic-argparse` package, which contains the classes, methods
and functions required for declarative and typed argument parsing with
`pydantic` models.

The public interface exposed by this package is the declarative and typed
`ArgumentParser` class, as well as the package "dunder" metadata.
"""

# Local
from pydantic import BaseModel, ConfigDict

from gallia.pydantic_argparse.argparse import ArgumentParser


class BaseArgument(BaseModel):
    """Base pydantic model for argument groups."""

    model_config = ConfigDict(json_schema_extra={"subcommand": False})


class BaseCommand(BaseModel):
    """Base pydantic model for command groups.

    This class is only a convenience base class that sets the
    `model_config` parameter to have the `json_schema_extra` parameter to
    have `subcommand=True`.
    """

    model_config = ConfigDict(json_schema_extra={"subcommand": True}, defer_build=True)


# Public Re-Exports
__all__ = (
    "ArgumentParser",
    "BaseArgument",
    "BaseCommand",
)
