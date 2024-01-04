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

from pydantic_argparse.__metadata__ import (
    __author__,
    __description__,
    __license__,
    __title__,
    __version__,
)
from pydantic_argparse.argparse import ArgumentParser

from . import argparse, parsers, utils


class BaseArgument(BaseModel):
    """Base pydantic model for argument groups."""

    model_config = ConfigDict(json_schema_extra=dict(subcommand=False))


class BaseCommand(BaseModel):
    """Base pydantic model for command groups.

    This class is only a convenience base class that sets the
    `model_config` parameter to have the `json_schema_extra` parameter to
    have `subcommand=True`.
    """

    model_config = ConfigDict(json_schema_extra=dict(subcommand=True), defer_build=True)


# Public Re-Exports
__all__ = (
    "ArgumentParser",
    "BaseArgument",
    "BaseCommand",
    "__title__",
    "__description__",
    "__version__",
    "__author__",
    "__license__",
)
