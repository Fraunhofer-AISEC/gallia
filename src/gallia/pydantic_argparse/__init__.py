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

from gallia.pydantic_argparse.argparse import ArgumentParser
from gallia.pydantic_argparse.utils.pydantic import BaseArgument, BaseCommand

# Public Re-Exports
__all__ = (
    "ArgumentParser",
    "BaseArgument",
    "BaseCommand",
)
