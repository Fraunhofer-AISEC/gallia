# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Argument parser utilities."""

from argparse import Action, FileType
from collections.abc import Callable, Iterable
from typing import Any, Protocol


class SupportsAddArgument(Protocol):
    """ArgumentParser protocol that captures the base parser and argument groups."""

    def add_argument[T](  # noqa: D102
        self,
        *name_or_flags: str,
        action: str | type[Action] = ...,
        nargs: int | str = ...,
        const: Any = ...,
        default: Any = ...,
        type: Callable[[str], T] | FileType = ...,  # noqa: A002
        choices: Iterable[T] | None = ...,
        required: bool = ...,
        help: str | None = ...,  # noqa: A002
        metavar: str | tuple[str, ...] | None = ...,
        dest: str | None = ...,
        version: str = ...,
        **kwargs: Any,
    ) -> Action: ...
