# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Recursively Nesting Sub-Parsers Action for Typed Argument Parsing.

The `actions` module contains the `SubParsersAction` class, which is an action
that provides recursive namespace nesting when parsing sub-commands. It also
contains the `BooleanOptionalAction` class, which is a direct backport of the
Python standard library `argparse` class of the same name.
"""

import argparse
from collections.abc import Callable, Iterable, Sequence
from typing import (
    Any,
    cast,
)


class SubParsersAction(argparse._SubParsersAction):  # type: ignore
    """Recursively Nesting Sub-Parsers Action for Typed Argument Parsing.

    This custom action differs in functionality from the existing standard
    argparse SubParsersAction because it nests the resultant sub-namespace
    directly into the supplied parent namespace, rather than iterating through
    and updating the parent namespace object with each argument individually.

    Example:
        Construct `ArgumentParser`:
        ```python
        # Create Argument Parser
        parser = argparse.ArgumentParser()

        # Add Example Global Argument
        parser.add_argument("--time")

        # Add SubParsersAction
        subparsers = parser.add_subparsers()

        # Add Example 'walk' Command with Arguments
        walk = subparsers.add_parser("walk")
        walk.add_argument("--speed")
        walk.add_argument("--distance")

        # Add Example 'talk' Command with Arguments
        talk = subparsers.add_parser("talk")
        talk.add_argument("--volume")
        talk.add_argument("--topic")
        ```

        Parse the Arguments:
        ```console
        --time 3 walk --speed 7 --distance 42
        ```

        Check Resultant Namespaces:
        ```python
        Original: Namespace(time=3, speed=7, distance=42)
        Custom:   Namespace(time=3, walk=Namespace(speed=7, distance=42))
        ```

    This behaviour results in a final namespace structure which is much easier
    to parse, where subcommands are easily identified and nested into their own
    namespace recursively.
    """

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        """Parses arguments into a namespace with the specified subparser.

        This custom method parses arguments with the specified subparser, then
        embeds the resultant sub-namespace into the supplied parent namespace.

        Args:
            parser (argparse.ArgumentParser): Parent argument parser object.
            namespace (argparse.Namespace): Parent namespace being parsed to.
            values (Union[str, Sequence[Any], None]): Arguments to parse.
            option_string (Optional[str]): Optional option string (not used).

        Raises:
            argparse.ArgumentError: Raised if subparser name does not exist.
        """
        # Check values object is a sequence
        # In order to not violate the Liskov Substitution Principle (LSP), the
        # function signature for __call__ must match the base Action class. As
        # such, this function signature also accepts 'str' and 'None' types for
        # the values argument. However, in reality, this should only ever be a
        # list of strings here, so we just do a type cast.
        values = cast(list[str], values)

        # Get Parser Name and Remaining Argument Strings
        parser_name, *arg_strings = values

        # Try select the parser
        try:
            # Select the parser
            parser = self._name_parser_map[parser_name]

        except KeyError as exc:
            # Parser doesn't exist, raise an exception
            raise argparse.ArgumentError(
                self,
                f"unknown parser {parser_name} (choices: {', '.join(self._name_parser_map)})",
            ) from exc

        # Parse all the remaining options into a sub-namespace, then embed this
        # sub-namespace into the parent namespace
        subnamespace, arg_strings = parser.parse_known_args(arg_strings)
        setattr(namespace, parser_name, subnamespace)

        # Store any unrecognized options on the parent namespace, so that the
        # top level parser can decide what to do with them
        if arg_strings:
            vars(namespace).setdefault(argparse._UNRECOGNIZED_ARGS_ATTR, [])
            getattr(namespace, argparse._UNRECOGNIZED_ARGS_ATTR).extend(arg_strings)


class BooleanOptionalAction(argparse.Action):  # pragma: no cover
    """Action for parsing paired GNU-style boolean arguments.

    This backported action provides the functionality for parsing paired
    GNU-style boolean arguments, such as "--foo/--no-foo". This style of
    argument allows us to easily provide *required* boolean arguments.

    This action was added into the Python standard library `argparse` module
    in [`BPO-8538`](https://bugs.python.org/issue8538) and is available in
    Python 3.9 and above. In order to support Python 3.7 and 3.8 we directly
    backport the class and make it available here.

    Source:
    <https://github.com/python/cpython/blob/v3.11.0/Lib/argparse.py#L878-L914>
    """

    def __init__[T](
        self,
        option_strings: Sequence[str],
        dest: str,
        default: T | str | None = None,
        type_: Callable[[str], T] | argparse.FileType | None = None,
        choices: Iterable[T] | None = None,
        required: bool = False,
        help: str | None = None,  # noqa: A002
        metavar: str | tuple[str, ...] | None = None,
    ) -> None:
        """Instantiates the Boolean Optional Action.

        This creates the default provided "--<OPT>" option strings which set
        the argument to `True`. It also creates alternative pair "--no-<OPT>"
        option strings which set the argument to `False`.

        Args:
            option_strings (Sequence[str]): Option strings.
            dest (str): Destination variable to save the value to.
            default (Optional[Union[T, str]]): Default value of the option.
            type (Optional[Union[Callable[[str], T], argparse.FileType]]): Type
                to cast the option to.
            choices (Optional[Iterable[T]]): Allowed values for the option.
            required (bool): Whether the option is required.
            help (Optional[str]): Help string for the option.
            metavar (Optional[Union[str, Tuple[str, ...]]]): Meta variable name
                for the option.
        """
        # Initialise intermediary option strings list
        _option_strings = []

        # Loop through passed in option strings
        for option_string in option_strings:
            # Append the option string to the new list
            _option_strings.append(option_string)

            # Check if this option string is a "--<OPT>" option string
            if option_string.startswith("--"):
                # Create a "--no-<OPT>" negated option string
                _option_strings.append(f"--no-{option_string[2:]}")

        # Initialise Super Class
        super().__init__(
            option_strings=_option_strings,
            dest=dest,
            nargs=0,
            default=default,
            type=type_,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        """Parses the provided boolean arguments into a namespace.

        This custom method parses arguments as booleans, negating the values of
        any arguments prepended with "--no-".

        Args:
            parser (argparse.ArgumentParser): Parent argument parser object.
            namespace (argparse.Namespace): Parent namespace being parsed to.
            values (Optional[Union[str, Sequence[Any]]]): Arguments to parse.
            option_string (Optional[str]): Optional option string.
        """
        # Check if the passed in option string matches our option strings
        if option_string in self.option_strings:
            # Set a boolean value on the namespace
            # If the option string starts with "--no-", then negate the value
            setattr(namespace, self.dest, not option_string.startswith("--no-"))  # type: ignore[union-attr]

    def format_usage(self) -> str:
        """Formats the usage string.

        Returns:
            str: Usage string for the option.
        """
        # Format and return usage string
        return " | ".join(self.option_strings)
