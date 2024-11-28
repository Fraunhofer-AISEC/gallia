# SPDX-FileCopyrightText: Hayden Richards
#
# SPDX-License-Identifier: MIT

"""Declarative and Typed Argument Parser.

The `parser` module contains the `ArgumentParser` class, which provides a
declarative method of defining command-line interfaces.

The procedure to declaratively define a typed command-line interface is:

1. Define `pydantic` arguments model
2. Create typed `ArgumentParser`
3. Parse typed arguments

The resultant arguments object returned is an instance of the defined
`pydantic` model. This means that the arguments object and its attributes will
be compatible with an IDE, linter or type checker.
"""

import argparse
import sys
from typing import Any, Generic, Never, NoReturn

from pydantic import BaseModel, ValidationError

from gallia.pydantic_argparse import parsers
from gallia.pydantic_argparse.argparse import actions
from gallia.pydantic_argparse.parsers import command
from gallia.pydantic_argparse.utils.field import ArgFieldInfo
from gallia.pydantic_argparse.utils.nesting import _NestedArgumentParser
from gallia.pydantic_argparse.utils.pydantic import PydanticField, PydanticModelT


class ArgumentParser(argparse.ArgumentParser, Generic[PydanticModelT]):
    """Declarative and Typed Argument Parser.

    The `ArgumentParser` declaratively generates a command-line interface using
    the `pydantic` model specified upon instantiation.

    The `ArgumentParser` provides the following `argparse` functionality:

    * Argument Groups
    * Subcommands

    All arguments are *named*, and positional arguments are not supported.

    The `ArgumentParser` provides the method `parse_typed_args()` to parse
    command line arguments and return an instance of its bound `pydantic`
    model, populated with the parsed and validated user supplied command-line
    arguments.
    """

    # Argument Group Names
    COMMANDS = "commands"
    HELP = "help"

    # Exit Codes
    EXIT_ERROR = 2

    def __init__(
        self,
        model: type[PydanticModelT],
        prog: str | None = None,
        description: str | None = None,
        version: str | None = None,
        epilog: str | None = None,
        add_help: bool = True,
        exit_on_error: bool = True,
        extra_defaults: dict[type, dict[str, tuple[str, Any]]] | None = None,
    ) -> None:
        """Instantiates the typed Argument Parser with its `pydantic` model.

        :param model: Pydantic argument model class.
        :param prog: Program name for CLI.
        :param description: Program description for CLI.
        :param version: Program version string for CLI.
        :param epilog: Optional text following help message.
        :param add_help: Whether to add a `-h`/`--help` flag.
        :param exit_on_error: Whether to exit on error.
        :param extra_defaults: Defaults coming from external sources, such as environment variables or config files.
        """
        # Initialise Super Class
        super().__init__(
            prog=prog,
            description=description,
            epilog=epilog,
            exit_on_error=exit_on_error,
            add_help=False,  # Always disable the automatic help flag.
            argument_default=argparse.SUPPRESS,  # Allow `pydantic` to handle defaults.
            formatter_class=argparse.RawTextHelpFormatter,
        )

        # Set Version, Add Help and Exit on Error Flag
        self.version = version
        self.add_help = add_help
        self.exit_on_error = exit_on_error
        self.extra_defaults = extra_defaults

        # Add Arguments Groups
        self._subcommands: argparse._SubParsersAction[Any] | None = None

        # Add Arguments from Model
        self._submodels: dict[str, type[BaseModel]] = {}
        self.model = model
        self._add_model(model)

        self._help_group = self.add_argument_group(ArgumentParser.HELP)

        # Add Help and Version Flags
        if self.add_help:
            self._add_help_flag()
        if self.version:
            self._add_version_flag()

    def parse_typed_args(
        self,
        args: list[str] | None = None,
    ) -> tuple[PydanticModelT, BaseModel]:
        """Parses command line arguments.

        If `args` are not supplied by the user, then they are automatically
        retrieved from the `sys.argv` command-line arguments.

        :param args: Optional list of arguments to parse.
        :return: A tuple of the whole parsed model, as well as the submodel representing the selected subcommand.
        """
        # Call Super Class Method
        namespace = self.parse_args(args)
        nested_parser = _NestedArgumentParser(model=self.model, namespace=namespace)

        try:
            return nested_parser.validate()
        except ValidationError as exc:
            # Catch exceptions, and use the ArgumentParser.error() method
            # to report it to the user
            self._validation_error(exc, nested_parser)

    def _validation_error(
        self, error: ValidationError, parser: _NestedArgumentParser[Any]
    ) -> Never:
        self.print_usage(sys.stderr)

        model = parser.model
        for scp in parser.subcommand_path:
            model = PydanticField(scp, model.model_fields[scp]).model_type

        fields = model.model_fields
        msg = ""

        if error.error_count() == 1:
            msg += "error: "
        else:
            msg += f"{error.error_count()} errors: \n"

        for e in error.errors():
            if error.error_count() > 1:
                msg += "  "

            source = ""
            sources = e["loc"][len(parser.subcommand_path) :]

            # If the validation failed for a field validator there is one source level left,
            # which equals the name of the field
            if len(sources) > 0:
                argument = sources[0]

                assert isinstance(argument, str)

                if (
                    self.extra_defaults is not None
                    and model in self.extra_defaults
                    and argument in self.extra_defaults[model]
                    and self.extra_defaults[model][argument][1] == e["input"]
                ):
                    source = (
                        f"default of {argument} from {self.extra_defaults[model][argument][0]}: "
                    )
                else:
                    # Use the same method, that was used for the CLI generation
                    argument_name = PydanticField(argument, fields[argument]).arg_names()
                    source = f"argument {', '.join(argument_name)}: "

            try:
                error_msg = str(e["ctx"]["error"])
            except KeyError:
                error_msg = e["msg"]

            msg += f"{source}{error_msg}\n"

        # Check whether parser should exit
        if self.exit_on_error:
            self.exit(ArgumentParser.EXIT_ERROR, msg)

        # Raise Error
        raise argparse.ArgumentError(None, msg)

    def error(self, message: str) -> NoReturn:
        """Prints a usage message to `stderr` and exits if required.

        Args:
            message (str): Message to print to the user.

        Raises:
            argparse.ArgumentError: Raised if not exiting on error.
            SystemExit: Raised if exiting on error.
        """
        # Print usage message
        self.print_usage(sys.stderr)

        msg = f"error: {message}\n"

        # TODO: Investigate why this function is called twice when exit_on_error is respected
        # Check whether parser should exit
        # if self.exit_on_error:
        self.exit(ArgumentParser.EXIT_ERROR, msg)

        # Raise Error
        # raise argparse.ArgumentError(None, msg)

    def _commands(self) -> argparse._SubParsersAction:  # type: ignore
        """Creates and Retrieves Subcommands Action for the ArgumentParser.

        Returns:
            argparse._SubParsersAction: SubParsersAction for the subcommands.
        """
        # Check for Existing Sub-Commands Group
        if self._subcommands is None:
            # Add Sub-Commands Group
            self._subcommands = self.add_subparsers(
                title=ArgumentParser.COMMANDS,
                action=actions.SubParsersAction,
                required=True,
            )

            # Shuffle Group to the Top for Help Message
            self._action_groups.insert(0, self._action_groups.pop())

        # Return
        return self._subcommands

    def _add_help_flag(self) -> None:
        """Adds help flag to argparser."""
        # Add help flag
        self._help_group.add_argument(
            "-h",
            "--help",
            action=argparse._HelpAction,
            help="show this help message and exit",
        )

    def _add_version_flag(self) -> None:
        """Adds version flag to argparser."""
        # Add version flag
        self._help_group.add_argument(
            "-v",
            "--version",
            action=argparse._VersionAction,
            help="show program's version number and exit",
        )

    def _add_model(
        self,
        model: type[BaseModel],
        arg_group: argparse._ArgumentGroup | None = None,
    ) -> None:
        """Adds the `pydantic` model to the argument parser.

        Args:
            model (Type[BaseModel]): Pydantic model class to add to the
                argument parser.
            arg_group: (Optional[argparse._ArgumentGroup]): argparse ArgumentGroup.
                This should not normally be passed manually, but only during
                recursion if the original model is a nested pydantic model. These
                nested models are then parsed as argument groups.
        """
        # Initialise validators dictionary
        parser = self if arg_group is None else arg_group

        explicit_groups = {}

        # Loop through fields in model
        for field in PydanticField.parse_model(model):
            if field.is_a(BaseModel):
                if field.is_subcommand():
                    command.parse_field(self._commands(), field, self.extra_defaults)
                else:
                    # for any nested pydantic models, set default factory to model_construct
                    # method. This allows pydantic to handle if no arguments from a nested
                    # submodel are passed by creating the default submodel.
                    # This is not allowed for subcommands.
                    if field.info.default_factory is None:
                        field.info.default_factory = field.model_type.model_construct

                    # create new arg group
                    group_name = field.info.title or field.name
                    arg_group = self.add_argument_group(group_name)

                    # recurse and parse fields below this submodel
                    self._add_model(model=field.model_type, arg_group=arg_group)
            else:
                # Add field
                added = False

                if (
                    self.extra_defaults is not None
                    and model in self.extra_defaults
                    and field.name in self.extra_defaults[model]
                ):
                    field.extra_default = self.extra_defaults[model][field.name]

                if isinstance(field.info, ArgFieldInfo) and field.info.hidden:
                    continue

                if isinstance(field.info, ArgFieldInfo) and field.info.group is not None:
                    if field.info.group not in explicit_groups:
                        explicit_groups[field.info.group] = self.add_argument_group(
                            field.info.group
                        )

                    parsers.add_field(explicit_groups[field.info.group], field)
                    added = True

                if not added:
                    parsers.add_field(parser, field)
