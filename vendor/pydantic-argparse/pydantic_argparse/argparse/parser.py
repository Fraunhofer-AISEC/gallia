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
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Dict, Generic, List, NoReturn, Optional, Tuple, Type, Any

from pydantic import BaseModel, ValidationError

from pydantic_argparse import parsers, utils
from pydantic_argparse.argparse import actions
from pydantic_argparse.utils.field import ArgFieldInfo
from pydantic_argparse.utils.nesting import _NestedArgumentParser
from pydantic_argparse.utils.pydantic import PydanticField, PydanticModelT


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
        model: Type[PydanticModelT],
        prog: Optional[str] = None,
        description: Optional[str] = None,
        version: Optional[str] = None,
        epilog: Optional[str] = None,
        add_help: bool = True,
        exit_on_error: bool = True,
        extra_defaults: dict[Type, dict[str, Any]] | None = None
    ) -> None:
        """Instantiates the Typed Argument Parser with its `pydantic` model.

        Args:
            model (Type[PydanticModelT]): Pydantic argument model class.
            prog (Optional[str]): Program name for CLI.
            description (Optional[str]): Program description for CLI.
            version (Optional[str]): Program version string for CLI.
            epilog (Optional[str]): Optional text following help message.
            add_help (bool): Whether to add a `-h`/`--help` flag.
            exit_on_error (bool): Whether to exit on error.
        """
        # Initialise Super Class
        if sys.version_info < (3, 9):  # pragma: <3.9 cover
            super().__init__(
                prog=prog,
                description=description,
                epilog=epilog,
                add_help=False,  # Always disable the automatic help flag.
                argument_default=argparse.SUPPRESS,  # Allow `pydantic` to handle defaults.
            )

        else:  # pragma: >=3.9 cover
            super().__init__(
                prog=prog,
                description=description,
                epilog=epilog,
                exit_on_error=exit_on_error,
                add_help=False,  # Always disable the automatic help flag.
                argument_default=argparse.SUPPRESS,  # Allow `pydantic` to handle defaults.
            )

        # Set Version, Add Help and Exit on Error Flag
        self.version = version
        self.add_help = add_help
        self.exit_on_error = exit_on_error
        self.extra_defaults = extra_defaults

        # Add Arguments Groups
        self._subcommands: Optional[argparse._SubParsersAction] = None

        # Add Arguments from Model
        self._submodels: dict[str, Type[BaseModel]] = dict()
        self.model = self._add_model(model)
        print(vars(self.model), file=open("/tmp/after", "w"))

        self._help_group = self.add_argument_group(ArgumentParser.HELP)

        # Add Help and Version Flags
        if self.add_help:
            self._add_help_flag()
        if self.version:
            self._add_version_flag()

    @property
    def has_submodels(self) -> bool:  # noqa: D102
        # this is for simple nested models as arg groups
        has_submodels = len(self._submodels) > 0

        # this is for nested commands
        if self._subcommands is not None:
            has_submodels = has_submodels or any(
                len(subparser._submodels) > 0
                for subparser in self._subcommands.choices.values()
            )
        return has_submodels

    def parse_typed_args(
        self,
        args: Optional[List[str]] = None,
    ) -> Tuple[PydanticModelT, BaseModel]:
        """Parses command line arguments.

        If `args` are not supplied by the user, then they are automatically
        retrieved from the `sys.argv` command-line arguments.

        Args:
            args (Optional[List[str]]): Optional list of arguments to parse.

        Returns:
            PydanticModelT: Populated instance of typed arguments model.

        Raises:
            argparse.ArgumentError: Raised upon error, if not exiting on error.
            SystemExit: Raised upon error, if exiting on error.
        """
        # Call Super Class Method
        namespace = self.parse_args(args)

        print(namespace)

        try:
            nested_parser = _NestedArgumentParser(model=self.model, namespace=namespace)
            return nested_parser.validate()
        except ValidationError as exc:
            # Catch exceptions, and use the ArgumentParser.error() method
            # to report it to the user
            self.error(utils.errors.format(exc))

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

        # Check whether parser should exit
        if self.exit_on_error:
            self.exit(ArgumentParser.EXIT_ERROR, f"{self.prog}: error: {message}\n")

        # Raise Error
        raise argparse.ArgumentError(None, f"{self.prog}: error: {message}")

    def _commands(self) -> argparse._SubParsersAction:
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
        model: Type[BaseModel],
        arg_group: Optional[argparse._ArgumentGroup] = None,
    ) -> Type[BaseModel]:
        """Adds the `pydantic` model to the argument parser.

        This method also generates "validators" for the arguments derived from
        the `pydantic` model, and generates a new subclass from the model
        containing these validators.

        Args:
            model (Type[PydanticModelT]): Pydantic model class to add to the
                argument parser.
            arg_group: (Optional[argparse._ArgumentGroup]): argparse ArgumentGroup.
                This should not normally be passed manually, but only during
                recursion if the original model is a nested pydantic model. These
                nested models are then parsed as argument groups.

        Returns:
            Type[PydanticModelT]: Pydantic model possibly with new validators.
        """
        # Initialise validators dictionary
        validators: Dict[str, utils.pydantic.PydanticValidator] = dict()
        parser = self if arg_group is None else arg_group

        explicit_groups = {}
        validation_model = model.model_construct()

        # Loop through fields in model
        for field in PydanticField.parse_model(model):
            if field.is_a(BaseModel):
                if field.is_subcommand():
                    validator = parsers.command.parse_field(self._commands(), field, self.extra_defaults)
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
                    # TODO: storage of submodels not needed
                    self._submodels[field.name] = self._add_model(
                        model=field.model_type,
                        arg_group=arg_group
                    )

                    validator = None

            else:
                # Add field
                added = False

                if self.extra_defaults is not None and model in self.extra_defaults and field.name in self.extra_defaults[model]:
                    field.extra_default = self.extra_defaults[model][field.name]
                    try:
                        field.validated_extra_default = getattr(model.__pydantic_validator__.validate_assignment(validation_model, field.name, field.extra_default), field.name)
                    except ValidationError:
                        # TODO Print warning for invalid config
                        pass

                if isinstance(field.info, ArgFieldInfo) and field.info.group is not None:
                    if field.info.group not in explicit_groups:
                        explicit_groups[field.info.group] = self.add_argument_group(field.info.group)

                    validator = parsers.add_field(explicit_groups[field.info.group], field)
                    added = True

                if not added:
                    validator = parsers.add_field(parser, field)

            # Update validators
            utils.pydantic.update_validators(validators, validator)

        # Construct and return model with validators
        return utils.pydantic.model_with_validators(model, validators)
