# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import asyncio
import io
import os
import sys
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from contextlib import redirect_stderr, redirect_stdout
from importlib.metadata import version as meta_version
from pprint import pprint
from typing import Any, NamedTuple, Never

import argcomplete
from pydantic import Field, create_model

from gallia import exitcodes
from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig, config_type_of
from gallia.command.config import GalliaBaseModel
from gallia.config import Config, load_config_file
from gallia.log import Loglevel, setup_logging
from gallia.plugins.plugin import (
    Command,
    CommandTree,
    iter_command_leaves,
    load_commands,
    load_plugins,
    resolve_command,
    validate_plugins,
)
from gallia.pydantic_argparse import ArgumentParser
from gallia.pydantic_argparse import BaseCommand as PydanticBaseCommand

defaults = dict[type, dict[str, Any]]
_CLASS_ATTR = "_dynamic_gallia_command_class_reference"


def _create_parser_from_command(
    command: type[AsyncScript[Any]],
    config: Config,
    extra_defaults: defaults,
    model_counter: int = 0,
) -> tuple[type[PydanticBaseCommand], defaults, int]:
    config_type = config_type_of(command)
    config_attributes = config_type.attributes_from_config(config)

    # it is necessary to create a submodel, because several commands can use the same config
    # (e.g. of their base class if no additional arguments are required)
    model_type = create_model(f"_dynamic_{config_type}_{model_counter}", __base__=config_type)
    model_type._original_field_infos = config_type._original_field_infos  # type: ignore[attr-defined]
    extra_defaults[model_type] = config_attributes

    setattr(model_type, _CLASS_ATTR, command)

    return model_type, extra_defaults, model_counter  # type: ignore[return-value]


def _create_parser_from_tree(
    command_tree: CommandTree, config: Config, extra_defaults: defaults, model_counter: int = 0
) -> tuple[type[PydanticBaseCommand], defaults, int]:
    model_name = f"_dynamic_gallia_hierarchy_model_{model_counter}"
    args: dict[str, Any] = {}

    for key, value in command_tree.subtree.items():
        model_counter += 1

        if isinstance(value, CommandTree):
            model_type, extra_defaults, model_counter = _create_parser_from_tree(
                value, config, extra_defaults, model_counter
            )
            description = value.description
        else:
            command = resolve_command(value)
            model_type, extra_defaults, model_counter = _create_parser_from_command(
                command, config, extra_defaults, model_counter
            )
            description = command.SHORT_HELP

        args[key] = (model_type | None, Field(None, description=description))

    return (
        create_model(model_name, __base__=PydanticBaseCommand, **args),
        extra_defaults,
        model_counter,
    )


# TODO: Move this function into some CLI library package.
def create_parser(
    commands: type[AsyncScript[Any]] | MutableMapping[str, CommandTree | Command],
) -> ArgumentParser[PydanticBaseCommand]:
    """
    Creates an argument parser out of the given command hierarchy.

    Command classes may be given as specification strings (``"module:QualName"``);
    they are resolved (i.e. imported) eagerly by this function. For lazy
    resolution of only the selected command, see parse_and_run().

    For accessing the command after parsing, see get_command().
    See parse_and_run() for an easy-to-use one call alternative.

    :param commands: A hierarchy of commands.
    :return The argument parser for the given commands.
    """

    config, _ = load_config_file()

    if isinstance(commands, MutableMapping):
        command_tree = CommandTree("", subtree=commands)
        model, extra_defaults, _ = _create_parser_from_tree(command_tree, config, {})
    else:
        model, extra_defaults, _ = _create_parser_from_command(commands, config, {})

    return ArgumentParser(model=model, extra_defaults=extra_defaults)


def get_command(config: AsyncScriptConfig) -> AsyncScript[Any]:
    """
    Retrieve the command out of the config returned by an argument parser as created by create_parser().

    :param config:
    :return: The command initiated with the given config.
    """
    cmd: type[AsyncScript[Any]] = getattr(config, _CLASS_ATTR)

    return cmd(config)


def _resolve_all(
    commands: Mapping[str, CommandTree | Command],
) -> MutableMapping[str, CommandTree | Command]:
    """Recursively resolves all command specifications to their classes."""
    resolved: MutableMapping[str, CommandTree | Command] = {}

    for name, value in commands.items():
        if isinstance(value, CommandTree):
            resolved[name] = CommandTree(value.description, subtree=_resolve_all(value.subtree))
        else:
            resolved[name] = resolve_command(value)

    return resolved


def _resolve_path(
    commands: Mapping[str, CommandTree | Command],
    path: Sequence[str],
    *,
    expand_last_tree: bool = False,
) -> MutableMapping[str, CommandTree | Command]:
    """Resolves the command addressed by ``path``.

    All command classes along the path are imported; sibling branches are
    dropped, so that only the selected command is modeled by the parser.

    If the path addresses a command tree and ``expand_last_tree`` is set,
    only that tree is expanded by one level: its leaf children are resolved
    and nested trees are represented by empty placeholders. This is
    sufficient to display the help of the selected tree.
    """
    name, rest = path[0], path[1:]
    value = commands[name]

    if isinstance(value, CommandTree):
        if rest:
            subtree = _resolve_path(value.subtree, rest, expand_last_tree=expand_last_tree)
        elif expand_last_tree:
            subtree = _shallow_top_level(value.subtree)
        else:
            subtree = _resolve_all(value.subtree)
        return {name: CommandTree(value.description, subtree=subtree)}

    return {name: resolve_command(value)}


def _shallow_top_level(
    commands: Mapping[str, CommandTree | Command],
) -> MutableMapping[str, CommandTree | Command]:
    """Resolves only the top level of the given command hierarchy.

    ``CommandTree`` branches are represented by empty placeholders: the
    resulting parser spans all command names with their descriptions,
    which is sufficient to display the top-level help.
    """
    shallow: MutableMapping[str, CommandTree | Command] = {}

    for name, value in commands.items():
        if isinstance(value, CommandTree):
            shallow[name] = CommandTree(value.description, subtree={})
        else:
            shallow[name] = resolve_command(value)

    return shallow


class _Selection(NamedTuple):
    """The command selected by ``argv``.

    ``path`` holds the matched command names. ``leaf`` states whether the
    selection is a leaf command; otherwise it is a command tree, whose
    children are addressed by the remaining tokens (``rest``).
    """

    path: list[str]
    leaf: bool
    rest: Sequence[str]


def _find_command_path(
    commands: Mapping[str, CommandTree | Command],
    argv: Sequence[str],
    top_level_actions: Mapping[str, Callable[[], None]] | None = None,
) -> _Selection | None:
    """Walks ``argv`` and returns the deepest command selection.

    ``None`` is returned if the selection cannot be narrowed without the
    full command tree, i.e. for options or garbage tokens before any
    command name, signaling the caller to fall back to a parser spanning
    all commands.

    Top-level actions (e.g. ``--version``) are executed here, before any
    command module is imported.
    """
    path: list[str] = []
    level: Mapping[str, CommandTree | Command] = commands

    for index, token in enumerate(argv):
        if token.startswith("-"):
            if not path:
                if (
                    top_level_actions is not None
                    and (action := top_level_actions.get(token)) is not None
                ):
                    action()
                    sys.exit(exitcodes.OK)
                return None
            return _Selection(path, False, argv[index:])

        if (value := level.get(token)) is None:
            if not path:
                return None
            return _Selection(path, False, argv[index:])

        path.append(token)

        if isinstance(value, CommandTree):
            level = value.subtree
        else:
            return _Selection(path, True, argv[index + 1 :])

    return _Selection(path, False, [])


def _add_top_level_options(
    parser: ArgumentParser[PydanticBaseCommand],
    top_level_options: Mapping[str, tuple[Callable[[], None], str]] | None,
) -> None:
    if top_level_options is None:
        return

    for name, (func, help_) in top_level_options.items():

        class Action(argparse.Action):
            cmd = staticmethod(func)

            def __call__(
                self,
                parser: argparse.ArgumentParser,
                namespace: argparse.Namespace,
                values: str | Sequence[Any] | None,
                option_string: str | None = None,
            ) -> None:
                self.cmd()
                sys.exit(exitcodes.OK)

        parser.add_argument(
            name,
            nargs=0,
            action=Action,
            help=help_,
        )


def _parse_selected(
    parser: ArgumentParser[PydanticBaseCommand],
    commands: MutableMapping[str, CommandTree | Command],
    top_level_options: Mapping[str, tuple[Callable[[], None], str]] | None,
) -> tuple[PydanticBaseCommand, Any]:
    """Parses ``sys.argv`` with a parser spanning only the selected subtree.

    Help and error messages of the pruned parser can differ from the full
    parser, because the usage line omits unselected commands. Therefore,
    parse errors (exit code 2) are re-created with the full parser, and
    other exits (e.g. ``--help``) replay the captured output.
    """
    out, err = io.StringIO(), io.StringIO()

    try:
        with redirect_stdout(out), redirect_stderr(err):
            return parser.parse_typed_args()
    except SystemExit as exc:
        if exc.code == 2:
            full_parser = create_parser(_resolve_all(commands))
            _add_top_level_options(full_parser, top_level_options)
            return full_parser.parse_typed_args()

        sys.stdout.write(out.getvalue())
        sys.stderr.write(err.getvalue())
        raise


def _get_log_level(cli_level: int) -> Loglevel:
    level = Loglevel.INFO
    if cli_level == 1:
        level = Loglevel.DEBUG
    elif cli_level == 2:
        level = Loglevel.TRACE
    return level


# TODO: Move this function into some CLI library package.
def parse_and_run(
    commands: type[AsyncScript[Any]] | MutableMapping[str, CommandTree | Command],
    auto_complete: bool = True,
    setup_log: bool = True,
    top_level_options: Mapping[str, tuple[Callable[[], None], str]] | None = None,
    show_help_on_zero_args: bool = True,
) -> Never:
    """
    Creates an argument parser out of the given command hierarchy and runs the command with its argument.

    This function never returns.
    A set of commands is simply generated by a dict with command name as key and a Command object as value.
    For a full hierarchy of commands CommandTrees can be used.
    Command classes may be given as specification strings (``"module:QualName"``);
    only the module of the selected command is imported.

    :param commands: A hierarchy of commands.
    :param auto_complete: Turns auto-complete functionality on.
    :param setup_log: Setup logging according to the parameters in the parsed config.
    :param top_level_options: Optional top-level actions, such as "--version", given by a mapping of arguments and
                              functions. The program redirects control to the given function, once the program is
                              called with the corresponding argument and terminates after it returns.
    :param show_help_on_zero_args: Show the help message instead of an error in case no arguments are submitted at all.
    """
    if not isinstance(commands, MutableMapping):
        # A single command: nothing to discover or defer.
        parser = create_parser(commands)
        _add_top_level_options(parser, top_level_options)

        if auto_complete:
            argcomplete.autocomplete(parser)

        if show_help_on_zero_args and len(sys.argv) == 1:
            parser.print_help(sys.stderr)
            sys.exit(exitcodes.USAGE)

        _, config = parser.parse_typed_args()
    elif auto_complete and "_ARGCOMPLETE" in os.environ:
        # Shell completion needs to consider all commands, so the full
        # parser (with all command modules imported) is required here.
        parser = create_parser(_resolve_all(commands))
        _add_top_level_options(parser, top_level_options)
        argcomplete.autocomplete(parser)

        _, config = parser.parse_typed_args()
    else:
        if show_help_on_zero_args and len(sys.argv) == 1:
            # The top-level help lists command names and descriptions only;
            # no command module needs to be imported for that.
            parser = create_parser(_shallow_top_level(commands))
            _add_top_level_options(parser, top_level_options)
            parser.print_help(sys.stderr)
            sys.exit(exitcodes.USAGE)

        top_level_actions = (
            {name: func for name, (func, _) in top_level_options.items()}
            if top_level_options is not None
            else None
        )

        # Root-level help: only the top-level descriptions are needed.
        if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
            parser = create_parser(_shallow_top_level(commands))
            _add_top_level_options(parser, top_level_options)
            _, config = _parse_selected(parser, commands, top_level_options)
        else:
            selection = _find_command_path(commands, sys.argv[1:], top_level_actions)

            is_tree_help = (
                selection is not None
                and not selection.leaf
                and bool(selection.rest)
                and selection.rest[0] in ("-h", "--help")
            )

            if selection is None or not (selection.leaf or is_tree_help):
                # Options or garbage before any command name, or an
                # incomplete/invalid command selection: the resulting
                # messages reference all commands, so the full parser is
                # required to reproduce them.
                parser = create_parser(_resolve_all(commands))
                _add_top_level_options(parser, top_level_options)
                _, config = parser.parse_typed_args()
            elif selection.leaf:
                # Fast path: import and model only the selected command.
                parser = create_parser(_resolve_path(commands, selection.path))
                _add_top_level_options(parser, top_level_options)
                _, config = _parse_selected(parser, commands, top_level_options)
            else:
                # Fast path: import and model only the selected subtree.
                parser = create_parser(
                    _resolve_path(commands, selection.path, expand_last_tree=True)
                )
                _add_top_level_options(parser, top_level_options)
                _, config = _parse_selected(parser, commands, top_level_options)

    assert isinstance(config, AsyncScriptConfig)

    volatile_info = config.volatile_info
    if sys.stderr.isatty() is False:
        volatile_info = False

    if setup_log:
        setup_logging(
            level=_get_log_level(config.verbose),
            volatile_info=volatile_info,
            syslog_format=config.syslog_format,
            logger_name="",  # Take over the root logger
        )

    sys.exit(asyncio.run(get_command(config).entry_point()))


def version() -> None:
    """
    Prints the currently installed version of gallia.
    """
    print(f"gallia {meta_version('gallia')}")


def _walk_commands(
    commands: Mapping[str, CommandTree | Command], level: int = 0
) -> tuple[str, int]:
    command_str = ""
    command_ctr = 0

    for name, command in commands.items():
        command_str += f"{'  ' * (level + 2)}{name}"

        if isinstance(command, CommandTree):
            command_str += "\n"

            sub_command_str, sub_command_ctr = _walk_commands(command.subtree, level + 1)
            command_ctr += sub_command_ctr
            command_str += sub_command_str
        else:
            command_ctr += 1

            if isinstance(command, str):
                module, _, qualname = command.partition(":")
                command_str += f": {module}.{qualname}\n"
            else:
                command_str += f": {command.__module__}.{command.__name__}\n"

    return command_str, command_ctr


def show_plugins() -> None:
    """
    Prints the currently installed plugins.
    """
    plugins = load_plugins()

    print(f"There are currently {len(plugins)} plugins installed:")

    for plugin in plugins:
        print()
        print(plugin.name())

        ecus = plugin.ecus()
        print(f"  ECUs ({len(ecus)}):")

        for ecu in ecus:
            print(f"    {ecu.OEM}: {ecu.__module__}.{ecu.__name__}")

        transports = plugin.transports()
        print(f"\n  Transports ({len(transports)}):")

        for transport in transports:
            print(f"    {transport.SCHEME}: {transport.__module__}.{transport.__name__}")

        commands = plugin.commands()
        command_str, command_ctr = _walk_commands(commands)

        print(f"\n  Commands ({command_ctr}):")
        print(command_str)


def show_config() -> None:
    """
    Prints the currently loaded config.
    """
    if (p := os.getenv("GALLIA_CONFIG")) is not None:
        print(f"path to config set by env variable: {p}", file=sys.stderr)

    config, config_path = load_config_file()

    if config_path is not None:
        print(f"loaded config: {config_path}", file=sys.stderr)
        pprint(config)
    else:
        print("no config available", file=sys.stderr)
        sys.exit(exitcodes.CONFIG)


def template() -> None:
    """
    Prints a template config with default according to the programmatic defaults.
    """
    print(GalliaBaseModel.create_template() + "\n")


def check_plugins() -> None:
    """
    Resolves all commands of all plugins and reports broken specifications,
    e.g. typos in the module path of a command specification string.
    """
    plugins = load_plugins()

    if len(plugins) == 0:
        print("no plugins registered", file=sys.stderr)
        sys.exit(exitcodes.SOFTWARE)

    failures = validate_plugins()

    if failures:
        print(f"Found {len(failures)} broken plugin entries:", file=sys.stderr)

        for failure in failures:
            print(f"  {failure}", file=sys.stderr)

        sys.exit(exitcodes.SOFTWARE)

    n_commands = sum(len(list(iter_command_leaves(p.commands()))) for p in plugins)
    print(f"All {len(plugins)} plugins valid ({n_commands} commands resolved).")


def main() -> None:
    gallia_commands = load_commands()
    parse_and_run(
        gallia_commands,
        top_level_options={
            "--version": (version, "show version and exit"),
            "--show-plugins": (show_plugins, "show registered plugins"),
            "--check-plugins": (
                check_plugins,
                "resolve all plugin commands and report broken specifications",
            ),
            "--show-config": (show_config, "show loaded config"),
            "--template": (template, "generate an annotated config template"),
        },
        show_help_on_zero_args=True,
    )


if __name__ == "__main__":
    main()
