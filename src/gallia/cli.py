# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# PYTHON_ARGCOMPLETE_OK

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Iterable
from importlib.metadata import EntryPoint, version
from pathlib import Path
from pprint import pprint
from typing import Any

import argcomplete

from gallia.command.base import BaseCommand
from gallia.commands import registry as cmd_registry
from gallia.config import Config, load_config_file
from gallia.log import setup_logging
from gallia.plugins import (
    Parsers,
    add_cli_group,
    load_cli_init_plugin_eps,
    load_cli_init_plugins,
    load_command_plugin_eps,
    load_command_plugins,
    load_ecu_plugin_eps,
    load_transport_plugin_eps,
)


def load_parsers() -> Parsers:
    parser = argparse.ArgumentParser(
        description="""gallia COMMANDs are grouped by GROUP and SUBGROUP.
        Each GROUP, SUBGROUP, or COMMAND contains a help page which can be accessed via `-h` or `--help`.
        A few command line option can be set via a TOML config file. Check `gallia --template` for a starting point.
        """,
        epilog="""https://fraunhofer-aisec.github.io/gallia/index.html""",
    )
    parser.set_defaults(usage_func=parser.print_usage)
    parser.set_defaults(help_func=parser.print_help)
    parser.add_argument(
        "--version",
        action="version",
        version=f'%(prog)s {version("gallia")}',
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="show information about the loaded config",
    )
    parser.add_argument(
        "--show-defaults",
        action="store_true",
        help="show defaults of all flags",
    )
    parser.add_argument(
        "--show-plugins",
        action="store_true",
        help="show loaded plugins",
    )
    parser.add_argument(
        "--template",
        action="store_true",
        help="print a config template",
    )

    subparsers = parser.add_subparsers(metavar="GROUP")
    parsers: Parsers = {
        "parser": parser,
        "subparsers": subparsers,
        "siblings": {},
    }

    command = "COMMAND"
    subgroup = "SUBGROUP"

    add_cli_group(
        parsers,
        "discover",
        "discover scanners for hosts and endpoints",
        metavar=subgroup,
    )
    add_cli_group(
        parsers["siblings"]["discover"],
        "uds",
        "Universal Diagnostic Services",
        description="find UDS endpoints on specific transports using discovery scanning techniques",
        epilog="https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#discovery-scan",
        metavar=command,
    )
    add_cli_group(
        parsers,
        "primitive",
        "protocol specific primitives",
        metavar=subgroup,
    )
    add_cli_group(
        parsers["siblings"]["primitive"],
        "uds",
        "Universal Diagnostic Services",
        description="primitives for the UDS protocol according to the ISO standard",
        metavar=command,
    )
    add_cli_group(
        parsers["siblings"]["primitive"],
        "generic",
        "generic networks primitives",
        description="generic primitives for network protocols, e.g. send a pdu",
        metavar=command,
    )

    add_cli_group(
        parsers,
        "scan",
        "scanners for network protocol parameters",
        metavar=subgroup,
    )
    add_cli_group(
        parsers["siblings"]["scan"],
        "uds",
        "Universal Diagnostic Services",
        description="scan UDS parameters",
        epilog="https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html",
        metavar=command,
    )

    add_cli_group(
        parsers,
        "fuzz",
        "fuzzing tools",
        metavar=subgroup,
    )
    add_cli_group(
        parsers["siblings"]["fuzz"],
        "uds",
        "Universal Diagnostic Services",
        metavar=command,
    )

    add_cli_group(
        parsers,
        "script",
        "miscellaneous helper scripts",
        description="miscellaneous uncategorized helper scripts",
        metavar=command,
    )

    return parsers


def build_cli(
    parsers: Parsers,
    config: Config,
    registry: list[type[BaseCommand]],
) -> None:
    for cls in registry:
        if cls.GROUP is None:
            continue

        if cls.SUBGROUP is not None:
            subparsers = parsers["siblings"][cls.GROUP]["siblings"][cls.SUBGROUP][
                "subparsers"
            ]
        else:
            subparsers = parsers["siblings"][cls.GROUP]["subparsers"]

        # Seems like a mypy bug. This is already covered by the check above.
        assert cls.COMMAND is not None
        subparser = subparsers.add_parser(
            cls.COMMAND,
            description=cls.__doc__,
            help=cls.SHORT_HELP,
            epilog=cls.EPILOG,
        )
        cmd = cls(subparser, config)
        subparser.set_defaults(run_func=cmd.entry_point)


def cmd_show_config(
    args: argparse.Namespace,
    config: Config,
    config_path: Path | None,
) -> None:
    if (p := os.getenv("GALLIA_CONFIG")) is not None:
        print(f"path to config set by env variable: {p}", file=sys.stderr)

    if config_path is not None:
        print(f"loaded config: {config_path}", file=sys.stderr)
        pprint(config)
    else:
        print("no config available", file=sys.stderr)
        sys.exit(1)


def _get_cli_defaults(parser: argparse.ArgumentParser, out: dict[str, Any]) -> None:
    for action in parser.__dict__["_actions"]:
        if isinstance(
            action,
            (
                argparse._StoreAction,  # pylint: disable=protected-access
                argparse._StoreTrueAction,  # pylint: disable=protected-access
                argparse._StoreFalseAction,  # pylint: disable=protected-access
                argparse.BooleanOptionalAction,
            ),
        ):
            opts = action.__dict__["option_strings"]
            if len(opts) == 2:
                if opts[0].startswith("--"):
                    opts_str = opts[0]
                else:
                    opts_str = opts[1]
            elif len(opts) == 1:
                opts_str = opts[0]
            else:
                continue

            keys = (
                f"{parser.prog} {opts_str.removeprefix('--').replace('-', '_')}".split()
            )
            value = action.default

            d = out
            for i, key in enumerate(keys):
                if key not in d:
                    d[key] = {}

                d = d[key]

                if i == len(keys) - 2:
                    d[keys[-1]] = value
                    break

        if isinstance(
            action, argparse._SubParsersAction  # pylint: disable=protected-access
        ):
            for subparser in action.__dict__["choices"].values():
                _get_cli_defaults(subparser, out)


def get_cli_defaults(parser: argparse.ArgumentParser) -> dict[str, Any]:
    out: dict[str, Any] = {}
    _get_cli_defaults(parser, out)
    return out


def cmd_show_defaults(parser: argparse.ArgumentParser) -> None:
    pprint(get_cli_defaults(parser))


def _print_plugin(description: str, eps: list[EntryPoint]) -> None:
    print(f"{description}:")
    for ep in eps:
        print(f"  EntryPoint.name: {ep.name}")
        ep_loaded = ep.load()
        if isinstance(ep_loaded, Iterable):
            for cls in ep_loaded:
                print(f"    * {cls}")
        else:
            print(f"    * {ep_loaded}")


def cmd_show_plugins() -> None:
    _print_plugin(
        "initialization callbacks (gallia_cli_init)", load_cli_init_plugin_eps()
    )
    _print_plugin("commands (gallia_commands)", load_command_plugin_eps())
    _print_plugin("transports (gallia_transports)", load_transport_plugin_eps())
    _print_plugin("ecus (gallia_ecus)", load_ecu_plugin_eps())


def cmd_template(args: argparse.Namespace) -> None:
    template = """# [gallia]
# verbosity = <int>
# trace_log = <bool>
# lock_file = <str>

# [gallia.hooks]
# enable = <bool>
# pre = <str>
# post = <str>

# [gallia.scanner]
# db = <string>
# target = <string>
# power_supply = <string>
# power_cycle = <bool>
# power_cycle_sleep = <float>
# dumpcap = <bool>
# artifacts_dir = <string>
# artifacts_base = <string>

# [gallia.protocols.uds]
# dumpcap = <bool>
# ecu_reset = <float>
# oem = <string>
# timeout = <float>
# max_retries = <int>
# ping = <bool>
# tester_present_interval = <float>
# tester_present = <bool>
# properties = <bool>
# compare_properties = <bool>
"""
    print(template.strip())


def main() -> None:
    registry = cmd_registry[:]

    plugin_cmds = load_command_plugins()
    if len(plugin_cmds) > 0:
        registry += plugin_cmds

    # Will be set to the correct verbosity later.
    setup_logging()

    parsers = load_parsers()

    # Load plugins.
    for fn in load_cli_init_plugins():
        fn(parsers)

    try:
        config, config_path = load_config_file()
    except ValueError as e:
        print(f"invalid config: {e}")
        sys.exit(1)

    build_cli(parsers, config, registry)

    parser = parsers["parser"]
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.show_config:
        cmd_show_config(args, config, config_path)
        sys.exit(0)

    if args.show_defaults:
        cmd_show_defaults(parser)
        sys.exit(0)

    if args.show_plugins:
        cmd_show_plugins()
        sys.exit(0)

    if args.template:
        cmd_template(args)
        sys.exit(0)

    if not hasattr(args, "run_func"):
        args.help_func()
        parser.exit(1)

    sys.exit(args.run_func(args))


if __name__ == "__main__":
    main()
