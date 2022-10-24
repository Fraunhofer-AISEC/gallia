# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# PYTHON_ARGCOMPLETE_OK

import argparse
import os
import sys
from collections.abc import Callable
from importlib.metadata import entry_points, version
from pathlib import Path
from pprint import pprint
from typing import Any

import argcomplete

from gallia.command import BaseCommand, load_ecus
from gallia.commands.discover.uds.doip import DoIPDiscoverer
from gallia.commands.discover.uds.isotp import IsotpDiscoverer
from gallia.commands.fuzz.uds.pdu import PDUFuzzer
from gallia.commands.primitive.uds.dtc import DTCPrimitive
from gallia.commands.primitive.uds.ecu_reset import ECUResetPrimitive
from gallia.commands.primitive.uds.iocbi import IOCBIPrimitive
from gallia.commands.primitive.uds.ping import PingPrimitive
from gallia.commands.primitive.uds.read_by_identifier import ReadByIdentifierPrimitive
from gallia.commands.primitive.uds.read_error_log import ReadErrorLogPrimitive
from gallia.commands.primitive.uds.rmba import RMBAPrimitive
from gallia.commands.primitive.uds.rtcl import RTCLPrimitive
from gallia.commands.primitive.uds.send_pdu import SendPDUPrimitive
from gallia.commands.primitive.uds.vin import VINPrimitive
from gallia.commands.primitive.uds.wmba import WMBAPrimitive
from gallia.commands.primitive.uds.write_by_identifier import WriteByIdentifierPrimitive
from gallia.commands.scan.uds.identifiers import ScanIdentifiers
from gallia.commands.scan.uds.memory import MemoryFunctionsScanner
from gallia.commands.scan.uds.reset import ResetScanner
from gallia.commands.scan.uds.sa_dump_seeds import SASeedsDumper
from gallia.commands.scan.uds.services import ServicesScanner
from gallia.commands.scan.uds.sessions import SessionsScanner
from gallia.commands.script.vecu import VirtualECU
from gallia.config import Config, load_config_file
from gallia.log import Loglevel, setup_logging
from gallia.transports import load_transports


def load_cli_commands() -> list[type[BaseCommand]]:
    out = []
    eps = entry_points()
    for entry in eps.select(group="gallia_cli_commands"):
        cmd_list: list[type[BaseCommand]] = entry.load()
        for cmd in cmd_list:
            out.append(cmd)
    return out


def load_cli_init() -> list[Callable[[dict[str, Any]], None]]:
    out = []
    eps = entry_points()
    for entry in eps.select(group="gallia_cli_init"):
        out.append(entry.load())
    return out


def add_cli_category(
    parent: dict[str, Any],
    category: str,
    help_: str,
    metavar: str,
    description: str | None = None,
    epilog: str | None = None,
) -> None:
    parser = parent["subparsers"].add_parser(
        category,
        help=help_,
        description=description,
        epilog=epilog,
    )
    parser.set_defaults(usage_func=parser.print_usage)
    parser.set_defaults(help_func=parser.print_help)

    parent["siblings"][category] = {}
    parent["siblings"][category]["siblings"] = {}
    parent["siblings"][category]["parser"] = parser
    parent["siblings"][category]["subparsers"] = parser.add_subparsers(metavar=metavar)


def load_parsers() -> dict[str, Any]:
    parser = argparse.ArgumentParser(
        description="""gallia COMMANDs are grouped by CATEGORY and SUBCATEGORY.
        Each CATEGORY, SUBCATEGORY, or COMMAND contains a help page which can be accessed via `-h` or `--help`.
Every command line option can be set via a TOML config file. Check `gallia --template` for a starting point.
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

    subparsers = parser.add_subparsers(metavar="CATEGORY")
    parsers: dict[str, Any] = {
        "parser": parser,
        "subparsers": subparsers,
        "siblings": {},
    }

    command = "COMMAND"
    subcategory = "SUBCATEGORY"

    add_cli_category(
        parsers,
        "discover",
        "discover scanners for hosts and endpoints",
        metavar=subcategory,
    )
    add_cli_category(
        parsers["siblings"]["discover"],
        "uds",
        "Universal Diagnostic Services",
        description="find UDS endpoints on specific transports using discovery scanning techniques",
        epilog="https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#discovery-scan",
        metavar=command,
    )
    add_cli_category(
        parsers["siblings"]["discover"],
        "xcp",
        "Universal Measurement and Calibration Protocol",
        metavar=command,
    )

    add_cli_category(
        parsers,
        "primitive",
        "protocol specific primitives",
        metavar=subcategory,
    )
    add_cli_category(
        parsers["siblings"]["primitive"],
        "uds",
        "Universal Diagnostic Services",
        description="primitives for the UDS protocol according to the ISO standard",
        metavar=command,
    )

    add_cli_category(
        parsers,
        "scan",
        "scanners for network protocol parameters",
        metavar=subcategory,
    )
    add_cli_category(
        parsers["siblings"]["scan"],
        "uds",
        "Universal Diagnostic Services",
        description="scan UDS parameters",
        epilog="https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html",
        metavar=command,
    )

    add_cli_category(
        parsers,
        "fuzz",
        "fuzzing tools",
        metavar=subcategory,
    )
    add_cli_category(
        parsers["siblings"]["fuzz"],
        "uds",
        "Universal Diagnostic Services",
        metavar=command,
    )

    add_cli_category(
        parsers,
        "script",
        "miscellaneous helper scripts",
        description="miscellaneous uncategorized helper scripts",
        metavar=command,
    )

    return parsers


# This can be annotated once recursive types are supported by mypy.
# https://github.com/python/mypy/issues/731
def build_cli(
    parsers: dict[str, Any],
    config: Config,
    registry: list[type[BaseCommand]],
) -> None:
    for cls in registry:
        if cls.SUBCATEGORY is not None:
            subparsers = parsers["siblings"][cls.CATEGORY]["siblings"][cls.SUBCATEGORY][
                "subparsers"
            ]
        else:
            subparsers = parsers["siblings"][cls.CATEGORY]["subparsers"]

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


def _print_plugin(description: str, fn: Callable[[], Any]) -> None:
    if len(objs := fn()) > 0:
        print(f"{description}:")
        for obj in objs:
            print(f" * {obj}")


def cmd_show_plugins() -> None:
    _print_plugin("initialization callbacks", load_cli_init)
    _print_plugin("commands", load_cli_commands)
    _print_plugin("transports", load_transports)
    _print_plugin("ecus", load_ecus)


def cmd_template(args: argparse.Namespace) -> None:
    template = """[gallia]
# verbosity = <int>
# trace_log = <bool>
# pre_hook = <str>
# post_hook = <str>
# lock_file = <str>

[gallia.scanner]
# db = <string>
# target = <string>
# power_supply = <string>
# power_cycle = <float>
# dumpcap = <bool>
# artifacts_dir = <string>
# artifacts_base = <string>

[gallia.protocols.uds]
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
    registry: list[type[BaseCommand]] = [
        # SimpleTestXCP,
        DoIPDiscoverer,
        IsotpDiscoverer,
        PDUFuzzer,
        MemoryFunctionsScanner,
        ReadByIdentifierPrimitive,
        ResetScanner,
        SASeedsDumper,
        ScanIdentifiers,
        SessionsScanner,
        ServicesScanner,
        DTCPrimitive,
        ECUResetPrimitive,
        VINPrimitive,
        IOCBIPrimitive,
        PingPrimitive,
        RMBAPrimitive,
        RTCLPrimitive,
        ReadErrorLogPrimitive,
        SendPDUPrimitive,
        WMBAPrimitive,
        VirtualECU,
        WriteByIdentifierPrimitive,
    ]

    plugin_cmds = load_cli_commands()
    if len(plugin_cmds) > 0:
        registry += plugin_cmds

    # Will be set to the correct verbosity later.
    setup_logging(Loglevel.DEBUG)

    parsers = load_parsers()

    # Load plugins.
    for fn in load_cli_init():
        fn(parsers)

    config, config_path = load_config_file()
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
