# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# PYTHON_ARGCOMPLETE_OK

import argparse
import sys
from importlib.metadata import entry_points, version
from typing import Any, Optional

import argcomplete

from gallia.command import BaseCommand
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
from gallia.commands.primitive.uds.send_pdu import SendPDUPrimitve
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

# from gallia.commands.prims.uds.simple_test_xcp import SimpleTestXCP

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
    SendPDUPrimitve,
    WMBAPrimitive,
    VirtualECU,
    WriteByIdentifierPrimitive,
]


# This can be annotated once recursive types are supported by mypy.
# https://github.com/python/mypy/issues/731
PARSERS: dict[str, Any] = {}


def load_cli_commands() -> None:
    eps = entry_points()
    if (s := "gallia_cli_commands") in eps:
        for entry in eps[s]:
            cmd_list: list[type[BaseCommand]] = entry.load()
            for cmd in cmd_list:
                registry.append(cmd)


def load_cli_init() -> None:
    eps = entry_points()
    if (s := "gallia_cli_init") in eps:
        for entry in eps[s]:
            entry.load()()


def add_cli_category(
    parent: dict[str, Any],
    category: str,
    help_: str,
    metavar: str,
    description: Optional[str] = None,
    epilog: Optional[str] = None,
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

    load_cli_init()

    return parsers


def build_cli(parsers: dict[str, Any]) -> None:
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
        scanner = cls(subparser)
        subparser.set_defaults(run_func=scanner.run)


def main() -> None:
    load_cli_commands()

    global PARSERS  # pylint: disable=W0603
    PARSERS = load_parsers()

    build_cli(PARSERS)

    parser = PARSERS["parser"]
    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    if not hasattr(args, "run_func"):
        args.help_func()
        parser.exit(1)

    sys.exit(args.run_func(args))
