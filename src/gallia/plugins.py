# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING, Callable, TypedDict

from gallia.services.uds.ecu import ECU
from gallia.transports import BaseTransport, TargetURI, registry

if TYPE_CHECKING:
    from gallia.command import BaseCommand


class Parsers(TypedDict):
    siblings: dict[str, Parsers]
    parser: argparse.ArgumentParser
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser]


def load_ecu_plugin_eps() -> list[EntryPoint]:
    """Loads the ``gallia_uds_ecus`` entry_point."""
    eps = entry_points()
    return list(eps.select(group="gallia_uds_ecus"))


def load_ecu_plugins() -> list[type[ECU]]:
    """Loads the ``gallia_uds_ecus`` entry_point and
    imports the ecu classes with some sanity checks."""
    ecus = []
    for ep in load_ecu_plugin_eps():
        for t in ep.load():
            if not issubclass(t, ECU):
                raise ValueError(f"entry_point {t} not derived from ECU")
            ecus.append(t)
    return ecus


def load_ecu(vendor: str) -> type[ECU]:
    """Selects an ecu class depending on a vendor string.
    The lookup is performed in builtin ecus and all
    classes behind the ``gallia_uds_ecus`` entry_point.
    The vendor string ``default`` selects a generic ECU.
    """
    if vendor == "default":
        return ECU

    for ecu in load_ecu_plugins():
        if vendor == ecu.OEM:
            return ecu

    raise ValueError(f"no such OEM: '{vendor}'")


def load_command_plugin_eps() -> list[EntryPoint]:
    """Loads the ``gallia_commands`` entry_point."""
    eps = entry_points()
    return list(eps.select(group="gallia_commands"))


def load_command_plugins() -> list[type[BaseCommand]]:
    """Loads the ``gallia_commands`` entry_point and
    imports the command classes with some sanity checks."""
    out = []
    for ep in load_command_plugin_eps():
        for t in ep.load():
            # TODO: Find out how to avoid the circular dep.
            # if not issubclass(t, BaseCommand):
            #     raise ValueError(f"{type(t)} not derived from BaseCommand")
            out.append(t)
    return out


def load_cli_init_plugin_eps() -> list[EntryPoint]:
    """Loads the ``gallia_cli_init`` entry_point."""
    eps = entry_points()
    return list(eps.select(group="gallia_cli_init"))


def load_cli_init_plugins() -> list[Callable[[Parsers], None]]:
    """Loads the ``gallia_cli_init`` entry_point and
    imports the functions behind it."""
    out = []
    for entry in load_cli_init_plugin_eps():
        out.append(entry.load())
    return out


def load_transport_plugin_eps() -> list[EntryPoint]:
    """Loads the ``gallia_transports`` entry_point."""
    eps = entry_points()
    return list(eps.select(group="gallia_transports"))


def load_transport_plugins() -> list[type[BaseTransport]]:
    """Loads the ``gallia_transports`` entry_point and
    imports the transport classes with some sanity checks.
    """
    out = []
    for ep in load_transport_plugin_eps():
        for t in ep.load():
            if not issubclass(t, BaseTransport):
                raise ValueError(f"{type(t)} not derived from BaseTransport")
            out.append(t)
    return out


def load_transport(target: TargetURI) -> type[BaseTransport]:
    """Selects a transport class depending on a TargetURI.
    The lookup is performed in builtin transports and all
    classes behind the ``gallia_transports`` entry_point.
    """
    transports = registry[:]
    transports += load_transport_plugins()

    for transport in transports:
        if target.scheme == transport.SCHEME:
            return transport

    raise ValueError(f"no transport for {target}")


def add_cli_group(
    parent: Parsers,
    group: str,
    help_: str,
    metavar: str,
    description: str | None = None,
    epilog: str | None = None,
) -> None:
    """Adds a group to the gallia CLI interface. The arguments
    correspond to the arguments of :meth:`argparse.ArgumentParser.add_argument()`.
    The ``parent`` argument must contain the relevant entry point to the cli
    parse tree. The parse tree is passed to the entry_point ``gallia_cli_init``.
    """
    parser = parent["subparsers"].add_parser(
        group,
        help=help_,
        description=description,
        epilog=epilog,
    )
    parser.set_defaults(usage_func=parser.print_usage)
    parser.set_defaults(help_func=parser.print_help)

    parent["siblings"][group] = {
        "siblings": {},
        "parser": parser,
        "subparsers": parser.add_subparsers(metavar=metavar),
    }
