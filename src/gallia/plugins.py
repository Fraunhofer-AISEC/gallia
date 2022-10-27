# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from importlib.metadata import EntryPoint, entry_points
from typing import TYPE_CHECKING, Any, Callable

from gallia.services.uds.ecu import ECU
from gallia.transports import BaseTransport, TargetURI, registry

if TYPE_CHECKING:
    from gallia.command import BaseCommand


def load_ecu_plugin_eps() -> list[EntryPoint]:
    eps = entry_points()
    return list(eps.select(group="gallia_uds_ecus"))


def load_ecu_plugins() -> list[type[ECU]]:
    ecus = []
    for ep in load_ecu_plugin_eps():
        for t in ep.load():
            if not issubclass(t, ECU):
                raise ValueError(f"entry_point {t} is not derived from ECU")
            ecus.append(t)
    return ecus


def load_ecu(vendor: str) -> type[ECU]:
    if vendor == "default":
        return ECU

    for ecu in load_ecu_plugins():
        if vendor == ecu.OEM:
            return ecu

    raise ValueError(f"no such OEM: '{vendor}'")


def load_command_plugin_eps() -> list[EntryPoint]:
    eps = entry_points()
    return list(eps.select(group="gallia_commands"))


def load_command_plugins() -> list[type[BaseCommand]]:
    out = []
    for ep in load_command_plugin_eps():
        cmd_list: list[type[BaseCommand]] = ep.load()
        for cmd in cmd_list:
            out.append(cmd)
    return out


def load_cli_init_plugin_eps() -> list[EntryPoint]:
    eps = entry_points()
    return list(eps.select(group="gallia_cli_init"))


def load_cli_init_plugins() -> list[Callable[[dict[str, Any]], None]]:
    out = []
    for entry in load_cli_init_plugin_eps():
        out.append(entry.load())
    return out


def load_transport_plugin_eps() -> list[EntryPoint]:
    eps = entry_points()
    return list(eps.select(group="gallia_transports"))


def load_transport_plugins() -> list[type[BaseTransport]]:
    out = []
    for ep in load_transport_plugin_eps():
        for t in ep.load():
            if not issubclass(t, BaseTransport):
                raise ValueError(f"{type(t)} is not derived from BaseTransport")
            out.append(t)
    return out


def load_transport(target: TargetURI) -> type[BaseTransport]:
    transports = registry[:]
    transports += load_transport_plugins()

    for transport in transports:
        if target.scheme == transport.SCHEME:
            return transport

    raise ValueError(f"no transport for {target}")


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
