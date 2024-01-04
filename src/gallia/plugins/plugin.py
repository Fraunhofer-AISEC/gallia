# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Union

from gallia.command import BaseCommand
from gallia.services.uds import ECU
from gallia.transports import BaseTransport, TargetURI


@dataclass
class CommandTree:
    description: str | None
    subtree: MutableMapping[str, Union["CommandTree", type[BaseCommand]]]


class Plugin(ABC):
    @classmethod
    @abstractmethod
    def name(cls) -> str: ...

    @classmethod
    def description(cls) -> str:
        return ""

    @classmethod
    def transports(cls) -> list[type[BaseTransport]]:
        return []

    @classmethod
    def ecus(cls) -> list[type[ECU]]:
        return []

    @classmethod
    def commands(cls) -> Mapping[str, CommandTree | type[BaseCommand]]:
        return {}


def load_plugins() -> list[type[Plugin]]:
    """Loads the ``gallia_transports`` entry_point."""
    plugins: list[type[Plugin]] = []

    for plugin_ep in entry_points(group="gallia_plugins"):
        plugin = plugin_ep.load()

        if not issubclass(plugin, Plugin):
            raise ValueError(
                f"{plugin.__name__} from {plugin_ep.name} is not derived from {Plugin.__name__}"
            )

        plugins.append(plugin)

    return plugins


def load_transports() -> list[type[BaseTransport]]:
    transports = []

    for plugin in load_plugins():
        for transport in plugin.transports():
            transports.append(transport)

    return transports


def load_transport(target: TargetURI) -> type[BaseTransport]:
    """Selects a transport class depending on a TargetURI.
    The lookup is performed in builtin transports and all
    classes behind the ``gallia_transports`` entry_point.
    """
    for plugin in load_plugins():
        for transport in plugin.transports():
            if target.scheme == transport.SCHEME:
                return transport

    raise ValueError(f"no transport for {target}")


def load_ecus() -> list[type[ECU]]:
    ecus = []

    for plugin in load_plugins():
        for ecu in plugin.ecus():
            ecus.append(ecu)

    return ecus


def load_ecu(vendor: str) -> type[ECU]:
    """Selects an ecu class depending on a vendor string.
    The lookup is performed in builtin ecus and all
    classes behind the ``gallia_uds_ecus`` entry_point.
    The vendor string ``default`` selects a generic ECU.
    """
    for plugin in load_plugins():
        for ecu in plugin.ecus():
            if vendor == ecu.OEM:
                return ecu

    raise ValueError(f"no such OEM: '{vendor}'")


def _merge_commands(
    c1: MutableMapping[str, CommandTree | type[BaseCommand]],
    c2: Mapping[str, CommandTree | type[BaseCommand]],
) -> None:
    for key, value in c2.items():
        if key not in c1:
            c1[key] = value
        elif isinstance(value, CommandTree) and isinstance(cmd := c1[key], CommandTree):
            try:
                _merge_command_trees(cmd, value)
            except ValueError as e:
                raise ValueError(f"{key} {str(e)}")
        else:
            raise ValueError(f"{key} ]: There already exists a leaf command")


def _merge_command_trees(tree1: CommandTree, tree2: CommandTree) -> None:
    if (
        tree1.description is not None
        and tree2.description is not None
        and tree1.description != tree2.description
    ):
        raise ValueError("]: Incompatible descriptions")

    _merge_commands(tree1.subtree, tree2.subtree)


def load_commands() -> MutableMapping[str, CommandTree | type[BaseCommand]]:
    plugins = load_plugins()
    commands: MutableMapping[str, CommandTree | type[BaseCommand]] = {}

    for plugin in plugins:
        try:
            _merge_commands(commands, plugin.commands())
        except ValueError as e:
            raise ValueError(
                f'Plugin "{plugin.name()}" conflicts with other plugins on command [ {str(e)}'
            ) from None

    return commands
