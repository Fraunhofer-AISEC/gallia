from abc import ABC, abstractmethod
from dataclasses import dataclass
from importlib.metadata import entry_points
from typing import Union

from gallia.command import BaseCommand
from gallia.command.config import GalliaBaseModel
from gallia.services.uds import ECU
from gallia.transports import BaseTransport, TargetURI


@dataclass
class Command:
    description: str
    config: type[GalliaBaseModel]
    command: type[BaseCommand]


@dataclass
class CommandTree:
    description: str
    subtree: dict[str, Union["CommandTree", Command]]


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
    def commands(cls) -> dict[str, CommandTree | Command]:
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


def load_commands() -> dict[str, CommandTree | Command]:
    plugins = load_plugins()

    for plugin in plugins:
        # TODO: Merge multiple, currently only one
        return plugin.commands()
