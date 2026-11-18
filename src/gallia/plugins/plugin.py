# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping, MutableMapping
from dataclasses import dataclass
from functools import lru_cache
from importlib import import_module
from importlib.metadata import entry_points
from typing import Any

from gallia.command import AsyncScript
from gallia.services.uds import ECU
from gallia.transports import BaseTransport, TargetURI

#: A command is either an ``AsyncScript`` subclass or a specification string
#: of the form ``"module:QualName"``. Specification strings are resolved
#: lazily (see :func:`resolve_command`), which keeps the imports of heavy
#: dependencies out of the CLI startup path.
type Command = type[AsyncScript[Any]] | str


@dataclass
class CommandTree:
    description: str | None
    subtree: MutableMapping[str, CommandTree | Command]


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
    def commands(cls) -> Mapping[str, CommandTree | Command]:
        return {}


def resolve_command(command: Command) -> type[AsyncScript[Any]]:
    """Resolve a command to the corresponding ``AsyncScript`` subclass.

    ``AsyncScript`` subclasses are returned unchanged. Specification strings
    of the form ``"module:QualName"`` are resolved by importing the module
    and looking up the (dotted) attribute path.
    """
    if not isinstance(command, str):
        return command

    module_name, sep, qualname = command.partition(":")
    if not sep or not module_name or not qualname:
        raise ValueError(
            f"invalid command specification: {command!r}, expected format 'module:QualName'"
        )

    obj: Any = import_module(module_name)
    for attribute in qualname.split("."):
        obj = getattr(obj, attribute)

    if not (isinstance(obj, type) and issubclass(obj, AsyncScript)):
        raise TypeError(f"{command!r} does not refer to an AsyncScript subclass")

    return obj


def iter_command_leaves(
    commands: Mapping[str, CommandTree | Command],
    prefix: tuple[str, ...] = (),
) -> Iterator[tuple[tuple[str, ...], Command]]:
    """Iterates over the leaves of a command hierarchy.

    Yields tuples of a command's path (the names along the hierarchy,
    e.g. ``("discover", "doip")``) and the corresponding, possibly unresolved,
    command.
    """
    for name, value in commands.items():
        if isinstance(value, CommandTree):
            yield from iter_command_leaves(value.subtree, (*prefix, name))
        else:
            yield (*prefix, name), value


def validate_plugins() -> list[str]:
    """Validates all plugins registered via the ``gallia_plugins`` entry_points.

    For each plugin, the ``transports()`` and ``ecus()`` factories are called
    and all command specifications are resolved. This forces the imports which
    are deferred at CLI startup by the lazy resolution (see
    :func:`resolve_command`) and is therefore suited for a self-check, e.g.
    triggered by ``gallia --check-plugins`` or from a test suite.

    Returns the error messages of all encountered failures; the list is empty
    if the plugin registry is consistent.
    """
    failures: list[str] = []

    for plugin in load_plugins():
        name = plugin.name()

        try:
            plugin.transports()
        except Exception as e:
            failures.append(f"{name}: transports(): {e!r}")

        try:
            plugin.ecus()
        except Exception as e:
            failures.append(f"{name}: ecus(): {e!r}")

        for path, command in iter_command_leaves(plugin.commands()):
            try:
                resolve_command(command)
            except Exception as e:
                failures.append(f"{name}: command '{' '.join(path)}' ({command!r}): {e!r}")

    return failures


@lru_cache
def _load_plugins() -> tuple[type[Plugin], ...]:
    """Loads the classes behind the ``gallia_plugins`` entry_points."""
    plugins: list[type[Plugin]] = []

    for plugin_ep in entry_points(group="gallia_plugins"):
        plugin = plugin_ep.load()

        if not issubclass(plugin, Plugin):
            raise TypeError(
                f"{plugin.__name__} from {plugin_ep.name} is not derived from {Plugin.__name__}"
            )

        plugins.append(plugin)

    return tuple(plugins)


def load_plugins() -> tuple[type[Plugin], ...]:
    """Loads all plugin classes registered via the ``gallia_plugins`` entry_points.

    The result is cached; plugin modules are imported once per process.
    """
    return _load_plugins()


def load_transports() -> list[type[BaseTransport]]:
    transports = []

    for plugin in load_plugins():
        transports.extend(plugin.transports())

    return transports


def load_transport(target: TargetURI) -> BaseTransport:
    """Selects a transport class depending on a TargetURI.
    The lookup is performed in builtin transports and all
    classes behind the ``gallia_transports`` entry_point.
    """
    for plugin in load_plugins():
        for transport in plugin.transports():
            if target.scheme == transport.SCHEME:
                return transport(target)

    raise ValueError(f"no transport for {target}")


def load_ecus() -> list[type[ECU]]:
    ecus = []

    for plugin in load_plugins():
        ecus.extend(plugin.ecus())

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
    c1: MutableMapping[str, CommandTree | Command],
    c2: Mapping[str, CommandTree | Command],
) -> None:
    for key, value in c2.items():
        if key not in c1:
            c1[key] = value
        elif isinstance(value, CommandTree) and isinstance(cmd := c1[key], CommandTree):
            try:
                _merge_command_trees(cmd, value)
            except ValueError as e:
                raise ValueError(f"{key} {e!s}") from e
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


def load_commands() -> MutableMapping[str, CommandTree | Command]:
    plugins = load_plugins()
    commands: MutableMapping[str, CommandTree | Command] = {}

    for plugin in plugins:
        try:
            _merge_commands(commands, plugin.commands())
        except ValueError as e:
            raise ValueError(
                f'Plugin "{plugin.name()}" conflicts with other plugins on command [ {e!s}'
            ) from None

    return commands
