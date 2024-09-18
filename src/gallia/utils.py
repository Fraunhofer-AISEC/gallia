# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import ipaddress
import json
import re
import subprocess
import sys
from argparse import Action, ArgumentError, ArgumentParser, Namespace
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlparse

import aiofiles
import pydantic
from pydantic.networks import IPvAnyAddress

from gallia.log import Loglevel, get_logger

if TYPE_CHECKING:
    from gallia.db.handler import DBHandler
    from gallia.transports import TargetURI


logger = get_logger(__name__)


def auto_int(arg: str) -> int:
    return int(arg, 0)


def strtobool(val: str) -> bool:
    val = val.lower()
    match val:
        case "y" | "yes" | "t" | "true" | "on" | "1":
            return True
        case "n" | "no" | "f" | "false" | "off" | "0":
            return False
        case _:
            raise ValueError(f"invalid truth value {val!r}")


def split_host_port(
    hostport: str,
    default_port: int | None = None,
) -> tuple[str, int | None]:
    """Splits a combination of ip address/hostname + port into hostname/ip address
    and port.  The default_port argument can be used to return a port if it is
    absent in the hostport argument."""
    # Special case: If hostport is an ipv6 then the urlparser does some weird
    # things with the colons and tries to parse ports. Catch this case early.
    host = ""
    port = default_port
    try:
        # If hostport is a valid ip address (v4 or v6) there
        # is no port included
        host = str(ipaddress.ip_address(hostport))
    except ValueError:
        pass

    # Only parse if hostport is not a valid ip address.
    if host == "":
        # urlparse() and urlsplit() insists on absolute URLs starting with "//".
        url = urlparse(f"//{hostport}")
        host = url.hostname if url.hostname else url.netloc
        port = url.port if url.port else default_port
    return host, port


def join_host_port(host: str, port: int) -> str:
    if ":" in host:
        return f"[{host}]:port"
    return f"{host}:{port}"


def camel_to_snake(s: str) -> str:
    """Convert a CamelCase string to a snake_case string."""
    # https://stackoverflow.com/a/1176023
    s = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", s)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s).lower()


def camel_to_dash(s: str) -> str:
    """Convert a CamelCase string to a dash-case string."""
    return camel_to_snake(s).replace("_", "-")


def isotp_addr_repr(a: int) -> str:
    """
    Default string representation of a CAN id.
    """
    return f"{a:02x}"


def can_id_repr(i: int) -> str:
    """
    Default string representation of a CAN id.
    """
    return f"{i:03x}"


def _unravel(listing: str) -> list[int]:
    listing_delimiter = ","
    range_delimiter = "-"
    result = set()

    for range_element in listing.split(listing_delimiter):
        if range_delimiter in range_element:
            first_tmp, last_tmp = range_element.split(range_delimiter)
            first = auto_int(first_tmp)
            last = auto_int(last_tmp)

            for element in range(first, last + 1):
                result.add(element)
        else:
            element = auto_int(range_element)
            result.add(element)

    return sorted(result)


class ParseSkips(Action):
    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        values: str | Sequence[Any] | None,
        option_string: str | None = None,
    ) -> None:
        skip_sids: dict[int, list[int] | None] = {}

        try:
            if values is not None:
                for session_skips in values:
                    # Whole sessions can be skipped by only giving the session number without ids
                    if ":" not in session_skips:
                        session_ids = _unravel(session_skips)

                        for session_id in session_ids:
                            skip_sids[session_id] = None
                    else:
                        session_ids_tmp, identifier_ids_tmp = session_skips.split(":")
                        session_ids = _unravel(session_ids_tmp)
                        identifier_ids = _unravel(identifier_ids_tmp)
                        skips = session_skips

                        for session_id in session_ids:
                            if session_id not in skip_sids:
                                skip_sids[session_id] = []

                            skips = skip_sids[session_id]

                            if skips is not None:
                                skips += identifier_ids

            setattr(namespace, self.dest, skip_sids)
        except Exception as e:
            raise ArgumentError(self, "malformed argument") from e


T = TypeVar("T")


async def catch_and_log_exception(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    **kwargs: Any,
) -> T | None:
    """Runs an async function. If an exception is raised,
    it will be logged via logger.

    :param logger: an instance of gallia.penlog.Logger
    :param func: a async function object which will be awaited
    :return: None
    """
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.error(f"func {func.__name__} failed: {repr(e)}")
        return None


async def write_target_list(
    path: Path,
    targets: list[TargetURI],
    db_handler: DBHandler | None = None,
) -> None:
    """Write a list of ECU connection strings (urls) into file

    :param path: output file
    :param targets: list of ECUs with ECU specific url and params as dict
    :params db_handler: if given, urls are also written to the database as discovery results
    :return: None
    """
    async with aiofiles.open(path, "w") as f:
        for target in targets:
            await f.write(f"{target}\n")

            if db_handler is not None:
                await db_handler.insert_discovery_result(str(target))


def lazy_import(name: str) -> ModuleType:
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.find_spec(name)
    if spec is None or spec.loader is None:
        raise ImportError()

    loader = importlib.util.LazyLoader(spec.loader)
    spec.loader = loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def dump_args(args: Namespace) -> dict[str, str | int | float]:
    settings = {}
    for key, value in args.__dict__.items():
        match value:
            case str() | int() | float():
                settings[key] = value

    return settings


def get_log_level(args: Namespace) -> Loglevel:
    level = Loglevel.INFO
    if hasattr(args, "verbose"):
        if args.verbose == 1:
            level = Loglevel.DEBUG
        elif args.verbose >= 2:
            level = Loglevel.TRACE
    return level


def get_file_log_level(args: Namespace) -> Loglevel:
    level = Loglevel.DEBUG
    if hasattr(args, "trace_log"):
        if args.trace_log:
            level = Loglevel.TRACE
    elif hasattr(args, "verbose"):
        if args.verbose >= 2:
            level = Loglevel.TRACE
    return level


class AddrInfo(pydantic.BaseModel):
    family: str
    local: IPvAnyAddress
    prefixlen: int
    broadcast: IPvAnyAddress | None = None
    scope: str
    label: str | None = None
    valid_life_time: int
    preferred_life_time: int

    def is_v4(self) -> bool:
        return self.family == "inet"


class Interface(pydantic.BaseModel):
    ifindex: int
    ifname: str
    flags: list[str]
    mtu: int
    qdisc: str
    operstate: str
    group: str
    link_type: str
    address: str | None = None
    broadcast: str | None = None
    addr_info: list[AddrInfo]

    def is_up(self) -> bool:
        return self.operstate == "UP"

    def can_broadcast(self) -> bool:
        return "BROADCAST" in self.flags


def net_if_addrs() -> list[Interface]:
    if sys.platform != "linux":
        raise NotImplementedError("net_if_addrs() is only supported on Linux platforms")

    p = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, check=True)

    try:
        return [Interface(**item) for item in json.loads(p.stdout.decode())]
    except pydantic.ValidationError as e:
        logger.error("BUG: A special case for `ip -j address show` is not handled!")
        logger.error("Please report a bug including the following json string.")
        logger.error("https://github.com/Fraunhofer-AISEC/gallia/issues")
        logger.error(e.json())
        raise
