# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import contextvars
import importlib.util
import ipaddress
import json
import logging
import re
import subprocess
import sys
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any, TypeVar
from urllib.parse import urlparse

import aiofiles
import pydantic
from pydantic.networks import IPvAnyAddress

from gallia.log import get_logger

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


def unravel(listing: str) -> list[int]:
    """
    Parses a string representing a one-dimensional list of ranges into an equivalent python data structure.

    Ranges are delimited by hyphens ('-').
    Enumerations are delimited by commas (',').

    Ranges are allowed to overlap and are merged.
    Ranges are always unraveled, which could lead to high memory consumption for distant limits.

    Example: 0,10,8-11
    This would result in [0,8,9,10,11].

    :param listing: The string representation of the one-dimensional list of ranges.
    :return: A list of numbers.
    """

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


def unravel_2d(listing: str) -> dict[int, list[int] | None]:
    """
    Parses a string representing a two-dimensional list of ranges into an equivalent python data structure.

    The outer dimension entries are separated by spaces (' ').
    Inner dimension ranges and outer dimension ranges are separated by colons (':').
    Ranges in both dimensions are delimited by hyphens ('-').
    Enumerations in both dimensions are delimited by commas (',').

    Ranges are allowed to overlap and are merged.
    Ranges are always unraveled, which could lead to high memory consumption for distant limits.
    If a range with only outer dimensions is given, this will result in None for the inner list and overrides other values.

    Example: "1:1,2  1-3:0,2-4  3"
    This would result in {1: [0,1,2,3,4], 2: [0,2,3,4], 3: None}.

    :param listing: The string representation of the two-dimensional list of ranges.
    :return: A mapping of numbers in the outer dimension to numbers in the inner dimension.
    """

    listing_delimiter = " "
    level_delimiter = ":"

    unsorted_result: dict[int, set[int] | None] = {}

    for range_element in listing.split(listing_delimiter):
        if level_delimiter in range_element:
            first_tmp, second_tmp = range_element.split(level_delimiter)
            first = unravel(first_tmp)
            second = unravel(second_tmp)

            for x in first:
                if x not in unsorted_result:
                    unsorted_result[x] = set()

                if (ur := unsorted_result[x]) is not None:
                    for y in second:
                        ur.add(y)
        else:
            first = unravel(range_element)

            for x in first:
                unsorted_result[x] = None

    return {
        x: None if (ur := unsorted_result[x]) is None else sorted(ur)
        for x in sorted(unsorted_result)
    }


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
        logging.error(f"func {func.__name__} failed: {repr(e)}")
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
        raise ImportError

    loader = importlib.util.LazyLoader(spec.loader)
    spec.loader = loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


# TODO: (Re)move these functions
def dump_args(args: Any) -> dict[str, str | int | float]:
    settings = {}
    for key, value in args.__dict__.items():
        match value:
            case str() | int() | float():
                settings[key] = value

    return settings


CONTEXT_SHARED_VARIABLE = "logger_name"
context: contextvars.ContextVar[tuple[str, str | None]] = contextvars.ContextVar(
    CONTEXT_SHARED_VARIABLE
)


def set_task_handler_ctx_variable(
    logger_name: str,
    task_name: str | None = None,
) -> contextvars.Context:
    ctx = contextvars.copy_context()
    ctx.run(context.set, (logger_name, task_name))
    return ctx


def handle_task_error(fut: asyncio.Future[Any]) -> None:
    logger_name, task_name = context.get((__name__, "Task"))
    logger = get_logger(logger_name)
    if logger.name is __name__:
        logger.warning(f"BUG: {fut} had no context '{CONTEXT_SHARED_VARIABLE}' set")
        logger.warning("BUG: please fix this to ensure the task name is logged correctly")

    try:
        fut.result()
    except BaseException as e:
        task_name = task_name if task_name is not None else "Task"

        # Info level is enough, since our aim is only to consume the stack trace
        logger.info(f"{task_name} ended with error: {e!r}")


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

    try:
        p = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, check=True)
    except FileNotFoundError as e:
        logger.warning(f"Could not query information about interfaces: {e}")
        return []

    try:
        return [Interface(**item) for item in json.loads(p.stdout.decode())]
    except pydantic.ValidationError as e:
        logger.error("BUG: A special case for `ip -j address show` is not handled!")
        logger.error("Please report a bug including the following json string.")
        logger.error("https://github.com/Fraunhofer-AISEC/gallia/issues")
        logger.error(e.json())
        raise


def net_if_broadcast_addrs() -> list[AddrInfo]:
    out = []
    for iface in net_if_addrs():
        if not (iface.is_up() and iface.can_broadcast()):
            continue

        for addr in iface.addr_info:
            # We only work with broadcastable IPv4.
            if not addr.is_v4() or addr.broadcast is None:
                continue
            out.append(addr)
    return out
