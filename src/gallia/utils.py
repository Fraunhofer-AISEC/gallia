# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import ipaddress
import re
from argparse import Action, ArgumentError, ArgumentParser, Namespace
from enum import Enum
from pathlib import Path
from sys import stdout
from typing import TYPE_CHECKING, Any, Callable, Optional, Sequence, Union
from urllib.parse import urlparse

import aiofiles

from gallia.penlog import Logger
from gallia.uds.core.service import NegativeResponse
from gallia.uds.core.utils import bytes_repr, int_repr

if TYPE_CHECKING:
    from gallia.db.db_handler import DBHandler
    from gallia.transports.base import TargetURI


def auto_int(arg: str) -> int:
    return int(arg, 0)


def split_host_port(
    hostport: str,
    default_port: Optional[int] = None,
) -> tuple[str, Optional[int]]:
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
    # https://stackoverflow.com/a/12867228
    return re.sub(r"((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))", r"_\1", s).lower()


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


def g_repr(x: Any) -> str:
    """
    Object string representation with default gallia output settings.
    """
    if isinstance(x, Enum):
        return x.name
    if isinstance(x, bool):
        return repr(x)
    if isinstance(x, int):
        return int_repr(x)
    elif isinstance(x, str):
        return x
    elif isinstance(x, (bytes, bytearray)):
        return bytes_repr(x)
    elif isinstance(x, list):
        return f'[{", ".join(g_repr(y) for y in x)}]'
    elif isinstance(x, dict):
        return f'{{{", ".join(f"{g_repr(k)}: {g_repr(v)}" for k, v in x.items())}}}'
    elif isinstance(x, NegativeResponse):
        return str(x)
    else:
        return repr(x)


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
        values: Union[str, Sequence[Any], None],
        option_string: str = None,
    ) -> None:
        skip_sids: dict[int, Optional[list[int]]] = {}

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

                        for session_id in session_ids:
                            if session_id not in skip_sids:
                                skip_sids[session_id] = []

                            session_skips = skip_sids[session_id]

                            if session_skips is not None:
                                session_skips += identifier_ids

            setattr(namespace, self.dest, skip_sids)
        except Exception as e:
            raise ArgumentError(self, "The argument is malformed!") from e


async def catch_and_log_exception(
    logger: Logger,
    func: Callable,
    *args: Any,
    **kwargs: Any,
) -> None:
    """Runs an async function. If an exception is raised,
    it will be logged via logger.

    :param logger: an instance of gallia.penlog.Logger
    :param func: a async function object which will be awaited
    :return: None
    """
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.log_error(f"func {func.__name__} failed: {repr(e)}")


class ANSIEscapes:
    if stdout.isatty():
        BOLD = "\033[1m"
        ITALIC = "\033[3m"
        UNDERSCORE = "\033[4m"
        BLINK = "\033[5m"
        CROSSED = "\033[9m"

        BLACK = "\033[90m"
        RED = "\033[91m"
        GREEN = "\033[92m"
        YELLOW = "\033[93m"
        BLUE = "\033[94m"
        MAGENTA = "\033[95m"
        CYAN = "\033[96m"
        WHITE = "\033[97m"

        RESET = "\033[0m"
    else:
        BOLD = ITALIC = UNDERSCORE = BLINK = CROSSED = ""
        BLACK = RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = ""


async def write_target_list(
    path: Path,
    targets: list["TargetURI"],
    db_handler: Optional["DBHandler"] = None,
) -> None:
    """Write a list of ECU connection strings (urls) into file

    :param path: output file
    :param targets: list of ECUs with ECU specific url and params as dict
    :params db_handler: if given, urls are also written to the database as discovery results
    :return: None
    """
    urls = []
    async with aiofiles.open(path, "w") as f:
        for target in targets:
            urls.append(str(target))
            await f.write(f"{target}\n")

            if db_handler is not None:
                await db_handler.insert_discovery_result(str(target))
