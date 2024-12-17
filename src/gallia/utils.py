# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import contextvars
import importlib.util
import logging
import re
import sys
from collections.abc import Awaitable, Callable
from functools import wraps
from pathlib import Path
from types import ModuleType
from typing import TYPE_CHECKING, Any

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


async def catch_and_log_exception[T](
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
    with path.open("w") as f:
        for target in targets:
            f.write(f"{target}\n")

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


def get_log_level(args: Any) -> Loglevel:
    level = Loglevel.INFO
    if hasattr(args, "verbose"):
        if args.verbose == 1:
            level = Loglevel.DEBUG
        elif args.verbose >= 2:
            level = Loglevel.TRACE
    return level


def get_file_log_level(args: Any) -> Loglevel:
    level = Loglevel.DEBUG
    if hasattr(args, "trace_log"):
        if args.trace_log:
            level = Loglevel.TRACE
    elif hasattr(args, "verbose"):
        if args.verbose >= 2:
            level = Loglevel.TRACE
    return level


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


def supports_platform[T, **P](*platform: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    def decorator(function: Callable[P, T]) -> Callable[P, T]:
        @wraps(function)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            supported = False
            for p in platform:
                if sys.platform == p:
                    supported = True
                    break
            if supported is False:
                raise NotImplementedError(
                    f'`{function.__name__}()` is not supported on: "{sys.platform}"'
                )

            return function(*args, **kwargs)

        return wrapper

    return decorator
