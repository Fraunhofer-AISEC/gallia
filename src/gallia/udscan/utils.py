import asyncio
from argparse import Namespace, Action, ArgumentError, ArgumentParser
from subprocess import run
from sys import stdout
from pathlib import Path
from urllib.parse import urlencode, ParseResult
from typing import Any, Callable, Optional, Union, Sequence

import aiofiles

from gallia.db.db_handler import DBHandler
from gallia.uds.ecu import ECU
from gallia.penlog import Logger
from gallia.uds.core.exception import UnexpectedNegativeResponse
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.helpers import suggests_identifier_not_supported
from gallia.uds.core import service


def auto_int(arg: str) -> int:
    return int(arg, 0)


async def poll_service(
    ecu: ECU, sid: int, check: Optional[int] = None
) -> Union[service.NegativeResponse, service.PositiveResponse]:
    if check:
        cur_session = await ecu.read_session()
        if cur_session != check:
            ecu.logger.log_warning("ecu lost session")
            ecu.logger.log_warning(f"expected: {check:x}; read: {cur_session:x}")
            await ecu.set_session(check)

    resp = await ecu.send_raw(bytes([sid]))

    if check:
        cur_session = await ecu.read_session()
        if cur_session != check:
            await ecu.set_session(check)
            ecu.logger.log_warning(f"expected: {check:x}; read: {cur_session:x}")
    return resp


async def find_sessions(ecu: ECU, search: list, max_retry: int = 4) -> list[int]:
    sessions = []
    for sid in search:
        try:
            resp = await ecu.set_session(
                sid, config=UDSRequestConfig(max_retry=max_retry)
            )
            if isinstance(resp, service.NegativeResponse):
                continue
        except Exception:
            continue
        sessions.append(sid)
        await ecu.leave_session(sid)
    return sessions


async def check_and_set_session(
    ecu: ECU, expected_session: int, retries: int = 3
) -> bool:  # pylint: disable=R0911
    """check_and_set_session() reads the current session and (re)tries to set
    the session to the expected session if they do not match.

    Returns True if the current session matches the expected session,
    or if read_session is not supported by the ECU or in the current session."""

    ecu.logger.log_debug(
        f"Checking current session, expecting 0x{expected_session:02x}"
    )

    try:
        current_session = await ecu.read_session(
            config=UDSRequestConfig(max_retry=retries)
        )
    except UnexpectedNegativeResponse as e:
        if suggests_identifier_not_supported(e.RESPONSE_CODE):
            ecu.logger.log_info(
                f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
            )
            return True
        raise e
    except asyncio.TimeoutError:
        ecu.logger.log_warning(
            "Reading current session timed out, skipping check_session"
        )
        return True

    ecu.logger.log_debug(f"Current session is 0x{current_session:02x}")
    if current_session == expected_session:
        return True

    for i in range(retries):
        ecu.logger.log_warning(
            f"Not in session 0x{expected_session:02x}, ECU replied with 0x{current_session:02x}"
        )

        ecu.logger.log_info(
            f"Switching to session 0x{expected_session:02x}; attempt {i + 1} of {retries}"
        )
        resp = await ecu.set_session(expected_session)

        if isinstance(resp, service.NegativeResponse):
            ecu.logger.log_warning(
                f"Switching to session 0x{expected_session:02x} failed: {resp}"
            )

        try:
            current_session = await ecu.read_session(
                config=UDSRequestConfig(max_retry=retries)
            )
            ecu.logger.log_debug(f"Current session is 0x{current_session:02x}")
            if current_session == expected_session:
                return True
        except UnexpectedNegativeResponse as e:
            if suggests_identifier_not_supported(e.RESPONSE_CODE):
                ecu.logger.log_info(
                    f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                )
                return True
            raise e
        except asyncio.TimeoutError:
            ecu.logger.log_warning(
                "Reading current session timed out, skipping check_session"
            )
            return True

    ecu.logger.log_warning(
        f"Failed to switch to session 0x{expected_session:02x} after {retries} attempts"
    )
    return False


def get_command_output(command: list[str]) -> str:
    """get_command_output runs the command given as a list and returns a string
    of the corresponding output from STDOUT. If any error occurs, the error
    string is returned instead.

    :param command: A list of strings without whitespace which specify the command
    :return: A string of the command's output from STDOUT, or an error string"""
    try:
        process = run(command, capture_output=True, check=True)
    except Exception as e:
        return f"Error: {e}"

    return process.stdout.decode().strip()


def unravel(listing: str) -> list[int]:
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
                        session_ids = unravel(session_skips)

                        for session_id in session_ids:
                            skip_sids[session_id] = None
                    else:
                        session_ids_tmp, identifier_ids_tmp = session_skips.split(":")
                        session_ids = unravel(session_ids_tmp)
                        identifier_ids = unravel(identifier_ids_tmp)

                        for session_id in session_ids:
                            if session_id not in skip_sids:
                                skip_sids[session_id] = []

                            session_skips = skip_sids[session_id]

                            if session_skips is not None:
                                session_skips += identifier_ids

            setattr(namespace, self.dest, skip_sids)
        except Exception as e:
            raise ArgumentError(self, "The argument is malformed!") from e


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


def range_diff(base: list[range], coverage: list[range]) -> list[range]:
    """This function computes ranges of the base, that are not contained
    in the coverage.

    The main idea of this algorithm is to go through each range of the base and to iteratively shrink it by
    removing the ranges in the coverage. What's left is then the uncovered area.
    There are in principle five cases which are considered for a pair of ranges:

    - One or both are empty
    - They are disjoint
      -> In both cases nothing is removed from the base range
    - The base range is a subrange of the coverage range
      -> The base range becomes empty
    - The coverage range reaches into base range
      -> The base range gets smaller
    - The coverage range is a subrange of the base range
      -> The base range is split into two smaller ranges

    :param base: The base ranges.
    :param coverage: The coverage ranges.
    :return: The (sub-)ranges of the base ranges that are not covered by the coverage ranges.
    """
    result: list[range] = []
    sorted_base = sorted(base, key=lambda r: r[0])
    i = 0

    # We are looping with a while statement, because we may insert new elements into the list
    while i < len(sorted_base):
        base_r = sorted_base[i]

        for cover_r in sorted(coverage, key=lambda r: r[0]):
            # None is empty and they are not disjoint
            if not (
                len(base_r) == 0
                or len(cover_r) == 0
                or cover_r[-1] < base_r[0]
                or cover_r[0] > base_r[-1]
            ):
                # The base range is a subrange of the coverage range
                if cover_r[0] <= base_r[0] and cover_r[-1] >= base_r[-1]:
                    base_r = range(0)
                # The coverage range reaches into base range from the left
                elif cover_r[0] <= base_r[0]:
                    base_r = range(cover_r[-1] + 1, base_r[-1] + 1)
                # The coverage range reaches into base range from the right
                elif cover_r[-1] >= base_r[-1]:
                    base_r = range(base_r[0], cover_r[0])
                # The coverage range is a subrange of the base range
                # In this case the base range is divided by the coverage range into two ranges.
                # The first of them will take the place of the current base range and the second will be handled
                # separately in another iteration.
                else:
                    sorted_base.insert(i + 1, range(cover_r[-1] + 1, base_r[-1] + 1))
                    base_r = range(base_r[0], cover_r[0])

        # If an uncovered range is left after all elements of the coverage have been removed from the base range
        if len(base_r) > 0:
            result.append(base_r)

        i += 1

    return result


async def write_ecu_url_list(
    ecus_file: Path,
    ecus: list[tuple[ParseResult, dict[str, Any]]],
    db_handler: Optional[DBHandler] = None,
) -> list[str]:
    """Write a list of ECU connection strings (urls) into file

    :param ecus_file: output file
    :param ecus: list of ECUs with ECU specific url and params as dict
    :params db_handler: if given, urls are also written to the database as discovery results
    :return: None
    """
    urls: list[str] = list()
    async with aiofiles.open(ecus_file, "w") as file:
        for url, ecu in ecus:
            url_result = f"{url.scheme}://{url.netloc}?{urlencode(ecu)}"
            urls.append(url_result)
            await file.write(f"{url_result}\n")

            if db_handler is not None:
                await db_handler.insert_discovery_result(url_result)
    return urls


async def catch_and_log_exception(
    logger: Logger, func: Callable, *args: Any, **kwargs: Any
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
