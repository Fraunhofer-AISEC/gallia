import asyncio
from argparse import Action, ArgumentError, ArgumentParser, Namespace
from pathlib import Path
from sys import stdout
from typing import Any, Callable, Optional, Sequence, Union
from urllib.parse import ParseResult, urlencode

import aiofiles

from gallia.db.db_handler import DBHandler
from gallia.penlog import Logger
from gallia.uds.core import service
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.exception import UnexpectedNegativeResponse
from gallia.uds.ecu import ECU
from gallia.uds.helpers import suggests_identifier_not_supported
from gallia.utils import g_repr


def auto_int(arg: str) -> int:
    return int(arg, 0)


async def check_and_set_session(
    ecu: ECU, expected_session: int, retries: int = 3
) -> bool:  # pylint: disable=R0911
    """check_and_set_session() reads the current session and (re)tries to set
    the session to the expected session if they do not match.

    Returns True if the current session matches the expected session,
    or if read_session is not supported by the ECU or in the current session."""

    ecu.logger.log_debug(
        f"Checking current session, expecting {g_repr(expected_session)}"
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

    ecu.logger.log_debug(f"Current session is {g_repr(current_session)}")
    if current_session == expected_session:
        return True

    for i in range(retries):
        ecu.logger.log_warning(
            f"Not in session {g_repr(expected_session)}, ECU replied with {g_repr(current_session)}"
        )

        ecu.logger.log_info(
            f"Switching to session {g_repr(expected_session)}; attempt {i + 1} of {retries}"
        )
        resp = await ecu.set_session(expected_session)

        if isinstance(resp, service.NegativeResponse):
            ecu.logger.log_warning(
                f"Switching to session {g_repr(expected_session)} failed: {resp}"
            )

        try:
            current_session = await ecu.read_session(
                config=UDSRequestConfig(max_retry=retries)
            )
            ecu.logger.log_debug(f"Current session is {g_repr(current_session)}")
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
        f"Failed to switch to session {g_repr(expected_session)} after {retries} attempts"
    )
    return False


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
        logger.log_error(f"func {func.__name__} failed: {g_repr(e)}")
