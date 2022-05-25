import asyncio

from gallia.uds.core import service
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.exception import UnexpectedNegativeResponse
from gallia.uds.ecu import ECU
from gallia.uds.helpers import suggests_identifier_not_supported
from gallia.utils import g_repr


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
