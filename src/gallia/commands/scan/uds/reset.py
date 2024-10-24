# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import reprlib
import sys
from typing import Any

from gallia.command import UDSScanner
from gallia.command.config import Field, Ranges, Ranges2D
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequestConfig, UDSResponse
from gallia.services.uds.core.exception import IllegalResponse, UnexpectedNegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.services.uds.helpers import suggests_sub_function_not_supported

logger = get_logger(__name__)


class ResetScannerConfig(UDSScannerConfig):
    sessions: Ranges | None = Field(
        None, description="Set list of sessions to be tested; all if None"
    )
    skip: Ranges2D = Field(
        {},
        metavar="SESSION_ID:ID",
        description="The sub functions to be skipped per session.\nA session specific skip is given by <session_id>:<sub_functions>\nwhere <sub_functions> is a comma separated list of single ids or id ranges using a dash.\nExamples:\n - 0x01:0xf3\n - 0x10-0x2f\n - 0x01:0xf3,0x10-0x2f\nMultiple session specific skips are separated by space.\nOnly takes affect if --sessions is given.\n",
    )
    skip_check_session: bool = Field(
        False, description="skip check current session; only takes affect if --sessions is given"
    )


class ResetScanner(UDSScanner):
    """Scan ecu_reset"""

    CONFIG_TYPE = ResetScannerConfig
    SHORT_HELP = "identifier scan in ECUReset"

    def __init__(self, config: ResetScannerConfig):
        super().__init__(config)
        self.config: ResetScannerConfig = config

    async def main(self) -> None:
        if self.config.sessions is None:
            await self.perform_scan()
        else:
            sessions = self.config.sessions
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(self.config.skip)}")

            for session in sessions:
                logger.notice(f"Switching to session {g_repr(session)}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"Switching to session {g_repr(session)} failed: {resp}")
                    continue

                logger.result(f"Scanning in session: {g_repr(session)}")
                await self.perform_scan(session)

                await self.ecu.leave_session(session, sleep=self.config.power_cycle_sleep)

    async def perform_scan(self, session: None | int = None) -> None:
        l_ok: list[int] = []
        l_timeout: list[int] = []
        l_error: list[Any] = []

        for sub_func in range(0x01, 0x80):
            if session in self.config.skip and (
                (session_skip := self.config.skip[session]) is None or sub_func in session_skip
            ):
                logger.notice(f"skipping subFunc: {g_repr(sub_func)} because of --skip")
                continue

            if session is not None and (not self.config.skip_check_session):
                # Check session and try to recover from wrong session (max 3 times), else skip session
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current sub-func was {g_repr(sub_func)}"
                    )
                    break

            try:
                try:
                    resp = await self.ecu.ecu_reset(
                        sub_func, config=UDSRequestConfig(tags=["ANALYZE"])
                    )
                    if isinstance(resp, NegativeResponse):
                        if suggests_sub_function_not_supported(resp):
                            logger.info(f"{g_repr(sub_func)}: {resp}")
                        else:
                            l_error.append({sub_func: resp.response_code})
                            msg = f"{g_repr(sub_func)}: with error code: {resp}"
                            logger.result(msg)
                        continue
                except IllegalResponse as e:
                    logger.warning(f"{g_repr(e)}")

                logger.result(f"{g_repr(sub_func)}: reset level found!")
                l_ok.append(sub_func)
                logger.info("Waiting for the ECU to recover…")
                await self.ecu.wait_for_ecu()

                logger.info("Reboot ECU to restore default conditions")
                resp = await self.ecu.ecu_reset(0x01)
                if isinstance(resp, NegativeResponse):
                    logger.warning(
                        f"Could not reboot ECU after testing reset level {g_repr(sub_func)}"
                    )
                else:
                    await self.ecu.wait_for_ecu()

            except TimeoutError:
                l_timeout.append(sub_func)
                if not self.config.power_cycle:
                    logger.error(f"ECU did not respond after reset level {g_repr(sub_func)}; exit")
                    sys.exit(1)

                logger.warning(
                    f"ECU did not respond after reset level {g_repr(sub_func)}; try power cycle…"
                )
                try:
                    await self.ecu.power_cycle(self.config.power_cycle_sleep)
                    await self.ecu.wait_for_ecu()
                except (TimeoutError, ConnectionError) as e:
                    logger.error(f"Failed to recover ECU: {g_repr(e)}; exit")
                    sys.exit(1)
            except ConnectionError:
                msg = f"{g_repr(sub_func)}: lost connection to ECU (post), current session: {g_repr(session)}"
                logger.warning(msg)
                await self.ecu.reconnect()
                continue

            # We reach this code only for positive responses
            if session is not None and (not self.config.skip_check_session):
                try:
                    current_session = await self.ecu.read_session()
                    logger.info(
                        f"{g_repr(sub_func)}: Currently in session {g_repr(current_session)}, "
                        f"should be {g_repr(session)}"
                    )
                except UnexpectedNegativeResponse as e:
                    logger.warning(f"Could not read current session: {e.RESPONSE_CODE.name}")

            if session is not None:
                logger.info(f"Setting session {g_repr(session)}")
                await self.ecu.set_session(session)

        logger.result(f"ok: {l_ok}")
        logger.result(f"timeout: {l_timeout}")
        logger.result(f"with error: {l_error}")
