# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import reprlib
import sys
from argparse import Namespace
from typing import Any

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequestConfig, UDSResponse
from gallia.services.uds.core.exception import IllegalResponse, UnexpectedNegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.services.uds.helpers import suggests_sub_function_not_supported
from gallia.utils import ParseSkips, auto_int

logger = get_logger(__name__)


class ResetScanner(UDSScanner):
    """Scan ecu_reset"""

    SHORT_HELP = "identifier scan in ECUReset"
    COMMAND = "reset"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            type=auto_int,
            nargs="*",
            help="Set list of sessions to be tested; all if None",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="\n                 The sub functions to be skipped per session.\n                 A session specific skip is given by <session_id>:<sub_functions>\n                 where <sub_functions> is a comma separated list of single ids or id ranges using a dash.\n                 Examples:\n                  - 0x01:0xf3\n                  - 0x10-0x2f\n                  - 0x01:0xf3,0x10-0x2f\n                 Multiple session specific skips are separated by space.\n                 Only takes affect if --sessions is given.\n                 ",
        )
        self.parser.add_argument(
            "--skip-check-session",
            action="store_true",
            help="skip check current session; only takes affect if --sessions is given",
        )

    async def main(self, args: Namespace) -> None:
        if args.sessions is None:
            await self.perform_scan(args)
        else:
            sessions = args.sessions
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(args.skip)}")

            for session in sessions:
                logger.notice(f"Switching to session {g_repr(session)}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"Switching to session {g_repr(session)} failed: {resp}")
                    continue

                logger.result(f"Scanning in session: {g_repr(session)}")
                await self.perform_scan(args, session)

                await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)

    async def perform_scan(self, args: Namespace, session: None | int = None) -> None:
        l_ok: list[int] = []
        l_timeout: list[int] = []
        l_error: list[Any] = []

        for sub_func in range(0x01, 0x80):
            if session in args.skip and sub_func in args.skip[session]:
                logger.notice(f"skipping subFunc: {g_repr(sub_func)} because of --skip")
                continue

            if session is not None and (not args.skip_check_session):
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
                if not args.power_cycle:
                    logger.error(f"ECU did not respond after reset level {g_repr(sub_func)}; exit")
                    sys.exit(1)

                logger.warning(
                    f"ECU did not respond after reset level {g_repr(sub_func)}; try power cycle…"
                )
                try:
                    await self.ecu.power_cycle(args.power_cycle_sleep)
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
            if session is not None and (not args.skip_check_session):
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
