# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import reprlib
import sys
from argparse import Namespace
from typing import Any

from gallia.command import UDSScanner
from gallia.services.uds import NegativeResponse, UDSRequestConfig, UDSResponse
from gallia.services.uds.core.exception import (
    IllegalResponse,
    UnexpectedNegativeResponse,
)
from gallia.services.uds.core.utils import g_repr
from gallia.services.uds.helpers import suggests_sub_function_not_supported
from gallia.utils import ParseSkips, auto_int


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
            help="""
                 The sub functions to be skipped per session.
                 A session specific skip is given by <session_id>:<sub_functions>
                 where <sub_functions> is a comma separated list of single ids or id ranges using a dash.
                 Examples:
                  - 0x01:0xf3
                  - 0x10-0x2f
                  - 0x01:0xf3,0x10-0x2f
                 Multiple session specific skips are separated by space.
                 """,
        )
        self.parser.add_argument(
            "--skip-check-session",
            action="store_true",
            help="skip check current session",
        )

    async def main(self, args: Namespace) -> None:
        l_ok: dict[int, list[int]] = {}
        l_timeout: dict[int, list[int]] = {}
        l_error: dict[int, list[Any]] = {}

        if args.sessions is None:
            self.logger.info("No sessions specified, starting with session scan")
            # Only until 0x80 because the eight bit is "SuppressResponse"
            sessions = list(
                s
                for s in range(1, 0x80)
                if s not in args.skip or args.skip[s] is not None
            )
            sessions = await self.ecu.find_sessions(sessions)
            self.logger.result(f"Found {len(sessions)} sessions: {g_repr(sessions)}")
        else:
            sessions = list(
                s
                for s in args.sessions
                if s not in args.skip or args.skip[s] is not None
            )

        self.logger.info(f"testing sessions {g_repr(sessions)}")

        # TODO: Unified shortened output necessary here
        self.logger.info(f"skipping identifiers {reprlib.repr(args.skip)}")

        for session in sessions:  # pylint: disable=too-many-nested-blocks
            self.logger.notice(f"Switching to session {g_repr(session)}")
            resp: UDSResponse = await self.ecu.set_session(session)
            if isinstance(resp, NegativeResponse):
                self.logger.warning(
                    f"Switching to session {g_repr(session)} failed: {resp}"
                )
                continue

            self.logger.result(f"Scanning in session: {g_repr(session)}")
            l_ok[session] = []
            l_timeout[session] = []
            l_error[session] = []

            for sub_func in range(0x01, 0x80):
                if session in args.skip and sub_func in args.skip[session]:
                    self.logger.notice(
                        f"skipping subFunc: {g_repr(sub_func)} because of --skip"
                    )
                    continue

                if not args.skip_check_session:
                    # Check session and try to recover from wrong session (max 3 times), else skip session
                    if not await self.ecu.check_and_set_session(session):
                        self.logger.error(
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
                                self.logger.info(f"{g_repr(sub_func)}: {resp}")
                            else:
                                l_error[session].append({sub_func: resp.response_code})
                                msg = f"{g_repr(sub_func)}: with error code: {resp}"
                                self.logger.result(msg)
                            continue
                    except IllegalResponse as e:
                        self.logger.warning(f"{g_repr(e)}")

                    self.logger.result(f"{g_repr(sub_func)}: reset level found!")
                    l_ok[session].append(sub_func)
                    self.logger.info("Waiting for the ECU to recover…")
                    await self.ecu.wait_for_ecu()

                    self.logger.info("Reboot ECU to restore default conditions")
                    resp = await self.ecu.ecu_reset(0x01)
                    if isinstance(resp, NegativeResponse):
                        self.logger.warning(
                            f"Could not reboot ECU after testing reset level {g_repr(sub_func)}"
                        )
                    else:
                        await self.ecu.wait_for_ecu()

                except asyncio.TimeoutError:
                    self.logger.error(
                        f"ECU did not respond after reset level {g_repr(sub_func)}; exiting…"
                    )
                    sys.exit(1)
                except ConnectionError:
                    msg = f"{g_repr(sub_func)}: lost connection to ECU (post), current session: {g_repr(session)}"
                    self.logger.warning(msg)
                    await self.ecu.reconnect()
                    continue

                # We reach this code only for positive responses
                if not args.skip_check_session:
                    try:
                        current_session = await self.ecu.read_session()
                        self.logger.result(
                            f"{g_repr(sub_func)}: Currently in session {g_repr(current_session)}, "
                            f"should be {g_repr(session)}"
                        )
                    except UnexpectedNegativeResponse as e:
                        self.logger.warning(
                            f"Could not read current session: {e.RESPONSE_CODE.name}"
                        )

                self.logger.info(f"Setting session {g_repr(session)}")
                await self.ecu.set_session(session)

            await self.ecu.leave_session(session)

        self.logger.result(f"ok: {l_ok}")
        self.logger.result(f"timeout: {l_timeout}")
        self.logger.result(f"with error: {l_error}")
