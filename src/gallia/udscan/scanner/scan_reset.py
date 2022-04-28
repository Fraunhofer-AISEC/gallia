import asyncio
import reprlib
import sys
from argparse import Namespace
from typing import Any

from gallia.uds.core.exception import UnexpectedNegativeResponse
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.exception import IllegalResponse
from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.uds.helpers import suggests_sub_function_not_supported
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import (
    auto_int,
    check_and_set_session,
    find_sessions,
    ParseSkips,
)


class ScanReset(UDSScanner):
    """cmd_scan_reset"""

    def add_parser(self) -> None:
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
        l_ok: dict[int, list[int]] = dict()
        l_timeout: dict[int, list[int]] = dict()
        l_error: dict[int, list[Any]] = dict()

        if args.sessions is None:
            self.logger.log_info("No sessions specified, starting with session scan")
            # Only until 0x80 because the eight bit is "SuppressResponse"
            sessions = list(
                s
                for s in range(1, 0x80)
                if s not in args.skip or args.skip[s] is not None
            )
            sessions = await find_sessions(self.ecu, sessions)
            self.logger.log_summary(
                f'Found {len(sessions)} sessions: {" ".join([hex(i) for i in sessions])}'
            )
        else:
            sessions = list(
                s
                for s in args.sessions
                if s not in args.skip or args.skip[s] is not None
            )

        self.logger.log_info(f"testing sessions {sessions}")
        self.logger.log_info(f"skipping identifiers {reprlib.repr(args.skip)}")

        for session in sessions:  # pylint: disable=too-many-nested-blocks
            self.logger.log_notice(f"Switching to session 0x{session:02x}")
            resp: UDSResponse = await self.ecu.set_session(session)
            if isinstance(resp, NegativeResponse):
                self.logger.log_warning(
                    f"Switching to session 0x{session:02x} failed: {resp}"
                )
                continue

            self.logger.log_summary(f"Scanning in session: 0x{session:02x}")
            l_ok[session] = list()
            l_timeout[session] = list()
            l_error[session] = list()

            for sub_func in range(0x01, 0x80):
                if session in args.skip and sub_func in args.skip[session]:
                    self.logger.log_notice(
                        f"skipping subFunc: 0x{sub_func:02x} because of --skip"
                    )
                    continue

                if not args.skip_check_session:
                    # Check session and try to recover from wrong session (max 3 times), else skip session
                    if not await check_and_set_session(self.ecu, session):
                        self.logger.log_error(
                            f"Aborting scan on session 0x{session:02x}; current sub-func was 0x{sub_func:02x}"
                        )
                        break

                try:
                    try:
                        resp = await self.ecu.ecu_reset(
                            sub_func, config=UDSRequestConfig(tags=["ANALYZE"])
                        )
                        if isinstance(resp, NegativeResponse):
                            if suggests_sub_function_not_supported(resp):
                                self.logger.log_info(f"0x{sub_func:02x}: {resp}")
                            else:
                                l_error[session].append({sub_func: resp.response_code})
                                msg = f"0x{sub_func:02x}: with error code: {resp}"
                                self.logger.log_summary(msg)
                            continue
                    except IllegalResponse as e:
                        self.logger.log_warning(f"{repr(e)}")

                    self.logger.log_summary(f"0x{sub_func:02x}: reset level found!")
                    l_ok[session].append(sub_func)
                    self.logger.log_info("Waiting for the ECU to recover…")
                    await self.ecu.wait_for_ecu()

                    self.logger.log_info("Reboot ECU to restore default conditions")
                    resp = await self.ecu.ecu_reset(0x01)
                    if isinstance(resp, NegativeResponse):
                        self.logger.log_warning(
                            f"Could not reboot ECU after testing reset level 0x{sub_func:02x}"
                        )
                    else:
                        await self.ecu.wait_for_ecu()

                except asyncio.TimeoutError:
                    self.logger.log_error(
                        f"ECU did not respond after reset level 0x{sub_func:02x}; exiting…"
                    )
                    sys.exit(1)
                except ConnectionError:
                    msg = f"0x{sub_func:02x}: lost connection to ECU (post), current session: 0x{session:0x}"
                    self.logger.log_warning(msg)
                    await self.ecu.reconnect()
                    continue

                # We reach this code only for positive responses
                if not args.skip_check_session:
                    try:
                        current_session = await self.ecu.read_session()
                        self.logger.log_summary(
                            f"0x{sub_func:02x}: Currently in session 0x{current_session:02x}, should be 0x{session:02x}"
                        )
                    except UnexpectedNegativeResponse as e:
                        self.logger.log_warning(
                            f"Could not read current session: {e.RESPONSE_CODE.name}"
                        )

                self.logger.log_info(f"Setting session 0x{session:02x}")
                await self.ecu.set_session(session)

            await self.ecu.leave_session(session)

        self.logger.log_summary(f"ok: {l_ok}")
        self.logger.log_summary(f"timeout: {l_timeout}")
        self.logger.log_summary(f"with error: {l_error}")
