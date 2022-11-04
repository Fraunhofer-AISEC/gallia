# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import reprlib
from argparse import BooleanOptionalAction, Namespace
from binascii import unhexlify
from typing import Any

from gallia.command import UDSScanner
from gallia.services.uds import (
    NegativeResponse,
    UDSIsoServices,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.exception import UDSException
from gallia.services.uds.core.utils import g_repr
from gallia.services.uds.helpers import suggests_service_not_supported
from gallia.utils import ParseSkips, auto_int


class ServicesScanner(UDSScanner):
    """Iterate sessions and services and find endpoints"""

    COMMAND = "services"
    SHORT_HELP = "service scan on an ECU"
    EPILOG = (
        "https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#service-scan"
    )

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            nargs="*",
            type=auto_int,
            default=None,
            help="Set list of sessions to be tested; all if None",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="check current session",
        )
        self.parser.add_argument(
            "--scan-response-ids",
            default=False,
            action=BooleanOptionalAction,
            help="Do not scan reply flag in SID",
        )
        self.parser.add_argument(
            "--auto-reset",
            action="store_true",
            default=False,
            help="Reset ECU with UDS ECU Reset before every request",
        )
        self.parser.add_argument(
            "--payload",
            default=None,
            type=unhexlify,
            help="Payload which will be appended for each request as hex string",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="""
                 The service IDs to be skipped per session.
                 A session specific skip is given by <session id>:<service ids>
                 where <service ids> is a comma separated list of single ids or id ranges using a dash.
                 Examples:
                  - 0x01:0xf3
                  - 0x10-0x2f
                  - 0x01:0xf3,0x10-0x2f
                 Multiple session specific skips are separated by space.
                 """,
        )

    async def main(self, args: Namespace) -> None:
        self.ecu.max_retry = 1
        found: dict[int, dict[int, Any]] = {}

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

        for session in sessions:
            self.logger.info(f"Switching to session {g_repr(session)}")
            try:
                resp: UDSResponse = await self.ecu.set_session(
                    session, UDSRequestConfig(tags=["preparation"])
                )
            except (UDSException, RuntimeError) as e:
                self.logger.warning(
                    f"session change: {g_repr(session)} reason: {g_repr(e)}"
                )
                continue
            if isinstance(resp, NegativeResponse):
                self.logger.warning(f"session change: {g_repr(session)} reason: {resp}")
                continue

            found[session] = {}
            self.logger.result(f"scanning in session {g_repr(session)}")

            # Starts at 0x00, see first loop iteration.
            sid = -1
            while sid < 0xFF:
                sid += 1
                if sid & 0x40 and not args.scan_response_ids:
                    continue

                if session in args.skip and sid in args.skip[session]:
                    self.logger.info(f"{g_repr(sid)}: skipped")
                    continue

                if args.check_session:
                    if not await self.ecu.check_and_set_session(session):
                        self.logger.error(
                            f"Aborting scan on session {g_repr(session)}; current SID was {g_repr(sid)}"
                        )
                        break

                pdu = bytes([sid]) + args.payload if args.payload else bytes([sid])

                try:
                    resp = await self.ecu.send_raw(
                        pdu, config=UDSRequestConfig(tags=["ANALYZE"])
                    )
                except asyncio.TimeoutError:
                    self.logger.info(f"{g_repr(sid)}: timeout")
                    continue
                except Exception as e:
                    self.logger.info(f"{g_repr(sid)}: {e!r} occurred")
                    await self.ecu.reconnect()
                    continue

                if suggests_service_not_supported(resp):
                    self.logger.info(f"{g_repr(sid)}: not supported [{resp}]")
                    continue

                self.logger.result(
                    f"{g_repr(sid)}: available in session {g_repr(session)}: {resp}"
                )
                found[session][sid] = resp

            await self.ecu.leave_session(session)

        for key, value in found.items():
            self.logger.result(f"findings in session 0x{key:02X}:")
            for sid, data in value.items():
                try:
                    self.logger.result(
                        f"  [{g_repr(sid)}] {UDSIsoServices(sid).name}: {data}"
                    )
                except Exception:
                    self.logger.result(f"  [{g_repr(sid)}] vendor specific sid: {data}")
