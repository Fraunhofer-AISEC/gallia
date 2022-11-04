# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class ReadErrorLogPrimitive(UDSScanner):
    """Read the error log via the DTC service"""

    COMMAND = "error-log"
    GROUP = "primitive"
    SHORT_HELP = "read the error log via DTC"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--sessions",
            type=auto_int,
            nargs="*",
            help="set list of sessions to perform test in, or all",
        )
        self.parser.add_argument(
            "--clear-dtc",
            action="store_true",
            help="Clear DTC log",
        )

    async def main(self, args: Namespace) -> None:
        sessions = args.sessions
        if sessions is None or len(sessions) == 0:
            sessions = list(range(1, 0x80))
            sessions = await self.ecu.find_sessions(sessions)
            msg = f"Found {len(sessions)} sessions: {g_repr(sessions)}"
            self.logger.result(msg)

        for sess in sessions:
            await self.ecu.set_session(sess)
            resp = await self.ecu.read_dtc()
            if isinstance(resp, NegativeResponse):
                self.logger.warning(resp)
            else:
                self.logger.result(resp.dtc_and_status_record)
            await self.ecu.leave_session(sess)

        if args.clear_dtc:
            await self.ecu.clear_dtc()
            await self.ecu.read_dtc()
            self.logger.info("Rebooting ECU...")
            await self.ecu.ecu_reset(1)
            await asyncio.sleep(2)
            await self.ecu.read_dtc()
