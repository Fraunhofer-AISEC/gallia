# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int


class Ping(UDSScanner):
    """Ping ECU via Tester Present"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session to perform test"
        )
        self.parser.add_argument(
            "--count",
            type=auto_int,
            default=None,
            help="limit number of pings to this amount",
        )
        self.parser.add_argument(
            "--interval",
            type=float,
            default=0.5,
            metavar="SECONDS",
            help="time interval between two pings",
        )

    async def main(self, args: Namespace) -> None:
        resp = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            self.logger.log_error(f"Could not change to requested session: {resp}")
            sys.exit(1)

        i = 1
        while True:
            if args.count is not None and i > args.count:
                break
            ret = await self.ecu.ping()
            if isinstance(ret, NegativeResponse):
                self.logger.log_warning(ret)
            self.logger.log_summary("ECU is alive!")
            await asyncio.sleep(args.interval)
            i += 1
