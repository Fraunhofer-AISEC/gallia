# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class EcuReset(UDSScanner):
    """ECU_Reset"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session perform test in"
        )
        self.parser.add_argument(
            "-f", "--subfunc", type=auto_int, default=0x01, help="subfunc"
        )

    async def main(self, args: Namespace) -> None:
        resp: UDSResponse = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            self.logger.log_error(
                f"could not change to session: {g_repr(args.session)}"
            )
            return

        try:
            self.logger.log_info(f"try sub-func: {g_repr(args.subfunc)}")
            resp = await self.ecu.ecu_reset(args.subfunc)
            if isinstance(resp, NegativeResponse):
                msg = f"ECU Reset {g_repr(args.subfunc)} failed in session: {g_repr(args.session)}: {resp}"
                self.logger.log_error(msg)
            else:
                self.logger.log_summary(f"ECU Reset {g_repr(args.subfunc)} succeeded")
        except asyncio.TimeoutError:
            self.logger.log_error("Timeout")
            await asyncio.sleep(10)
        except ConnectionError:
            msg = f"Lost connection to ECU, session: {g_repr(args.session)} subFunc: {g_repr(args.subfunc)}"
            self.logger.log_error(msg)
            return
