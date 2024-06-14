# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger(__name__)


class ECUResetPrimitive(UDSScanner):
    """Use the ECUReset UDS service to reset the ECU"""

    GROUP = "primitive"
    COMMAND = "ecu-reset"
    SHORT_HELP = "ECUReset"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session perform test in"
        )
        self.parser.add_argument("-f", "--subfunc", type=auto_int, default=0x01, help="subfunc")

    async def main(self, args: Namespace) -> None:
        resp: UDSResponse = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            logger.error(f"could not change to session: {g_repr(args.session)}")
            return

        try:
            logger.info(f"try sub-func: {g_repr(args.subfunc)}")
            resp = await self.ecu.ecu_reset(args.subfunc)
            if isinstance(resp, NegativeResponse):
                msg = f"ECU Reset {g_repr(args.subfunc)} failed in session: {g_repr(args.session)}: {resp}"
                logger.error(msg)
            else:
                logger.result(f"ECU Reset {g_repr(args.subfunc)} succeeded")
        except TimeoutError:
            logger.error("Timeout")
            await asyncio.sleep(10)
        except ConnectionError:
            msg = f"Lost connection to ECU, session: {g_repr(args.session)} subFunc: {g_repr(args.subfunc)}"
            logger.error(msg)
            return
