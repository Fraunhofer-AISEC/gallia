# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds.core.service import NegativeResponse

logger = get_logger(__name__)


class VINPrimitive(UDSScanner):
    """Request VIN"""

    GROUP = "primitive"
    COMMAND = "vin"
    SHORT_HELP = "request VIN"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

    async def main(self, args: Namespace) -> None:
        resp = await self.ecu.read_vin()
        if isinstance(resp, NegativeResponse):
            logger.warning(f"ECU said: {resp}")
            return
        logger.result(resp.data_record.hex())
