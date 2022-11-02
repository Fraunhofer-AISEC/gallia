# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from argparse import Namespace

from gallia.command import UDSScanner
from gallia.services.uds.core.service import NegativeResponse


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
            self.logger.warning(f"ECU said: {resp}")
            return
        self.logger.result(resp.data_record.hex())
