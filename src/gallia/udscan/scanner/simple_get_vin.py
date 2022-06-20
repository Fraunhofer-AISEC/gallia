# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner


class GetVin(UDSScanner):
    """Request VIN"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

    async def main(self, args: Namespace) -> None:
        resp = await self.ecu.read_vin()
        if isinstance(resp, NegativeResponse):
            self.logger.log_warning(f"ECU said: {resp}")
            return
        self.logger.log_summary(resp.data_record.hex())
