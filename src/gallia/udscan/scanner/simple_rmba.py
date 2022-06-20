# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class ReadMemoryByAddressScanner(UDSScanner):
    """Read memory by address"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "address",
            type=auto_int,
            help="The start address from which data should be read",
        )
        self.parser.add_argument(
            "length", type=auto_int, help="The number of bytes which should be read"
        )

    async def main(self, args: Namespace) -> None:
        try:
            await self.ecu.check_and_set_session(args.session)
        except Exception as e:
            self.logger.log_critical(
                f"Could not change to session: {g_repr(args.session)}: {g_repr(e)}"
            )
            sys.exit(1)

        resp = await self.ecu.read_memory_by_address(args.address, args.length)

        if isinstance(resp, NegativeResponse):
            self.logger.log_error(resp)
        else:
            self.logger.log_summary("Positive response:")

            self.logger.log_summary(f"hex: {resp.data_record.hex()}")
            self.logger.log_summary(f"raw: {repr(resp.data_record)}")
