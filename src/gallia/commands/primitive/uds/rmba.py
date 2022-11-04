# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class RMBAPrimitive(UDSScanner):
    """Read memory by address"""

    GROUP = "primitive"
    COMMAND = "rmba"
    SHORT_HELP = "ReadMemoryByAddress"

    def configure_parser(self) -> None:
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
            "length",
            type=auto_int,
            help="The number of bytes which should be read",
        )

    async def main(self, args: Namespace) -> None:
        try:
            await self.ecu.check_and_set_session(args.session)
        except Exception as e:
            self.logger.critical(
                f"Could not change to session: {g_repr(args.session)}: {e!r}"
            )
            sys.exit(1)

        resp = await self.ecu.read_memory_by_address(args.address, args.length)

        if isinstance(resp, NegativeResponse):
            self.logger.error(resp)
        else:
            self.logger.result("Positive response:")

            self.logger.result(f"hex: {resp.data_record.hex()}")
            self.logger.result(f"raw: {repr(resp.data_record)}")
