# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace
from pathlib import Path

from gallia.command import UDSScanner
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class WMBAPrimitive(UDSScanner):
    """Write memory by address"""

    COMMAND = "wmba"
    GROUP = "primitive"
    SHORT_HELP = "WriteMemoryByAddress"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "address",
            type=auto_int,
            help="The start address to which data should be written",
        )
        data_group = self.parser.add_mutually_exclusive_group(required=True)
        data_group.add_argument(
            "--data",
            type=binascii.unhexlify,
            help="The data which should be written",
        )
        data_group.add_argument(
            "--data-file",
            type=Path,
            help="The path to a file with the binary data which should be written",
        )

    async def main(self, args: Namespace) -> None:
        try:
            await self.ecu.check_and_set_session(args.session)
        except Exception as e:
            self.logger.critical(
                f"Could not change to session: {g_repr(args.session)}: {e!r}"
            )
            sys.exit(1)

        if args.data is not None:
            data = args.data
        else:
            with args.data_file.open("rb") as file:
                data = file.read()

        resp = await self.ecu.write_memory_by_address(args.address, data)

        if isinstance(resp, NegativeResponse):
            self.logger.error(resp)
        else:
            # There is not real data returned, only echos
            self.logger.result("Success")
