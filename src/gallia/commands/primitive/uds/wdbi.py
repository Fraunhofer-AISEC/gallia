# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace
from pathlib import Path

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse
from gallia.utils import auto_int

logger = get_logger(__name__)


class WriteByIdentifierPrimitive(UDSScanner):
    """A simple scanner to talk to the write by identifier service"""

    GROUP = "primitive"
    COMMAND = "wdbi"
    SHORT_HELP = "WriteDataByIdentifier"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument("data_identifier", type=auto_int, help="The data identifier")
        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session perform test in"
        )
        data_group = self.parser.add_mutually_exclusive_group(required=True)
        data_group.add_argument(
            "--data", type=binascii.unhexlify, help="The data which should be written"
        )
        data_group.add_argument(
            "--data-file",
            type=Path,
            help="The path to a file with the binary data which should be written",
        )

    async def main(self, args: Namespace) -> None:
        try:
            if args.session != 0x01:
                resp: UDSResponse = await self.ecu.set_session(args.session)
                if isinstance(resp, NegativeResponse):
                    logger.critical(f"could not change to session: {resp}")
                    sys.exit(1)
        except Exception as e:
            logger.critical(f"fatal error: {e!r}")
            sys.exit(1)

        if args.data is not None:
            data = args.data
        else:
            with args.data_file.open("rb") as file:
                data = file.read()

        resp = await self.ecu.write_data_by_identifier(args.data_identifier, data)
        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Success")
