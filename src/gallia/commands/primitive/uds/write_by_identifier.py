# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse
from gallia.utils import auto_int

logger = get_logger("gallia.primitive.wdbi")


class WriteByIdentifierPrimitive(UDSScanner):
    """A simple scanner to talk to the write by identifier service"""

    GROUP = "primitive"
    COMMAND = "wdbid"
    SHORT_HELP = "WriteDataByIdentifier"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="set session perform test in",
        )
        self.parser.add_argument(
            "--data-id",
            type=auto_int,
            required=True,
            help="which data identifier to write to",
        )
        self.parser.add_argument(
            "--data",
            required=True,
            type=binascii.unhexlify,
            help="data to write as hex",
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

        resp = await self.ecu.write_data_by_identifier(args.data_id, args.data)
        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.info("Positive response")
