# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds.core.service import NegativeResponse
from gallia.utils import auto_int

logger = get_logger("gallia.primitive.rdbi")


class ReadByIdentifierPrimitive(UDSScanner):
    """Read data via the ReadDataByIdentifier service"""

    GROUP = "primitive"
    COMMAND = "rdbid"
    SHORT_HELP = "ReadDataByIdentifier"

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
            default=0x1001,
            help="data Identified to read",
        )

    async def main(self, args: Namespace) -> None:
        try:
            if args.session != 0x01:
                await self.ecu.set_session(args.session)
        except Exception as e:
            logger.critical(f"fatal error: {e!r}")
            sys.exit(1)

        resp = await self.ecu.read_data_by_identifier(args.data_id)
        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.info("Positive response:")
            data = resp.data_record
            logger.info(f"hex: {data.hex()}")
            logger.info(f"raw: {repr(data)}")
            logger.result(
                f"{self.ecu.transport.target.raw} responds to {args.data_id:#06x} with {data.hex()}"
            )
            self.result = data
