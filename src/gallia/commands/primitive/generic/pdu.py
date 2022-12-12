# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
from argparse import Namespace

from gallia.command import Scanner


class GenericPDUPrimitive(Scanner):
    """A raw scanner to send a plain pdu"""

    GROUP = "primitive"
    SUBGROUP = "generic"
    COMMAND = "pdu"
    SHORT_HELP = "send a plain PDU"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "pdu",
            type=binascii.unhexlify,
            help="raw pdu to send",
        )

    async def main(self, args: Namespace) -> None:
        await self.transport.write(args.pdu)
