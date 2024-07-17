# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import (
    NegativeResponse,
    UDSRequest,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.exception import UDSException
from gallia.services.uds.core.service import RawRequest, RawResponse
from gallia.services.uds.helpers import raise_for_error
from gallia.utils import auto_int

logger = get_logger(__file__)


class SendPDUPrimitive(UDSScanner):
    """A raw scanner to send a plain pdu"""

    GROUP = "primitive"
    COMMAND = "pdu"
    SHORT_HELP = "send a plain PDU"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "pdu",
            type=binascii.unhexlify,
            help="The raw pdu to send to the ECU",
        )
        self.parser.add_argument(
            "-r",
            "--max-retry",
            type=int,
            default=4,
            help="Set the uds' stack max_retry argument",
        )
        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=None,
            help="Change to this session prior to sending the pdu",
        )

    async def main(self, args: Namespace) -> None:
        pdu = args.pdu
        if args.session is not None:
            resp: UDSResponse = await self.ecu.set_session(args.session)
            raise_for_error(resp)

        parsed_request = UDSRequest.parse_dynamic(pdu)

        if isinstance(parsed_request, RawRequest):
            logger.warning("Could not parse the request pdu")

        logger.info(f"Sending {parsed_request}")

        try:
            response = await self.ecu.send_raw(
                pdu,
                config=UDSRequestConfig(max_retry=args.max_retry),
            )
        except UDSException as e:
            logger.error(repr(e))
            sys.exit(1)

        if isinstance(response, NegativeResponse):
            logger.warning(f"Received {response}")
        else:
            if isinstance(response, RawResponse):
                logger.warning("Could not parse the response pdu")

            logger.result(f"Received {response}")
