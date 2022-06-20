# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace

from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.exception import UDSException
from gallia.uds.core.service import (
    NegativeResponse,
    RawRequest,
    RawResponse,
    UDSRequest,
    UDSResponse,
)
from gallia.uds.helpers import raise_for_error
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class SendPDU(UDSScanner):
    """A raw scanner to send a plain pdu"""

    def add_parser(self) -> None:
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
            self.logger.log_warning("Could not parse the request pdu")

        self.logger.log_info(f"Sending {parsed_request}")

        try:
            response = await self.ecu.send_raw(
                pdu, config=UDSRequestConfig(max_retry=args.max_retry)
            )
        except UDSException as e:
            self.logger.log_error(g_repr(e))
            sys.exit(1)

        if isinstance(response, NegativeResponse):
            self.logger.log_warning(f"Received {response}")
        else:
            if isinstance(response, RawResponse):
                self.logger.log_warning("Could not parse the response pdu")

            self.logger.log_notice(f"Received {response}")
