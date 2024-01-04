# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequest, UDSRequestConfig, UDSResponse
from gallia.services.uds.core.exception import UDSException
from gallia.services.uds.core.service import RawRequest, RawResponse
from gallia.services.uds.helpers import raise_for_error

logger = get_logger(__name__)


class SendPDUPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    pdu: HexBytes = Field(description="The raw pdu to send to the ECU", positional=True)
    max_retry: int = Field(3, description="Set the uds' stack max_retry argument", short="r")
    session: AutoInt | None = Field(
        None, description="Change to this session prior to sending the pdu"
    )


class SendPDUPrimitive(UDSScanner):
    """A raw scanner to send a plain pdu"""

    CONFIG_TYPE = SendPDUPrimitiveConfig
    SHORT_HELP = "send a plain PDU"

    def __init__(self, config: SendPDUPrimitiveConfig):
        super().__init__(config)
        self.config: SendPDUPrimitiveConfig = config

    async def main(self) -> None:
        pdu = self.config.pdu
        if self.config.session is not None:
            resp: UDSResponse = await self.ecu.set_session(self.config.session)
            raise_for_error(resp)

        parsed_request = UDSRequest.parse_dynamic(pdu)

        if isinstance(parsed_request, RawRequest):
            logger.warning("Could not parse the request pdu")

        logger.info(f"Sending {parsed_request}")

        try:
            response = await self.ecu.send_raw(
                pdu, config=UDSRequestConfig(max_retry=self.config.max_retry)
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
