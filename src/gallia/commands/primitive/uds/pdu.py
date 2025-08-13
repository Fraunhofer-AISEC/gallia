# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequest, UDSResponse
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
    pdus: list[HexBytes] = Field(description="The raw PDU(s) to send to the ECU", positional=True)
    session: AutoInt | None = Field(
        None, description="Change to this session prior to sending the PDU(s)"
    )


class SendPDUPrimitive(UDSScanner):
    """A raw scanner to send plain PDU(s)"""

    CONFIG_TYPE = SendPDUPrimitiveConfig
    SHORT_HELP = "send plain PDU(s)"

    def __init__(self, config: SendPDUPrimitiveConfig):
        super().__init__(config)
        self.config: SendPDUPrimitiveConfig = config

    async def _send_pdu(self, pdu: HexBytes) -> None:
        parsed_request = UDSRequest.parse_dynamic(pdu)

        if isinstance(parsed_request, RawRequest):
            logger.warning("Could not parse the request PDU")

        logger.result(f"Sending {parsed_request}")

        try:
            response = await self.ecu.send_raw(pdu)
        except UDSException as e:
            logger.error(repr(e))
            return

        if isinstance(response, NegativeResponse):
            logger.warning(f"Received {response}")
        else:
            if isinstance(response, RawResponse):
                logger.warning("Could not parse the response PDU")
            logger.result(f"Received {response}")

    async def main(self) -> None:
        if self.config.session is not None:
            resp: UDSResponse = await self.ecu.set_session(self.config.session)
            raise_for_error(resp)
            logger.result(f"Switched to session 0x{self.config.session:02x}")

        for pdu in self.config.pdus:
            await self._send_pdu(pdu)
