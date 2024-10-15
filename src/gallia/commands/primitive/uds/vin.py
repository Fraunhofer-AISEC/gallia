# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


from gallia.command import UDSScanner
from gallia.command.config import Field
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.service import NegativeResponse

logger = get_logger(__name__)


class VINPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )


class VINPrimitive(UDSScanner):
    """Request VIN"""

    CONFIG_TYPE = VINPrimitiveConfig
    SHORT_HELP = "request VIN"

    def __init__(self, config: VINPrimitiveConfig):
        super().__init__(config)
        self.config: VINPrimitiveConfig = config

    async def main(self) -> None:
        resp = await self.ecu.read_vin()
        if isinstance(resp, NegativeResponse):
            logger.warning(f"ECU said: {resp}")
            return
        logger.result(resp.data_record.hex())
