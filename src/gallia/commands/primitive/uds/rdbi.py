# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.service import NegativeResponse

logger = get_logger(__name__)


class ReadByIdentifierPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    data_identifier: AutoInt = Field(description="The data identifier", positional=True)
    session: AutoInt = Field(0x01, description="set session perform test in")


class ReadByIdentifierPrimitive(UDSScanner):
    """Read data via the ReadDataByIdentifier service"""

    CONFIG_TYPE = ReadByIdentifierPrimitiveConfig
    SHORT_HELP = "ReadDataByIdentifier"

    def __init__(self, config: ReadByIdentifierPrimitiveConfig):
        super().__init__(config)
        self.config: ReadByIdentifierPrimitiveConfig = config
        self.result: bytes | None = None

    async def main(self) -> None:
        try:
            if self.config.session != 0x01:
                await self.ecu.set_session(self.config.session)
        except Exception as e:
            logger.critical(f"fatal error: {e!r}")
            sys.exit(1)

        resp = await self.ecu.read_data_by_identifier(self.config.data_identifier)
        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Positive response:")
            data = resp.data_record
            logger.result(f"hex: {data.hex()}")
            logger.result(f"raw: {repr(data)}")
            self.result = data
