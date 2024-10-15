# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class RMBAPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="The session in which the requests are made")
    address: AutoInt = Field(
        description="The start address from which data should be read", positional=True
    )
    length: AutoInt = Field(description="The number of bytes which should be read", positional=True)


class RMBAPrimitive(UDSScanner):
    """Read memory by address"""

    CONFIG_TYPE = RMBAPrimitiveConfig
    SHORT_HELP = "ReadMemoryByAddress"

    def __init__(self, config: RMBAPrimitiveConfig):
        super().__init__(config)
        self.config: RMBAPrimitiveConfig = config

    async def main(self) -> None:
        try:
            await self.ecu.check_and_set_session(self.config.session)
        except Exception as e:
            logger.critical(f"Could not change to session: {g_repr(self.config.session)}: {e!r}")
            sys.exit(1)

        resp = await self.ecu.read_memory_by_address(self.config.address, self.config.length)

        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Positive response:")

            logger.result(f"hex: {resp.data_record.hex()}")
            logger.result(f"raw: {repr(resp.data_record)}")
