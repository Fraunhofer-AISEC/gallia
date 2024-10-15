# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.service import NegativeResponse

logger = get_logger(__name__)


class PingPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="set session to perform test")
    count: AutoInt | None = Field(None, description="limit number of pings to this amount")
    interval: float = Field(0.5, description="time interval between two pings", metavar="SECONDS")


class PingPrimitive(UDSScanner):
    """Ping ECU via TesterPresent"""

    CONFIG_TYPE = PingPrimitiveConfig
    SHORT_HELP = "ping ECU via TesterPresent"

    def __init__(self, config: PingPrimitiveConfig):
        super().__init__(config)
        self.config: PingPrimitiveConfig = config

    async def main(self) -> None:
        resp = await self.ecu.set_session(self.config.session)
        if isinstance(resp, NegativeResponse):
            logger.error(f"Could not change to requested session: {resp}")
            sys.exit(1)

        i = 1
        while True:
            if self.config.count is not None and i > self.config.count:
                break
            ret = await self.ecu.ping()
            if isinstance(ret, NegativeResponse):
                logger.warning(ret)
            logger.result("ECU is alive!")
            await asyncio.sleep(self.config.interval)
            i += 1
