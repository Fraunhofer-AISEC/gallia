# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class WMBAPrimitiveConfig(UDSScannerConfig):
    session: AutoInt = Field(0x01, description="The session in which the requests are made")
    address: AutoInt = Field(
        description="The start address to which data should be written", positional=True
    )
    data: HexBytes | None = Field(description="The data which should be written")
    data_file: Path | None = Field(
        description="The path to a file with the binary data which should be written"
    )


class WMBAPrimitive(UDSScanner):
    """Write memory by address"""

    CONFIG_TYPE = WMBAPrimitiveConfig
    SHORT_HELP = "WriteMemoryByAddress"

    def __init__(self, config: WMBAPrimitiveConfig):
        super().__init__(config)
        self.config: WMBAPrimitiveConfig = config

    async def main(self) -> None:
        try:
            await self.ecu.check_and_set_session(self.config.session)
        except Exception as e:
            logger.critical(f"Could not change to session: {g_repr(self.config.session)}: {e!r}")
            sys.exit(1)

        if self.config.data is not None:
            data = self.config.data
        else:
            with self.config.data_file.open("rb") as file:
                data = file.read()

        resp = await self.ecu.write_memory_by_address(self.config.address, data)

        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            # There is not real data returned, only echos
            logger.result("Success")
