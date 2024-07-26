# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import Scanner
from gallia.command.base import ScannerConfig
from gallia.command.config import AutoInt, Field
from gallia.plugins.plugin import load_transport
from gallia.services.xcp import CANXCPSerivce, XCPService
from gallia.transports import ISOTPTransport, RawCANTransport
from gallia.utils import catch_and_log_exception


class SimpleTestXCPConfig(ScannerConfig):
    can_master: AutoInt | None = Field(None)
    can_slave: AutoInt | None = Field(None)


class SimpleTestXCP(Scanner):
    """Test XCP Slave"""

    SHORT_HELP = "XCP tester"

    def __init__(self, config: SimpleTestXCPConfig):
        super().__init__(config)
        self.config = config
        self.service: XCPService

    async def setup(self) -> None:
        transport_type = load_transport(self.config.target)
        transport = await transport_type.connect(self.config.target)

        if isinstance(transport, RawCANTransport):
            if self.config.can_master is None or self.config.can_slave is None:
                # TODO: Transform
                self.parser.error("For CAN interfaces, master and slave address are required!")

            self.service = CANXCPSerivce(transport, self.config.can_master, self.config.can_slave)
        elif isinstance(transport, ISOTPTransport):
            # TODO: Transform
            self.parser.error("Use can-raw for CAN interfaces!")
        else:
            self.service = XCPService(transport)

        await super().setup()

    async def main(self) -> None:
        await catch_and_log_exception(self.service.connect)
        await catch_and_log_exception(self.service.get_status)
        await catch_and_log_exception(self.service.get_comm_mode_info)
        await catch_and_log_exception(self.service.disconnect)
