# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Self

from pydantic import model_validator

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

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        if self.target.scheme == RawCANTransport.SCHEME and (
            self.can_master is None or self.can_slave is None
        ):
            raise ValueError("For CAN interfaces, master and slave address are required!")

        if self.target.scheme == ISOTPTransport.SCHEME:
            raise ValueError("Use can-raw for CAN interfaces!")

        return self


class SimpleTestXCP(Scanner):
    """Test XCP Slave"""

    CONFIG_TYPE = SimpleTestXCPConfig
    SHORT_HELP = "XCP tester"

    def __init__(self, config: SimpleTestXCPConfig):
        super().__init__(config)
        self.config: SimpleTestXCPConfig = config
        self.service: XCPService

    async def setup(self) -> None:
        transport_type = load_transport(self.config.target)
        transport = await transport_type.connect(self.config.target)

        if isinstance(transport, RawCANTransport):
            assert self.config.can_master is not None and self.config.can_slave is not None

            self.service = CANXCPSerivce(transport, self.config.can_master, self.config.can_slave)
        else:
            self.service = XCPService(transport)

        await super().setup()

    async def main(self) -> None:
        await catch_and_log_exception(self.service.connect)
        await catch_and_log_exception(self.service.get_status)
        await catch_and_log_exception(self.service.get_comm_mode_info)
        await catch_and_log_exception(self.service.disconnect)
