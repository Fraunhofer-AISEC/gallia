# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import ArgumentParser, Namespace

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import Scanner
from gallia.config import Config
from gallia.plugins import load_transport
from gallia.services.xcp import CANXCPSerivce, XCPService
from gallia.transports import ISOTPTransport, RawCANTransport
from gallia.utils import auto_int, catch_and_log_exception


class SimpleTestXCP(Scanner):
    """Test XCP Slave"""

    GROUP = "primitive"
    COMMAND = "xcp"
    SHORT_HELP = "XCP tester"

    def __init__(self, parser: ArgumentParser, config: Config):
        self.service: XCPService

        super().__init__(parser, config)

    def configure_parser(self) -> None:
        self.parser.add_argument("--can-master", type=auto_int, default=None)
        self.parser.add_argument("--can-slave", type=auto_int, default=None)

    async def setup(self, args: Namespace) -> None:
        transport_type = load_transport(args.target)
        transport = await transport_type.connect(args.target)

        if isinstance(transport, RawCANTransport):
            if args.can_master is None or args.can_slave is None:
                self.parser.error("For CAN interfaces, master and slave address are required!")

            self.service = CANXCPSerivce(transport, args.can_master, args.can_slave)
        elif isinstance(transport, ISOTPTransport):
            self.parser.error("Use can-raw for CAN interfaces!")
        else:
            self.service = XCPService(transport)

        await super().setup(args)

    async def main(self, args: Namespace) -> None:
        await catch_and_log_exception(self.service.connect)
        await catch_and_log_exception(self.service.get_status)
        await catch_and_log_exception(self.service.get_comm_mode_info)
        await catch_and_log_exception(self.service.disconnect)
