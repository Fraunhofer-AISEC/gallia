# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from argparse import Namespace

from gallia.services.xcp import XCPService
from gallia.udscan.core import Scanner, load_transport
from gallia.utils import catch_and_log_exception


class TestXCP(Scanner):
    """Test XCP Slave"""

    def add_parser(self) -> None:
        pass

    async def main(self, args: Namespace) -> None:
        transport = load_transport(args.target)
        await transport.connect(None)
        service = XCPService(transport)

        await catch_and_log_exception(self.logger, service.connect)
        await catch_and_log_exception(self.logger, service.get_status)
        await catch_and_log_exception(self.logger, service.get_comm_mode_info)
        await catch_and_log_exception(self.logger, service.disconnect)
