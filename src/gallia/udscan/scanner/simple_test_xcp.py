from argparse import Namespace

from gallia.udscan.core import Scanner
from gallia.udscan.utils import catch_and_log_exception
from gallia.services.xcp import XCPService


class TestXCP(Scanner):
    """Test XCP Slave"""

    def add_parser(self) -> None:
        pass

    async def main(self, args: Namespace) -> None:
        assert self.transport
        service = XCPService(self.transport)

        await catch_and_log_exception(self.logger, service.connect)
        await catch_and_log_exception(self.logger, service.get_status)
        await catch_and_log_exception(self.logger, service.get_comm_mode_info)
        await catch_and_log_exception(self.logger, service.disconnect)
