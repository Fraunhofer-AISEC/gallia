import sys
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int


class ReadByIdentifier(UDSScanner):
    """cmd_readByIdentifier"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session", type=auto_int, default=0x01, help="set session perform test in"
        )
        self.parser.add_argument(
            "--data-id", type=auto_int, default=0x1001, help="data Identified to read"
        )

    async def main(self, args: Namespace) -> None:
        try:
            if args.session != 0x01:
                await self.ecu.set_session(args.session)
        except Exception as e:
            self.logger.log_critical(f"fatal error: {e}")
            sys.exit(1)

        resp = await self.ecu.read_data_by_identifier(args.data_id)
        if isinstance(resp, NegativeResponse):
            self.logger.log_error(resp)
        else:
            self.logger.log_info("Positive response:")
            data = resp.data_record
            self.logger.log_info(f"hex: {data.hex()}")
            self.logger.log_info(f"raw: {repr(data)}")
