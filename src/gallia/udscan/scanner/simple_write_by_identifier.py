import binascii
import sys
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int
from gallia.utils import g_repr


class WriteByIdentifier(UDSScanner):
    """A simple scanner to talk to the write by identifier service"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="set session perform test in",
        )
        self.parser.add_argument(
            "--data-id",
            type=auto_int,
            required=True,
            help="which data identifier to write to",
        )
        self.parser.add_argument(
            "--data",
            required=True,
            type=binascii.unhexlify,
            help="data to write as hex",
        )

    async def main(self, args: Namespace) -> None:
        try:
            if args.session != 0x01:
                resp: UDSResponse = await self.ecu.set_session(args.session)
                if isinstance(resp, NegativeResponse):
                    self.logger.log_critical(f"could not change to session: {resp}")
                    sys.exit(1)
        except Exception as e:
            self.logger.log_critical(f"fatal error: {g_repr(e)}")
            sys.exit(1)

        resp = await self.ecu.write_data_by_identifier(args.data_id, args.data)
        if isinstance(resp, NegativeResponse):
            self.logger.log_error(resp)
        else:
            self.logger.log_info("Positive response")
