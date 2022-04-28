import binascii
import sys
from argparse import Namespace
from pathlib import Path

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int, check_and_set_session


class WriteMemoryByAddressScanner(UDSScanner):
    """Write memory by address"""

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "address",
            type=auto_int,
            help="The start address to which data should be written",
        )
        data_group = self.parser.add_mutually_exclusive_group(required=True)
        data_group.add_argument(
            "--data", type=binascii.unhexlify, help="The data which should be written"
        )
        data_group.add_argument(
            "--data-file",
            type=Path,
            help="The path to a file with the binary data which should be written",
        )

    async def main(self, args: Namespace) -> None:
        try:
            await check_and_set_session(self.ecu, args.session)
        except Exception as e:
            self.logger.log_critical(
                f"Could not change to session: 0x{args.session:02x}: {e.__class__.__name__} {e}"
            )
            sys.exit(1)

        if args.data is not None:
            data = args.data
        else:
            with args.data_file.open("rb") as file:
                data = file.read()

        resp = await self.ecu.write_memory_by_address(args.address, data)

        if isinstance(resp, NegativeResponse):
            self.logger.log_error(resp)
        else:
            # There is not real data returned, only echos
            self.logger.log_summary("Success")
