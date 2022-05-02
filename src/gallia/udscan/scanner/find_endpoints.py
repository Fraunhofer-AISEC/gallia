import asyncio
from argparse import Namespace

from gallia.uds.core.constants import UDSErrorCodes
from gallia.uds.core.service import (
    DiagnosticSessionControlResponse,
    DiagnosticSessionControlRequest,
    NegativeResponse,
)
from gallia.uds.helpers import raise_for_mismatch
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int, write_ecu_url_list


class FindEndpoints(UDSScanner):
    """This is a generic UDS endpoint discovery scanner. Currently only supports DoIP."""

    def __init__(self) -> None:
        super().__init__()

        self.implicit_logging = False
        self.log_scan_run = False

    def add_parser(self) -> None:
        self.parser.set_defaults(tester_present=False)

        self.parser.add_argument(
            "--reversed",
            action="store_true",
            help="scan in reversed order",
        )
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=auto_int,
            default=0x00,
            help="set start address",
        )
        self.parser.add_argument(
            "--end", metavar="INT", type=auto_int, default=0xFF, help="set end address"
        )

    async def setup(self, args: Namespace) -> None:
        await super().setup(args)

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(args.target.url.scheme)
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the discovery run to the database: {repr(e)}"
                )

    async def main(self, args: Namespace) -> None:
        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(args.target.url.scheme)
            except Exception as e:
                self.logger.log_warning(
                    f"Could not write the discovery run to the database: {repr(e)}"
                )

        assert self.transport is not None
        src_addr = self.transport.args["src_addr"]  # type: ignore
        found = []
        src_gen = (
            range(args.end + 1, args.start)
            if args.reversed
            else range(args.start, args.end + 1)
        )
        req = DiagnosticSessionControlRequest(0x01)
        url = args.target.url

        for dst_addr in src_gen:
            try:
                await self.transport.sendto(req.pdu, dst_addr)
                while True:
                    addr, data = await self.transport.recvfrom(timeout=args.timeout)
                    resp = DiagnosticSessionControlResponse.parse_static(data)
                    raise_for_mismatch(req, resp)
                    if (
                        isinstance(resp, NegativeResponse)
                        and resp.response_code
                        == UDSErrorCodes.requestCorrectlyReceivedResponsePending
                    ):
                        continue
                    break
                self.logger.log_info(f"{resp}")
                self.logger.log_info(f"found dst: {addr:2x}")
                found.append(
                    (url, {"dst_addr": hex(dst_addr), "src_addr": hex(src_addr)})
                )
            except BrokenPipeError:
                await self.transport.reconnect()
            except asyncio.TimeoutError:
                pass

        self.logger.log_summary(f"Finished scan; found {len(found)} endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        self.logger.log_summary(f"Writing urls to file: {ecus_file}")
        await write_ecu_url_list(ecus_file, found, self.db_handler)
