import asyncio
import sys
from argparse import Namespace

from gallia.transports.can import RawCANTransport, ISOTPTransport
from gallia.udscan.core import DiscoveryScanner
from gallia.udscan.utils import write_ecu_url_list


class FindISOTPAddrScanner(DiscoveryScanner):
    """This scanner discovers all UDS endpoints on a ECU using ISO-TP extended addressing.
    For this addressing schema, a tester-id is used as source CAN-ID for all endpoints.
    Different endpoints are addressed via ISO-TP extended address (1 byte).
    This scanner iterates all ISO-TP extended addresses to find all endpoints."""

    def add_parser(self) -> None:
        self.parser.set_defaults(tester_present=False)

        self.parser.add_argument(
            "--sniff-time",
            default=60,
            type=int,
            metavar="SECONDS",
            help="Time in seconds to sniff on bus for current traffic",
        )

    async def setup(self, args: Namespace) -> None:
        if not args.target.scheme == RawCANTransport.SCHEME:
            self.logger.log_error(
                f"Unsupported transport schema {args.target.scheme}; must be can-raw!"
            )
            sys.exit(1)
        if "src_addr" not in args.target.qs:
            self.logger.log_error("CAN source ID (test-id) must be set!")
            sys.exit(1)
        await super().setup(args)

    async def main(self, args: Namespace) -> None:
        assert isinstance(self.transport, RawCANTransport)
        found = []
        url = args.target.url._replace(scheme=ISOTPTransport.SCHEME)

        sniff_time: int = args.sniff_time
        self.logger.log_summary(
            f"Listening to idle bus communication for {sniff_time}s..."
        )
        addr_idle = await self.transport.get_idle_traffic(sniff_time)
        self.logger.log_summary(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        self.transport.set_filter(addr_idle, inv_filter=True)
        # flush receive queue
        await self.transport.get_idle_traffic(2)

        self.logger.log_summary("Starting with search")
        tester_id = int(args.target.qs["src_addr"][0], 0)
        for ID in range(0x100):
            self.logger.log_info(f"Testing ISO-TP address: {ID:02x}")
            is_broadcast = False

            await self.transport.sendto(
                bytes([ID, 0x02, 0x10, 0x01]), tester_id, timeout=0.1
            )
            try:
                addr_old, data = await self.transport.recvfrom(timeout=0.2)
                if addr_old == ID:
                    self.logger.log_warning(
                        f"{ID:02x}: wtf!? The same ID answered. Skipping..."
                    )
                    continue
            except asyncio.TimeoutError:
                continue

            new_addr = None
            while True:
                # The recv buffer needs to be flushed to avoid
                # wrong results...
                try:
                    new_addr, _ = await self.transport.recvfrom(timeout=0.2)
                    if new_addr != addr_old:
                        if not is_broadcast:
                            self.logger.log_summary(
                                f"found broadcast endpoint on ID {ID:02x}; "
                                f"response from CAN ID [src:dst] {tester_id:03x}:{addr_old:03x} "
                                f"ISO-TP [tx:rx] {ID:02x}:{data[0]:02x}"
                            )
                        self.logger.log_summary(
                            f"found broadcast endpoint on ID {ID:02x}; "
                            f"response from CAN ID [src:dst] {tester_id:03x}:{new_addr:03x} "
                            f"ISO-TP [tx:rx] {ID:02x}:{data[0]:02x}"
                        )
                        is_broadcast = True
                    else:
                        self.logger.log_summary(
                            f"{tester_id:03x}:{new_addr:03x}: seems like "
                            f"a large ISO-TP packet was received on ISO-TP address: {ID:02x}"
                        )
                except asyncio.TimeoutError:
                    if new_addr is None:
                        if is_broadcast is False and data is not None:
                            msg = (
                                f"found endpoint: CAN [src:dst]: {tester_id:03x}:{addr_old:03x} "
                                f"ISO-TP [tx:rx]: {data[0]:02x}:{ID:02x}, entire payload: {data.hex()}"
                            )
                            self.logger.log_summary(msg)
                            found.append(
                                (
                                    url,
                                    {
                                        "src_addr": hex(tester_id),
                                        "dst_addr": hex(addr_old),
                                        "rx_ext_address": hex(data[0]),
                                        "ext_address": hex(ID),
                                        "is_fd": str(
                                            self.transport.args["is_fd"]
                                        ).lower(),
                                    },
                                )
                            )
                    break

        self.logger.log_summary(f"Found {len(found)} ISO-TP endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        self.logger.log_summary(f"Writing urls to file: {ecus_file}")
        await write_ecu_url_list(ecus_file, found, self.db_handler)
