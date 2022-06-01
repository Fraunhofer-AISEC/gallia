import asyncio
from argparse import Namespace

from gallia.transports.base import TargetURI
from gallia.transports.can import ISOTPTransport, RawCANTransport
from gallia.uds.core.service import NegativeResponse
from gallia.uds.ecu import ECU
from gallia.udscan.core import DiscoveryScanner
from gallia.utils import auto_int, can_id_repr, g_repr, write_target_list


class FindCanIDsScanner(DiscoveryScanner):
    """This scanner discovers all UDS endpoints on a ECU using ISO-TP normal addressing.
    This is the default protocol used by OBD.
    When using normal addressing, the ISO-TP header does not include an address and there is no generic tester address.
    Addressing is only done via CAN IDs. Every endpoint has a source and destination CAN ID.
    Typically, there is also a broadcast destination ID to address all endpoints."""

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=auto_int,
            default=0x00,
            help="set start address",
        )
        self.parser.add_argument(
            "--end",
            metavar="INT",
            type=auto_int,
            default=0x7FF,
            help="set end address",
        )
        self.parser.add_argument(
            "--info-did",
            metavar="DID",
            type=auto_int,
            default=0xF197,
            help="DID to query ECU description",
        )
        self.parser.add_argument(
            "--sniff-time",
            default=60,
            type=int,
            metavar="SECONDS",
            help="Time in seconds to sniff on bus for current traffic",
        )

    async def setup(self, args: Namespace) -> None:
        if args.target is not None and not args.target.scheme == RawCANTransport.SCHEME:
            self.parser.error(
                f"Unsupported transport schema {args.target.scheme}; must be can-raw!"
            )
        await super().setup(args)

    async def main(self, args: Namespace) -> None:
        assert isinstance(self.transport, RawCANTransport)
        found = []

        sniff_time: int = args.sniff_time
        self.logger.log_summary(
            f"Listening to idle bus communication for {sniff_time}s..."
        )
        addr_idle = await self.transport.get_idle_traffic(sniff_time)
        self.logger.log_summary(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        self.transport.set_filter(addr_idle, inv_filter=True)

        for ID in range(args.start, args.end + 1):
            self.logger.log_info(f"Testing CAN ID {can_id_repr(ID)}")
            is_broadcast = False

            await self.transport.sendto(
                bytes([0x02, 0x10, 0x01, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
                timeout=0.1,
                dst=ID,
            )
            try:
                addr, _ = await self.transport.recvfrom(timeout=0.1)
                if addr == ID:
                    self.logger.log_info(
                        f"wtf!? The same CAN ID {can_id_repr(ID)} answered. Skipping..."
                    )
                    continue
            except asyncio.TimeoutError:
                continue

            while True:
                # The recv buffer needs to be flushed to avoid
                # wrong results...
                try:
                    new_addr, _ = await self.transport.recvfrom(timeout=0.1)
                    if new_addr != addr:
                        is_broadcast = True
                        self.logger.log_summary(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(new_addr)}"
                        )
                    else:
                        self.logger.log_info(
                            f"seems like a large ISO-TP packet was received on CAN ID {can_id_repr(ID)}"
                        )
                except asyncio.TimeoutError:
                    if is_broadcast:
                        self.logger.log_summary(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(addr)}"
                        )
                    else:
                        self.logger.log_summary(
                            f"found endpoint on CAN ID [src:dst]: {can_id_repr(ID)}:{can_id_repr(addr)}"
                        )
                        found.append(
                            TargetURI.from_parts(
                                ISOTPTransport.SCHEME,
                                args.target.host,
                                None,
                                {
                                    "src_addr": hex(ID),
                                    "dst_addr": hex(addr),
                                    "tx_padding": "0xaa",
                                    "rx_padding": "0xaa",
                                    "is_fd": str(self.transport.args["is_fd"]).lower(),
                                },
                            )
                        )
                    break

        self.logger.log_summary(f"finished; found {len(found)} UDS endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        self.logger.log_summary(f"Writing urls to file: {ecus_file}")
        connection_strings = await write_target_list(ecus_file, found, self.db_handler)

        self.logger.log_info("reading info DID from all discovered endpoints")
        did = args.info_did
        for url in connection_strings:
            self.logger.log_summary("----------------------------")
            self.logger.log_summary(f"Probing ECU: {url}")
            target = TargetURI(url)
            transport = ISOTPTransport(target)
            await transport.connect(None)
            ecu = ECU(transport, timeout=2)
            self.logger.log_summary(f"reading device description at {g_repr(did)}")
            try:
                resp = await ecu.read_data_by_identifier(did)
                if isinstance(resp, NegativeResponse):
                    self.logger.log_summary(f"could not read did: {resp}")
                else:
                    self.logger.log_summary(f"response was: {resp.data_record!r}")
            except Exception as e:
                self.logger.log_summary(f"reading description failed: {g_repr(e)}")
