# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace
from binascii import unhexlify

from gallia.command import UDSDiscoveryScanner
from gallia.services.uds import NegativeResponse, UDSClient, UDSRequest
from gallia.services.uds.core.utils import g_repr
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI
from gallia.utils import auto_int, can_id_repr, write_target_list


class IsotpDiscoverer(UDSDiscoveryScanner):
    """Discovers all UDS endpoints on an ECU using ISO-TP normal addressing.
    This is the default protocol used by OBD.
    When using normal addressing, the ISO-TP header does not include an address and there is no generic tester address.
    Addressing is only done via CAN IDs. Every endpoint has a source and destination CAN ID.
    Typically, there is also a broadcast destination ID to address all endpoints."""

    SUBGROUP = "uds"
    COMMAND = "isotp"
    SHORT_HELP = "ISO-TP enumeration scanner"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=auto_int,
            required=True,
            help="set start address",
        )
        self.parser.add_argument(
            "--stop",
            metavar="INT",
            type=auto_int,
            required=True,
            help="set end address",
        )
        self.parser.add_argument(
            "--padding",
            type=auto_int,
            default=None,
            help="set isotp padding",
        )
        self.parser.add_argument(
            "--pdu",
            type=unhexlify,
            default=bytes([0x10, 0x01]),
            help="set pdu used for discovery",
        )
        self.parser.add_argument(
            "--sleep",
            type=float,
            default=0.01,
            help="set sleeptime between loop iterations",
        )
        self.parser.add_argument(
            "--extended-addr",
            action="store_true",
            help="use extended isotp addresses",
        )
        self.parser.add_argument(
            "--tester-addr",
            type=auto_int,
            default=0x6F1,
            help="tester address for --extended",
        )
        self.parser.add_argument(
            "--query",
            action="store_true",
            help="query ECU description via RDBID",
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
            default=5,
            type=int,
            metavar="SECONDS",
            help="Time in seconds to sniff on bus for current traffic",
        )

    async def setup(self, args: Namespace) -> None:
        if args.target is not None and not args.target.scheme == RawCANTransport.SCHEME:
            self.parser.error(
                f"Unsupported transport schema {args.target.scheme}; must be can-raw!"
            )
        if args.extended_addr and (args.start > 0xFF or args.stop > 0xFF):
            self.parser.error("--start/--stop maximum value is 0xFF")
        await super().setup(args)

    async def query_description(self, target_list: list[TargetURI], did: int) -> None:
        self.logger.info("reading info DID from all discovered endpoints")
        for target in target_list:
            self.logger.result("----------------------------")
            self.logger.result(f"Probing ECU: {target}")

            transport = await ISOTPTransport.connect(target)
            uds_client = UDSClient(transport, timeout=2)
            self.logger.result(f"reading device description at {g_repr(did)}")
            try:
                resp = await uds_client.read_data_by_identifier(did)
                if isinstance(resp, NegativeResponse):
                    self.logger.result(f"could not read did: {resp}")
                else:
                    self.logger.result(f"response was: {resp}")
            except Exception as e:
                self.logger.result(f"reading description failed: {e!r}")

    def _build_isotp_frame_extended(
        self,
        pdu: bytes,
        ext_addr: int,
    ) -> bytes:
        isotp_hdr = bytes([ext_addr, len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def _build_isotp_frame(self, pdu: bytes) -> bytes:
        isotp_hdr = bytes([len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def build_isotp_frame(
        self,
        req: UDSRequest,
        ext_addr: int | None = None,
        padding: int | None = None,
    ) -> bytes:
        pdu = req.pdu
        max_pdu_len = 7 if ext_addr is None else 6
        if len(pdu) > max_pdu_len:
            raise ValueError("UDSRequest too large, ConsecutiveFrames not implemented")

        if ext_addr is None:
            frame = self._build_isotp_frame(pdu)
        else:
            frame = self._build_isotp_frame_extended(pdu, ext_addr)

        if padding is not None:
            pad_len = 8 - len(frame)
            frame += bytes([padding]) * pad_len

        return frame

    async def main(self, args: Namespace) -> None:
        transport = await RawCANTransport.connect(args.target)
        found = []

        sniff_time: int = args.sniff_time
        self.logger.result(f"Recording idle bus communication for {sniff_time}s")
        addr_idle = await transport.get_idle_traffic(sniff_time)

        self.logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)

        req = UDSRequest.parse_dynamic(args.pdu)
        pdu = self.build_isotp_frame(req, padding=args.padding)

        for ID in range(args.start, args.stop + 1):
            await asyncio.sleep(args.sleep)

            dst_addr = args.tester_addr if args.extended_addr else ID
            if args.extended_addr:
                pdu = self.build_isotp_frame(req, ID, padding=args.padding)

            self.logger.info(f"Testing ID {can_id_repr(ID)}")
            is_broadcast = False

            await transport.sendto(pdu, timeout=0.1, dst=dst_addr)
            try:
                addr, _ = await transport.recvfrom(timeout=0.1)
                if addr == ID:
                    self.logger.info(
                        f"The same CAN ID {can_id_repr(ID)} answered. Skipping…"
                    )
                    continue
            except asyncio.TimeoutError:
                continue

            while True:
                # The recv buffer needs to be flushed to avoid
                # wrong results...
                try:
                    new_addr, _ = await transport.recvfrom(timeout=0.1)
                    if new_addr != addr:
                        is_broadcast = True
                        self.logger.result(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(new_addr)}"
                        )
                    else:
                        self.logger.info(
                            f"seems like a large ISO-TP packet was received on CAN ID {can_id_repr(ID)}"
                        )
                except asyncio.TimeoutError:
                    if is_broadcast:
                        self.logger.result(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(addr)}"
                        )
                    else:
                        self.logger.result(
                            f"found endpoint on CAN ID [src:dst]: {can_id_repr(ID)}:{can_id_repr(addr)}"
                        )
                        target_args = {}
                        target_args["is_fd"] = str(transport.config.is_fd).lower()
                        target_args["is_extended"] = str(
                            transport.config.is_extended
                        ).lower()

                        if args.extended_addr:
                            target_args["ext_address"] = hex(ID)
                            target_args["rx_ext_address"] = hex(args.tester_addr & 0xFF)
                            target_args["src_addr"] = hex(args.tester_addr)
                            target_args["dst_addr"] = hex(addr)
                        else:
                            target_args["src_addr"] = hex(ID)
                            target_args["dst_addr"] = hex(addr)

                        if args.padding is not None:
                            target_args["tx_padding"] = f"{args.padding}"
                        if args.padding is not None:
                            target_args["rx_padding"] = f"{args.padding}"

                        target = TargetURI.from_parts(
                            ISOTPTransport.SCHEME,
                            args.target.hostname,
                            None,
                            target_args,
                        )
                        found.append(target)
                    break

        self.logger.result(f"finished; found {len(found)} UDS endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        self.logger.result(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)

        if args.query:
            await self.query_description(found, args.info_did)
