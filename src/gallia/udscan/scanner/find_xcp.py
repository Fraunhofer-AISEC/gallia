import asyncio
import io
import struct
from argparse import Namespace

from gallia.udscan.core import Scanner
from gallia.transports.can import RawCANTransport


def pack_xcp_eth(data: bytes, ctr: int = 0) -> bytes:
    return struct.pack("<HH", len(data), ctr) + data


def unpack_xcp_eth(data: bytes) -> tuple[int, int, bytes]:
    length, ctr = struct.unpack_from("<HH", data)
    return length, ctr, data[4:]


class FindXCP(Scanner):
    """Find XCP Slave"""

    async def test_tcp(self, args: Namespace) -> None:
        assert self.transport is not None

        data = bytes([0xFF, 0x00])
        await self.transport.write(pack_xcp_eth(data))
        _, _, data_ret = unpack_xcp_eth(await self.transport.read(io.DEFAULT_BUFFER_SIZE))
        if data_ret[0] == 0xff:
            self.logger.log_summary(f"XCP Slave on {args.target}")
            # Close XCP.
            await self.transport.write(pack_xcp_eth(bytes([0xFE, 0x00]), 1))
        else:
            self.logger.log_info(f"{args.target} reacats but is not an XCP slave")

    # async def test_udp(self, args: Namespace) -> None:
    #     # TODO: rewrite as async
    #
    #     data = bytes([0xFF, 0x00])
    #     endpoints = list()
    #     for port in args.udp_ports.split(","):
    #         port = int(port, 0)
    #         self.logger.log_info(f"Testing UDP port: {port}")
    #         self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #         self.socket.settimeout(0.5)
    #         server = (args.xcp_ip, port)
    #         self.socket.sendto(self.pack_xcp_eth(data), server)
    #         try:
    #             _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
    #             ret = data_ret.hex()
    #             self.logger.log_info(f"Receive data on UDP port {port}: {ret}")
    #             if ret.startswith("ff"):
    #                 self.logger.log_summary(
    #                     f"XCP Slave on UDP port {port}, data: {ret}"
    #                 )
    #                 endpoints.append(port)
    #             else:
    #                 self.logger.log_info(
    #                     f"UDP port {port} is no XCP slave, data: {shorten(ret)}"
    #                 )
    #
    #         except socket.timeout:
    #             self.logger.log_info(f"Timeout on UDP port {port}")
    #
    #         self.xcp_disconnect(server)
    #         self.socket.close()
    #
    #     self.logger.log_summary(
    #         f"Finished; Found {len(endpoints)} XCP endpoints via UDP"
    #     )
    #
    async def test_can(self, args: Namespace) -> None:
        assert isinstance(self.transport, RawCANTransport)

        endpoints = list()

        sniff_time: int = args.sniff_time
        self.logger.log_summary(
            f"Listening to idle bus communication for {sniff_time}s..."
        )
        addr_idle = await self.transport.get_idle_traffic(sniff_time)
        self.logger.log_summary(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        self.transport.set_filter(addr_idle, inv_filter=True)
        # flush receive queue
        await self.transport.get_idle_traffic(2)

        for can_id in range(0x800):
            self.logger.log_info(f"Testing CAN ID: {can_id:03x}")
            pdu = bytes([0xFF, 0x00])
            await self.transport.sendto(pdu, can_id, timeout=0.1)

            try:
                while True:
                    master, data = await self.transport.recvfrom(timeout=0.1)
                    if data[0] == 0xFF:
                        msg = f"Found XCP endpoint [master:slave]: CAN: {master:x}:{can_id:x} data: {data.hex()}"
                        self.logger.log_summary(msg)
                        endpoints.append((can_id, master))
                    else:
                        self.logger.log_info(
                            f"Received non XCP answer for CAN-ID {can_id:x}: {master:x}:{data.hex()}"
                        )
            except asyncio.TimeoutError:
                pass

        self.logger.log_summary(
            f"Finished; Found {len(endpoints)} XCP endpoints via CAN"
        )

    # def test_eth_broadcast(self, args: Namespace) -> None:
    #     # TODO: rewrite as async
    #
    #     multicast_group = ("239.255.0.0", 5556)
    #     self.logger.log_summary(
    #         f"Discover XCP via multicast group: {multicast_group[0]}:{multicast_group[1]}"
    #     )
    #
    #     self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     self.socket.connect((args.xcp_ip, 5555))
    #     addr = self.socket.getsockname()[0]
    #     self.socket.close()
    #     self.logger.log_info(f"xcp interface ip for multicast group: {addr}")
    #
    #     self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     self.socket.setsockopt(
    #         socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr)
    #     )
    #     self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    #     self.socket.settimeout(2)
    #
    #     xcp_discover = bytes([0xFA, 0x01])
    #     endpoints = list()
    #     self.socket.sendto(pack_xcp_eth(xcp_discover), multicast_group)
    #     try:
    #         while True:
    #             data, slave = self.socket.recvfrom(16)
    #             if not data:
    #                 break
    #
    #             self.logger.log_summary(f"Found XCP slave: {slave} {data.hex()}")
    #             endpoints.append(slave)
    #     except socket.timeout:
    #         self.logger.log_info("Timeout")
    #
    #     self.logger.log_summary(
    #         f"Finished; Found {len(endpoints)} XCP endpoints via multicast group"
    #     )
    #
    async def main(self, args: Namespace) -> None:
        if args.target.scheme == "can-raw":
            await self.test_can(args)
        elif args.target.scheme == "tcp":
            await self.test_tcp(args)
        # elif args.target.scheme == "udp":
        #     self.test_eth_broadcast(args)
        #     await self.test_udp(args)

        raise ValueError(f"{args.target.scheme} is not supported")
