# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import socket
import struct
from argparse import ArgumentParser, Namespace

from gallia.command import AsyncScript
from gallia.config import Config
from gallia.services.uds.core.utils import bytes_repr, g_repr
from gallia.transports import RawCANTransport, TargetURI
from gallia.utils import can_id_repr


class FindXCP(AsyncScript):
    """Find XCP Slave"""

    GROUP = "discover"
    COMMAND = "xcp"
    SHORT_HELP = "XCP enumeration scanner"
    HAS_ARTIFACTS_DIR = True

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)
        self.socket: socket.socket

    def configure_parser(self) -> None:
        subparsers = self.parser.add_subparsers(
            dest="mode", required=True, help="Transport mode"
        )

        sp = subparsers.add_parser("can")
        sp.add_argument(
            "--xcp-can-iface",
            type=str,
            default="",
            required=True,
            help="CAN interface used for XCP communication",
        )
        sp.add_argument(
            "--can-fd", action="store_true", default=False, help="use can FD"
        )
        sp.add_argument(
            "--sniff-time",
            default=60,
            type=int,
            metavar="SECONDS",
            help="Time in seconds to sniff on bus for current traffic",
        )

        sp = subparsers.add_parser("tcp")
        sp.add_argument(
            "--xcp-ip",
            type=str,
            default="",
            required=True,
            help="XCP destination IP Address",
        )
        sp.add_argument(
            "--tcp-ports",
            type=str,
            default="",
            required=True,
            help="Comma separated list of TCP ports to test for XCP",
        )

        sp = subparsers.add_parser("udp")
        sp.add_argument(
            "--xcp-ip",
            type=str,
            default="",
            required=True,
            help="XCP destination IP Address",
        )
        sp.add_argument(
            "--udp-ports",
            type=str,
            default="",
            required=True,
            help="Comma separated list of UDP ports to test for XCP",
        )

    def pack_xcp_eth(self, data: bytes, ctr: int = 0) -> bytes:
        length = len(data)
        data = struct.pack("<HH", length, ctr) + data
        self.logger.info(f"send: {data.hex()}")
        return data

    def unpack_xcp_eth(self, data: bytes) -> tuple[int, int, bytes]:
        length, ctr = struct.unpack_from("<HH", data)
        self.logger.info(f"recv: {data.hex()}")
        return length, ctr, data[4:]

    async def main(self, args: Namespace) -> None:
        if args.mode == "can":
            await self.test_can(args)

        elif args.mode == "tcp":
            await self.test_tcp(args)

        elif args.mode == "udp":
            self.test_eth_broadcast(args)
            await self.test_udp(args)

    async def test_tcp(self, args: Namespace) -> None:
        # TODO: rewrite as async

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in args.tcp_ports.split(","):
            port = int(port, 0)
            self.logger.info(f"Testing TCP port: {port}")
            server = (args.xcp_ip, port)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(0.2)
            try:
                self.socket.connect(server)
            except Exception as e:
                self.logger.info(f"Connect: {g_repr(e)} on TCP port {port}")
                continue

            try:
                self.socket.send(self.pack_xcp_eth(data))
                _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
                ret = bytes_repr(data_ret)
                self.logger.info(f"Receive data on TCP port {port}: {ret}")
                if len(data_ret) > 0 and data_ret[0] == 0xFF:
                    self.logger.result(f"XCP Slave on TCP port {port}, data: {ret}")
                    endpoints.append(port)
                else:
                    self.logger.info(f"TCP port {port} is no XCP slave, data: {ret}")
            except Exception as e:
                self.logger.info(f"send/recv: {g_repr(e)} on TCP port {port:d}")
                continue

            self.xcp_disconnect(server)
            self.socket.close()

        self.logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via TCP")

    def xcp_disconnect(self, server: tuple[str, int]) -> None:
        try:
            self.socket.sendto(self.pack_xcp_eth(bytes([0xFE, 0x00]), 1), server)
            self.socket.recv(1024)
        except Exception:
            pass

    async def test_udp(self, args: Namespace) -> None:
        # TODO: rewrite as async

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in args.udp_ports.split(","):
            port = int(port, 0)
            self.logger.info(f"Testing UDP port: {port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(0.5)
            server = (args.xcp_ip, port)
            self.socket.sendto(self.pack_xcp_eth(data), server)
            try:
                _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
                ret = bytes_repr(data_ret)
                self.logger.info(f"Receive data on TCP port {port}: {ret}")
                if len(data_ret) > 0 and data_ret[0] == 0xFF:
                    self.logger.result(f"XCP Slave on UDP port {port}, data: {ret}")
                    endpoints.append(port)
                else:
                    self.logger.info(f"UDP port {port} is no XCP slave, data: {ret}")

            except socket.timeout:
                self.logger.info(f"Timeout on UDP port {port}")

            self.xcp_disconnect(server)
            self.socket.close()

        self.logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via UDP")

    async def test_can(self, args: Namespace) -> None:
        target = TargetURI(
            f"{RawCANTransport.SCHEME}://{args.xcp_can_iface}"
            + ("?is_fd=true" if args.can_fd else "")
        )
        transport = await RawCANTransport.connect(target)
        endpoints = []

        sniff_time: int = args.sniff_time
        self.logger.result(f"Listening to idle bus communication for {sniff_time}s...")
        addr_idle = await transport.get_idle_traffic(sniff_time)
        self.logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)
        # flush receive queue
        await transport.get_idle_traffic(2)

        for can_id in range(0x800):
            self.logger.info(f"Testing CAN ID: {can_id_repr(can_id)}")
            pdu = bytes([0xFF, 0x00])
            await transport.sendto(pdu, can_id, timeout=0.1)

            try:
                while True:
                    master, data = await transport.recvfrom(timeout=0.1)
                    if data[0] == 0xFF:
                        msg = (
                            f"Found XCP endpoint [master:slave]: CAN: {can_id_repr(master)}:{can_id_repr(can_id)} "
                            f"data: {bytes_repr(data)}"
                        )
                        self.logger.result(msg)
                        endpoints.append((can_id, master))
                    else:
                        self.logger.info(
                            f"Received non XCP answer for CAN-ID {can_id_repr(can_id)}: {can_id_repr(master)}:"
                            f"{bytes_repr(data)}"
                        )
            except asyncio.TimeoutError:
                pass

        self.logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via CAN")

    def test_eth_broadcast(self, args: Namespace) -> None:
        # TODO: rewrite as async

        multicast_group = ("239.255.0.0", 5556)
        self.logger.result(
            f"Discover XCP via multicast group: {multicast_group[0]}:{multicast_group[1]}"
        )

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((args.xcp_ip, 5555))
        addr = self.socket.getsockname()[0]
        self.socket.close()
        self.logger.info(f"xcp interface ip for multicast group: {addr}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr)
        )
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
        self.socket.settimeout(2)

        xcp_discover = bytes([0xFA, 0x01])
        endpoints = []
        self.socket.sendto(self.pack_xcp_eth(xcp_discover), multicast_group)
        try:
            while True:
                data, slave = self.socket.recvfrom(16)
                if not data:
                    break

                self.logger.result(f"Found XCP slave: {slave} {bytes_repr(data)}")
                endpoints.append(slave)
        except socket.timeout:
            self.logger.info("Timeout")

        self.logger.result(
            f"Finished; Found {len(endpoints)} XCP endpoints via multicast group"
        )
