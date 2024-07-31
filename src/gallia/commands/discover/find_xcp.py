# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import socket
import struct
import sys

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field
from gallia.log import get_logger
from gallia.services.uds.core.utils import bytes_repr, g_repr
from gallia.transports import RawCANTransport, TargetURI
from gallia.utils import can_id_repr

logger = get_logger(__name__)


class FindXCPConfig(AsyncScriptConfig):
    pass


class CanFindXCPConfig(FindXCPConfig):
    xcp_can_iface: str = Field("", description="CAN interface used for XCP communication")
    can_fd: bool = Field(False, description="use can FD")
    extended: bool = Field(False, description="use extended CAN address space")
    sniff_time: int = Field(
        60, description="Time in seconds to sniff on bus for current traffic", metavar="SECONDS"
    )
    can_id_start: AutoInt = Field("", description="First CAN id to test")
    can_id_end: AutoInt = Field("", description="Last CAN id to test")


class TcpFindXCPConfig(FindXCPConfig):
    xcp_ip: str = Field("", description="XCP destination IP Address")
    tcp_ports: str = Field("", description="Comma separated list of TCP ports to test for XCP")


class UdpFindXCPConfig(FindXCPConfig):
    xcp_ip: str = Field("", description="XCP destination IP Address")
    udp_ports: str = Field("", description="Comma separated list of UDP ports to test for XCP")


class FindXCP(AsyncScript):
    """Find XCP Slave"""

    SHORT_HELP = "XCP enumeration scanner"
    HAS_ARTIFACTS_DIR = True

    def __init__(self, config: FindXCPConfig):
        super().__init__(config)
        self.config = config
        self.socket: socket.socket

    def pack_xcp_eth(self, data: bytes, ctr: int = 0) -> bytes:
        length = len(data)
        data = struct.pack("<HH", length, ctr) + data
        logger.info(f"send: {data.hex()}")
        return data

    def unpack_xcp_eth(self, data: bytes) -> tuple[int, int, bytes]:
        length, ctr = struct.unpack_from("<HH", data)
        logger.info(f"recv: {data.hex()}")
        return (length, ctr, data[4:])

    async def main(self) -> None:
        if isinstance(self.config, CanFindXCPConfig):
            await self.test_can()

        elif isinstance(self.config, TcpFindXCPConfig):
            await self.test_tcp()

        elif isinstance(self.config, UdpFindXCPConfig):
            self.test_eth_broadcast()
            await self.test_udp()

    async def test_tcp(self) -> None:
        # TODO: rewrite as async

        assert isinstance(self.config, TcpFindXCPConfig)

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in self.config.tcp_ports.split(","):
            port = int(port, 0)  # noqa
            logger.info(f"Testing TCP port: {port}")
            server = (self.config.xcp_ip, port)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(0.2)
            try:
                self.socket.connect(server)
            except Exception as e:
                logger.info(f"Connect: {g_repr(e)} on TCP port {port}")
                continue

            try:
                self.socket.send(self.pack_xcp_eth(data))
                _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
                ret = bytes_repr(data_ret)
                logger.info(f"Receive data on TCP port {port}: {ret}")
                if len(data_ret) > 0 and data_ret[0] == 0xFF:
                    logger.result(f"XCP Slave on TCP port {port}, data: {ret}")
                    endpoints.append(port)
                else:
                    logger.info(f"TCP port {port} is no XCP slave, data: {ret}")
            except Exception as e:
                logger.info(f"send/recv: {g_repr(e)} on TCP port {port:d}")
                continue

            self.xcp_disconnect(server)
            self.socket.close()

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via TCP")

    def xcp_disconnect(self, server: tuple[str, int]) -> None:
        try:
            self.socket.sendto(self.pack_xcp_eth(bytes([0xFE, 0x00]), 1), server)
            self.socket.recv(1024)
        except Exception:
            pass

    async def test_udp(self) -> None:
        # TODO: rewrite as async

        assert isinstance(self.config, UdpFindXCPConfig)

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in self.config.udp_ports.split(","):
            port = int(port, 0)  # noqa
            logger.info(f"Testing UDP port: {port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(0.5)
            server = (self.config.xcp_ip, port)
            self.socket.sendto(self.pack_xcp_eth(data), server)
            try:
                _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
                ret = bytes_repr(data_ret)
                logger.info(f"Receive data on TCP port {port}: {ret}")
                if len(data_ret) > 0 and data_ret[0] == 0xFF:
                    logger.result(f"XCP Slave on UDP port {port}, data: {ret}")
                    endpoints.append(port)
                else:
                    logger.info(f"UDP port {port} is no XCP slave, data: {ret}")

            except TimeoutError:
                logger.info(f"Timeout on UDP port {port}")

            self.xcp_disconnect(server)
            self.socket.close()

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via UDP")

    async def test_can(self) -> None:
        assert isinstance(self.config, CanFindXCPConfig)

        target = TargetURI(
            f"{RawCANTransport.SCHEME}://{self.config.xcp_can_iface}?is_extended={str(self.config.extended).lower()}"
            + ("&is_fd=true" if self.config.can_fd else "")
        )
        transport = await RawCANTransport.connect(target)
        endpoints = []

        sniff_time: int = self.config.sniff_time
        logger.result(f"Listening to idle bus communication for {sniff_time}s...")
        addr_idle = await transport.get_idle_traffic(sniff_time)
        logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)
        # flush receive queue
        await transport.get_idle_traffic(2)

        for can_id in range(self.config.can_id_start, self.config.can_id_end + 1):
            logger.info(f"Testing CAN ID: {can_id_repr(can_id)}")
            pdu = bytes([0xFF, 0x00])
            await transport.sendto(pdu, can_id, timeout=0.1)

            try:
                while True:
                    master, data = await transport.recvfrom(timeout=0.1)
                    if data[0] == 0xFF:
                        msg = f"Found XCP endpoint [master:slave]: CAN: {can_id_repr(master)}:{can_id_repr(can_id)} data: {bytes_repr(data)}"
                        logger.result(msg)
                        endpoints.append((can_id, master))
                    else:
                        logger.info(
                            f"Received non XCP answer for CAN-ID {can_id_repr(can_id)}: {can_id_repr(master)}:{bytes_repr(data)}"
                        )
            except TimeoutError:
                pass

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via CAN")

    def test_eth_broadcast(self) -> None:
        # TODO: rewrite as async

        assert isinstance(self.config, UdpFindXCPConfig)

        multicast_group = ("239.255.0.0", 5556)
        logger.result(
            f"Discover XCP via multicast group: {multicast_group[0]}:{multicast_group[1]}"
        )

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.config.xcp_ip, 5555))
        addr = self.socket.getsockname()[0]
        self.socket.close()
        logger.info(f"xcp interface ip for multicast group: {addr}")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))
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

                logger.result(f"Found XCP slave: {slave} {bytes_repr(data)}")
                endpoints.append(slave)
        except TimeoutError:
            logger.info("Timeout")

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via multicast group")
