# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import socket
import struct
import sys
from abc import ABC

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field, Ranges
from gallia.log import get_logger
from gallia.services.uds.core.utils import bytes_repr, g_repr
from gallia.transports import RawCANTransport, TargetURI

logger = get_logger(__name__)


class FindXCPConfig(AsyncScriptConfig):
    pass


class CanFindXCPConfig(FindXCPConfig):
    iface: str = Field(description="CAN interface used for XCP communication")
    send_can_fd: bool = Field(False, description="Send CAN-FD frames")
    force_extended: bool = Field(False, description="Force extended ID bit for IDs < 0x7ff")
    sniff_time: int = Field(
        60, description="Time in seconds to sniff on bus for current traffic", metavar="SECONDS"
    )
    start: AutoInt = Field(description="First CAN id to test")
    stop: AutoInt = Field(description="Last CAN id to test")


class TcpFindXCPConfig(FindXCPConfig):
    xcp_ip: str = Field(description="XCP destination IP Address")
    tcp_ports: Ranges = Field(description="List of TCP ports to test for XCP")


class UdpFindXCPConfig(FindXCPConfig):
    xcp_ip: str = Field(description="XCP destination IP Address")
    udp_ports: Ranges = Field(description="List of UDP ports to test for XCP")


class FindXCP(AsyncScript, ABC):
    """Find XCP Slave"""

    def __init__(self, config: FindXCPConfig):
        super().__init__(config)
        self.config: FindXCPConfig = config
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

    def xcp_disconnect(self, server: tuple[str, int]) -> None:
        try:
            self.socket.sendto(self.pack_xcp_eth(bytes([0xFE, 0x00]), 1), server)
            self.socket.recv(1024)
        except Exception:
            pass


class CanFindXCP(FindXCP):
    CONFIG_TYPE = CanFindXCPConfig
    SHORT_HELP = "XCP enumeration scanner for CAN"

    def __init__(self, config: CanFindXCPConfig):
        super().__init__(config)
        self.config: CanFindXCPConfig = config

    async def main(self) -> None:
        target = TargetURI(
            f"{RawCANTransport.SCHEME}://{self.config.iface}?force_extended={str(self.config.force_extended).lower()}"
            + ("&is_fd=true" if self.config.send_can_fd else "")
        )
        transport = RawCANTransport(target)
        await transport.connect()

        found_endpoints = []

        logger.result(f"Listening to idle bus communication for {self.config.sniff_time}s...")

        addr_idle, fd_frames_present = await transport.get_idle_traffic(self.config.sniff_time)

        if fd_frames_present is True and self.config.send_can_fd is False:
            logger.warning(
                "FD frames were observed, but you are sending non-FD frames! Consider using --send-can-fd flag!"
            )

        logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)
        # flush receive queue
        await transport.get_idle_traffic(2)

        for tx_id in range(self.config.start, self.config.stop + 1):
            logger.info(f"Testing CAN ID: {hex(tx_id)}")

            # XCP_CONNECT
            pdu = bytes([0xFF, 0x00])
            await transport.sendto(pdu, tx_id, timeout=0.1)

            try:
                while True:
                    can_message = await transport.recv_can_message(timeout=0.1)
                    rx_id, data = can_message.arbitration_id, can_message.data

                    if can_message.is_fd != self.config.send_can_fd:
                        logger.warning(
                            "Sent and received CAN frames have mismatching use of CAN-FD! (Re-)consider the use of --send-can-fd flag!"
                        )

                    if not len(data) > 0:
                        logger.warning(f"Received no data from {hex(rx_id)}")
                        continue

                    # 0xFF = positive reply, 0xFE = negative reply
                    if data[0] == 0xFF:
                        logger.notice(
                            f"XCP_CONNECT triggered positive reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                    elif data[0] == 0xFE:
                        logger.notice(
                            f"XCP_CONNECT triggered negative reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                    else:
                        logger.notice(
                            f"XCP_CONNECT triggered non-XCP reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                        continue

                    # XCP_DISCONNECT
                    pdu = bytes([0xFE, 0x00])
                    await transport.sendto(pdu, tx_id, timeout=0.1)

                    new_rx_id, data = await transport.recvfrom(timeout=0.5)
                    if new_rx_id != rx_id:
                        logger.notice(
                            f"XCP_DISCONNECT was not successful, received response from different ID: {hex(new_rx_id)}"
                        )
                        continue

                    # 0xFF = positive reply, 0xFE = negative reply
                    if data[0] == 0xFF:
                        logger.notice(
                            f"XCP_DISCONNECT triggered positive reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                    elif data[0] == 0xFE:
                        logger.notice(
                            f"XCP_DISCONNECT triggered negative reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                    else:
                        logger.notice(
                            f"XCP_DISCONNECT triggered non-XCP reply for {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]:{bytes_repr(data)}"
                        )
                        continue

                    logger.result(f"Found XCP endpoint {hex(tx_id)}:{hex(rx_id)} [tx_id:rx_id]")
                    found_endpoints.append((tx_id, rx_id))

            except TimeoutError:
                pass

        logger.result(f"Finished; Found {len(found_endpoints)} XCP endpoints via CAN")


class TcpFindXCP(FindXCP):
    CONFIG_TYPE = TcpFindXCPConfig
    SHORT_HELP = "XCP enumeration scanner for TCP"

    def __init__(self, config: TcpFindXCPConfig):
        super().__init__(config)
        self.config: TcpFindXCPConfig = config

    async def main(self) -> None:
        # TODO: rewrite as async

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in self.config.tcp_ports:
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
            finally:
                self.xcp_disconnect(server)
                self.socket.close()

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via TCP")


class UdpFindXCP(FindXCP):
    CONFIG_TYPE = UdpFindXCPConfig
    SHORT_HELP = "XCP enumeration scanner for Udp"

    def __init__(self, config: UdpFindXCPConfig):
        super().__init__(config)
        self.config: UdpFindXCPConfig = config

    async def main(self) -> None:
        self.test_eth_broadcast()
        await self.test_udp()

    async def test_udp(self) -> None:
        # TODO: rewrite as async

        data = bytes([0xFF, 0x00])
        endpoints = []
        for port in self.config.udp_ports:
            logger.info(f"Testing UDP port: {port}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(0.5)
            server = (self.config.xcp_ip, port)
            self.socket.sendto(self.pack_xcp_eth(data), server)
            try:
                _, _, data_ret = self.unpack_xcp_eth(self.socket.recv(1024))
                ret = bytes_repr(data_ret)
                logger.info(f"Receive data on UDP port {port}: {ret}")
                if len(data_ret) > 0 and data_ret[0] == 0xFF:
                    logger.result(f"XCP Slave on UDP port {port}, data: {ret}")
                    endpoints.append(port)
                else:
                    logger.info(f"UDP port {port} is no XCP slave, data: {ret}")

            except TimeoutError:
                logger.info(f"Timeout on UDP port {port}")

            finally:
                self.xcp_disconnect(server)
                self.socket.close()

        logger.result(f"Finished; Found {len(endpoints)} XCP endpoints via UDP")

    def test_eth_broadcast(self) -> None:
        # TODO: rewrite as async

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
