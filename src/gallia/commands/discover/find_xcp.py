# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field
from gallia.log import get_logger
from gallia.services.uds.core.utils import bytes_repr
from gallia.transports import RawCANTransport, TargetURI

logger = get_logger(__name__)


class CanFindXCPConfig(AsyncScriptConfig):
    iface: str = Field(description="CAN interface used for XCP communication")
    send_can_fd: bool = Field(False, description="Send CAN-FD frames")
    force_extended: bool = Field(False, description="Force extended ID bit for IDs < 0x7ff")
    sniff_time: int = Field(
        60, description="Time in seconds to sniff on bus for current traffic", metavar="SECONDS"
    )
    start: AutoInt = Field(description="First CAN id to test")
    stop: AutoInt = Field(description="Last CAN id to test")


class CanFindXCP(AsyncScript):
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
