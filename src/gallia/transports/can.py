# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import socket as s
import struct
import sys
import time
from dataclasses import dataclass
from typing import Self

assert sys.platform.startswith("linux"), "unsupported platform"

from pydantic import BaseModel

from gallia.dumpcap import dumpcap_argument_list_can
from gallia.log import get_logger
from gallia.transports._can_constants import (
    CAN_EFF_FLAG,
    CAN_EFF_MASK,
    CAN_ERR_FLAG,
    CAN_HEADER_FMT,
    CAN_INV_FILTER,
    CAN_RAW,
    CAN_RAW_FD_FRAMES,
    CAN_RAW_FILTER,
    CAN_RAW_JOIN_FILTERS,
    CAN_RTR_FLAG,
    CAN_SFF_MASK,
    CANFD_BRS,
    CANFD_ESI,
    CANFD_MTU,
    SOL_CAN_RAW,
)
from gallia.transports.base import BaseTransport, TargetURI

logger = get_logger(__name__)


@dataclass(kw_only=True, slots=True, frozen=True)
class CANMessage:
    timestamp: float = 0.0
    arbitration_id: int = 0
    force_extended_id: bool = False

    # TODO: Add a frametype attribute?
    is_remote_frame: bool = False
    is_error_frame: bool = False

    dlc: int | None = None
    data: bytes = b""
    is_fd: bool = False
    is_rx: bool = True
    bitrate_switch: bool = False
    error_state_indicator: bool = False

    # TODO: Is this semantically correct? Check this.
    def __len__(self) -> int:
        if self.dlc is None:
            return len(self.data)
        return self.dlc

    def _compose_arbitration_id(self) -> int:
        can_id = self.arbitration_id
        if can_id > CAN_SFF_MASK or self.force_extended_id:
            can_id |= CAN_EFF_FLAG
        if self.is_remote_frame:
            can_id |= CAN_RTR_FLAG
        if self.is_error_frame:
            can_id |= CAN_ERR_FLAG
        return can_id

    def pack(self) -> bytes:
        can_id = self._compose_arbitration_id()
        flags = 0
        if self.bitrate_switch:
            flags |= CANFD_BRS
        if self.error_state_indicator:
            flags |= CANFD_ESI
        max_len = 64 if self.is_fd else 8
        data = bytes(self.data).ljust(max_len, b"\x00")
        return CAN_HEADER_FMT.pack(can_id, len(self), flags) + data

    @staticmethod
    def _dissect_can_frame(frame: bytes) -> tuple[int, int, int, bytes]:
        can_id, can_dlc, flags = CAN_HEADER_FMT.unpack_from(frame)
        if len(frame) != CANFD_MTU:
            # Flags not valid in non-FD frames
            flags = 0
        return can_id, can_dlc, flags, frame[8 : 8 + can_dlc]

    @classmethod
    def unpack(cls, frame: bytes) -> Self:
        can_id, can_dlc, flags, data = cls._dissect_can_frame(frame)

        # EXT, RTR, ERR flags -> boolean attributes
        #   /* special address description flags for the CAN_ID */
        #   #define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
        #   #define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
        #   #define CAN_ERR_FLAG 0x20000000U /* error frame */
        is_extended_frame_format = bool(can_id & CAN_EFF_FLAG)
        is_remote_transmission_request = bool(can_id & CAN_RTR_FLAG)
        is_error_frame = bool(can_id & CAN_ERR_FLAG)
        is_fd = len(frame) == CANFD_MTU
        bitrate_switch = bool(flags & CANFD_BRS)
        error_state_indicator = bool(flags & CANFD_ESI)

        if is_extended_frame_format:
            arbitration_id = can_id & CAN_EFF_MASK
        else:
            arbitration_id = can_id & CAN_SFF_MASK

        return cls(
            arbitration_id=arbitration_id,
            is_remote_frame=is_remote_transmission_request,
            is_error_frame=is_error_frame,
            is_fd=is_fd,
            bitrate_switch=bitrate_switch,
            error_state_indicator=error_state_indicator,
            dlc=can_dlc,
            data=data,
        )


class RawCANConfig(BaseModel):
    is_fd: bool = False
    force_extended_ids: bool = False


class RawCANTransport(BaseTransport, scheme="can-raw"):
    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)

        self.config = RawCANConfig.model_validate(self.target.qs_flat)
        self._sock: s.socket | None = None

    async def connect(
        self,
        timeout: float | None = None,
    ) -> None:
        if self._sock is not None:
            logger.warning("Socket is already connected, not connecting a second time!")
            return

        if self.target.hostname is None:
            raise ValueError("empty interface")

        sock = s.socket(s.PF_CAN, s.SOCK_RAW, CAN_RAW)
        sock.bind((self.target.hostname,))

        if self.config.is_fd is True:
            sock.setsockopt(SOL_CAN_RAW, CAN_RAW_FD_FRAMES, 1)

        sock.setblocking(False)

        self._sock = sock

    def set_filter(self, can_ids: list[int], inv_filter: bool = False) -> None:
        if self._sock is None:
            raise RuntimeError("Not connected, cannot set filter!")

        if not can_ids:
            return
        data = b""
        for can_id in can_ids:
            if inv_filter:
                can_id |= CAN_INV_FILTER  # noqa: PLW2901
            data += struct.pack(
                "@II",
                can_id,
                CAN_EFF_MASK
                if can_id > CAN_SFF_MASK or self.config.force_extended_ids
                else CAN_SFF_MASK,
            )
        self._sock.setsockopt(SOL_CAN_RAW, CAN_RAW_FILTER, data)
        if inv_filter:
            self._sock.setsockopt(SOL_CAN_RAW, CAN_RAW_JOIN_FILTERS, 1)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        raise NotImplementedError("RawCANTransport does not implement read(), use recvfrom()")

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        raise NotImplementedError("RawCANTransport does not implement write(), use sendto()")

    async def sendto(
        self,
        data: bytes,
        arbitration_id: int,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        if self._sock is None:
            raise RuntimeError("Not connected, cannot write!")

        msg = CANMessage(
            arbitration_id=arbitration_id,
            force_extended_id=self.config.force_extended_ids,
            data=data,
            is_fd=self.config.is_fd,
        )
        t = tags + ["write"] if tags is not None else ["write"]
        logger.trace(f"{hex(msg.arbitration_id)}#{msg.data.hex()}", extra={"tags": t})

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, msg.pack()), timeout)
        return len(data)

    async def recvfrom(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> tuple[int, bytes]:
        if self._sock is None:
            raise RuntimeError("Not connected, cannot read!")

        loop = asyncio.get_running_loop()
        can_frame = await asyncio.wait_for(loop.sock_recv(self._sock, self.BUFSIZE), timeout)
        msg = CANMessage.unpack(can_frame)

        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(f"{hex(msg.arbitration_id)}#{msg.data.hex()}", extra={"tags": t})
        return msg.arbitration_id, msg.data

    async def close(self) -> None:
        if self._sock is None:
            logger.debug("Socket already closed")
            return
        self._sock.close()
        self._sock = None

    async def get_idle_traffic(self, sniff_time: float) -> list[int]:
        """Listen to traffic on the bus and return list of IDs
        which are seen in the specified period of time.
        The output of this function can be used as input to set_filter.
        """
        addr_idle: list[int] = []
        t1 = time.time()
        while time.time() - t1 < sniff_time:
            try:
                addr, _ = await self.recvfrom(timeout=1)
                if addr not in addr_idle:
                    logger.info(f"Received a message from {addr:03x}")
                    addr_idle.append(addr)
            except TimeoutError:
                continue
        addr_idle.sort()
        return addr_idle

    async def dumpcap_argument_list(self) -> list[str] | None:
        return dumpcap_argument_list_can(self.target.netloc, None, None)
