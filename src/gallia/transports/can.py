# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import socket as s
import struct
import time

from can import Message
from pydantic import BaseModel, field_validator

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import auto_int

logger = get_logger("gallia.transport.can-raw")

CANFD_MTU = 72
CAN_MTU = 16


class CANMessage(Message):
    # https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/can.h
    CAN_HEADER_FMT = struct.Struct("=IBB2x")
    CANFD_BRS = 0x01
    CANFD_ESI = 0x02

    def _compose_arbitration_id(self) -> int:
        can_id = self.arbitration_id
        if self.is_extended_id:
            can_id |= s.CAN_EFF_FLAG
        if self.is_remote_frame:
            can_id |= s.CAN_RTR_FLAG
        if self.is_error_frame:
            can_id |= s.CAN_ERR_FLAG
        return can_id

    def pack(self) -> bytes:
        can_id = self._compose_arbitration_id()
        flags = 0
        if self.bitrate_switch:
            flags |= self.CANFD_BRS
        if self.error_state_indicator:
            flags |= self.CANFD_ESI
        max_len = 64 if self.is_fd else 8
        data = bytes(self.data).ljust(max_len, b"\x00")
        return self.CAN_HEADER_FMT.pack(can_id, self.dlc, flags) + data

    @staticmethod
    def _dissect_can_frame(frame: bytes) -> tuple[int, int, int, bytes]:
        can_id, can_dlc, flags = CANMessage.CAN_HEADER_FMT.unpack_from(frame)
        if len(frame) != CANFD_MTU:
            # Flags not valid in non-FD frames
            flags = 0
        return can_id, can_dlc, flags, frame[8 : 8 + can_dlc]

    @classmethod
    def unpack(cls, frame: bytes) -> CANMessage:
        can_id, can_dlc, flags, data = cls._dissect_can_frame(frame)

        # EXT, RTR, ERR flags -> boolean attributes
        #   /* special address description flags for the CAN_ID */
        #   #define CAN_EFF_FLAG 0x80000000U /* EFF/SFF is set in the MSB */
        #   #define CAN_RTR_FLAG 0x40000000U /* remote transmission request */
        #   #define CAN_ERR_FLAG 0x20000000U /* error frame */
        is_extended_frame_format = bool(can_id & s.CAN_EFF_FLAG)
        is_remote_transmission_request = bool(can_id & s.CAN_RTR_FLAG)
        is_error_frame = bool(can_id & s.CAN_ERR_FLAG)
        is_fd = len(frame) == CANFD_MTU
        bitrate_switch = bool(flags & cls.CANFD_BRS)
        error_state_indicator = bool(flags & cls.CANFD_ESI)

        if is_extended_frame_format:
            arbitration_id = can_id & s.CAN_EFF_MASK
        else:
            arbitration_id = can_id & s.CAN_SFF_MASK

        return cls(
            arbitration_id=arbitration_id,
            is_extended_id=is_extended_frame_format,
            is_remote_frame=is_remote_transmission_request,
            is_error_frame=is_error_frame,
            is_fd=is_fd,
            bitrate_switch=bitrate_switch,
            error_state_indicator=error_state_indicator,
            dlc=can_dlc,
            data=data,
        )


class RawCANConfig(BaseModel):
    is_extended: bool = False
    is_fd: bool = False
    dst_id: int | None = None

    @field_validator(
        "dst_id",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class RawCANTransport(BaseTransport, scheme="can-raw"):
    # Flags for setsockopt CAN_RAW_FILTER
    CAN_INV_FILTER = 0x20000000

    def __init__(self, target: TargetURI, config: RawCANConfig, sock: s.socket) -> None:
        super().__init__(target)

        self._sock = sock
        self.config = config

    @classmethod
    async def connect(
        cls, target: str | TargetURI, timeout: float | None = None
    ) -> RawCANTransport:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        cls.check_scheme(t)

        if t.hostname is None:
            raise ValueError("empty interface")

        sock = s.socket(s.PF_CAN, s.SOCK_RAW, s.CAN_RAW)
        sock.bind((t.hostname,))
        config = RawCANConfig(**t.qs_flat)

        if config.is_fd is True:
            sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_FD_FRAMES, 1)

        sock.setblocking(False)

        return cls(t, config, sock)

    def set_filter(self, can_ids: list[int], inv_filter: bool = False) -> None:
        if not can_ids:
            return
        filter_mask = s.CAN_EFF_MASK if self.config.is_extended else s.CAN_SFF_MASK
        data = b""
        for can_id in can_ids:
            if inv_filter:
                can_id |= self.CAN_INV_FILTER  # noqa: PLW2901
            data += struct.pack("@II", can_id, filter_mask)
        self._sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_FILTER, data)
        if inv_filter:
            self._sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_JOIN_FILTERS, 1)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        raise RuntimeError("RawCANTransport is a special snowflake")

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        if self.config.dst_id:
            return await self.sendto(data, self.config.dst_id, timeout, tags)
        raise ValueError("dst_id not set")

    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        msg = CANMessage(
            arbitration_id=dst,
            data=data,
            is_extended_id=self.config.is_extended,
            is_fd=self.config.is_fd,
            check=True,
        )
        t = tags + ["write"] if tags is not None else ["write"]
        if self.config.is_extended:
            logger.trace(f"{dst:08x}#{data.hex()}", extra={"tags": t})
        else:
            logger.trace(f"{dst:03x}#{data.hex()}", extra={"tags": t})

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, msg.pack()), timeout)
        return len(data)

    async def recvfrom(
        self, timeout: float | None = None, tags: list[str] | None = None
    ) -> tuple[int, bytes]:
        loop = asyncio.get_running_loop()
        can_frame = await asyncio.wait_for(
            loop.sock_recv(self._sock, self.BUFSIZE), timeout
        )
        msg = CANMessage.unpack(can_frame)

        t = tags + ["read"] if tags is not None else ["read"]
        if msg.is_extended_id:
            logger.trace(
                f"{msg.arbitration_id:08x}#{msg.data.hex()}", extra={"tags": t}
            )
        else:
            logger.trace(
                f"{msg.arbitration_id:03x}#{msg.data.hex()}", extra={"tags": t}
            )
        return msg.arbitration_id, msg.data

    async def close(self) -> None:
        pass

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
            except asyncio.TimeoutError:
                continue
        addr_idle.sort()
        return addr_idle
