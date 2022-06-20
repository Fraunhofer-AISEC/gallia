# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import errno
import socket as s
import struct
import time
from typing import Optional, TypedDict, cast

from can import Message

from gallia.transports.base import BaseTransport, TargetURI, _bool_spec, _int_spec

CANFD_MTU = 72
CAN_MTU = 16


_ISOTP_SPEC_TYPE = TypedDict(
    "_ISOTP_SPEC_TYPE",
    {
        "src_addr": int,
        "dst_addr": int,
        "is_extended": bool,
        "is_fd": bool,
        "frame_txtime": int,
        "ext_address": Optional[int],
        "rx_ext_address": Optional[int],
        "tx_padding": Optional[int],
        "rx_padding": Optional[int],
        "tx_dl": Optional[int],
    },
)

isotp_spec = {
    "src_addr": (_int_spec(0), True),
    "dst_addr": (_int_spec(0), True),
    "is_extended": (_bool_spec(False), False),
    "is_fd": (_bool_spec(False), False),
    "frame_txtime": (_int_spec(10), False),
    "ext_address": (_int_spec(None), False),
    "rx_ext_address": (_int_spec(None), False),
    "tx_padding": (_int_spec(None), False),
    "rx_padding": (_int_spec(None), False),
    "tx_dl": (_int_spec(None), False),
}


class ISOTPTransport(BaseTransport, scheme="isotp", spec=isotp_spec):
    # Socket Constants not available in the socket module,
    # see linux/can/isotp.h
    # TODO: Can be removed in the future…
    # https://github.com/python/cpython/pull/23794
    SOL_CAN_ISOTP = s.SOL_CAN_BASE + s.CAN_ISOTP

    # Valuetypes for SOL_CAN_ISOTP
    CAN_ISOTP_OPTS = 1
    CAN_ISOTP_RECV_FC = 2
    CAN_ISOTP_TX_STMIN = 3
    CAN_ISOTP_RX_STMIN = 4
    CAN_ISOTP_LL_OPTS = 5

    # Flags for setsockopt CAN_ISOTP_OPTS
    CAN_ISOTP_LISTEN_MODE = 0x001
    CAN_ISOTP_EXTEND_ADDR = 0x002
    CAN_ISOTP_TX_PADDING = 0x004
    CAN_ISOTP_RX_PADDING = 0x008
    CAN_ISOTP_CHK_PAD_LEN = 0x010
    CAN_ISOTP_CHK_PAD_DATA = 0x020
    CAN_ISOTP_HALF_DUPLEX = 0x040
    CAN_ISOTP_FORCE_TXSTMIN = 0x080
    CAN_ISOTP_FORCE_RXSTMIN = 0x100
    CAN_ISOTP_RX_EXT_ADDR = 0x200

    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)
        self.args = cast(_ISOTP_SPEC_TYPE, self._args)

        assert target.hostname is not None, "empty interface"
        self.interface = target.hostname
        self._sock: s.socket

    async def connect(self, timeout: Optional[float] = None) -> None:
        self._sock = s.socket(s.PF_CAN, s.SOCK_DGRAM, s.CAN_ISOTP)
        self._sock.setblocking(False)

        src_addr = self._set_flags(self.args["src_addr"], self.args["is_extended"])
        dst_addr = self._set_flags(self.args["dst_addr"], self.args["is_extended"])

        self._setsockopts(
            frame_txtime=self.args["frame_txtime"],
            ext_address=self.args["ext_address"],
            rx_ext_address=self.args["rx_ext_address"],
            tx_padding=self.args["tx_padding"],
            rx_padding=self.args["rx_padding"],
        )
        # If CAN-FD is used, jumbo frames are possible.
        # This fails for non-fd configurations.
        if self.args["is_fd"]:
            tx_dl = 64 if self.args["tx_dl"] is None else self.args["tx_dl"]
            self._setsockllopts(canfd=self.args["is_fd"], tx_dl=tx_dl)
        self._sock.bind((self.interface, dst_addr, src_addr))

    @staticmethod
    def _set_flags(can_id: int, extended: bool = False) -> int:
        if extended:
            can_id = can_id & s.CAN_EFF_MASK
            return can_id | s.CAN_EFF_FLAG
        return can_id & s.CAN_SFF_MASK

    def _setsockopts(
        self,
        frame_txtime: int,
        tx_padding: Optional[int] = None,
        rx_padding: Optional[int] = None,
        ext_address: Optional[int] = None,
        rx_ext_address: Optional[int] = None,
        flags: int = 0,
    ) -> None:
        if ext_address is not None:
            flags |= self.CAN_ISOTP_EXTEND_ADDR
        else:
            ext_address = 0

        if rx_ext_address is not None:
            flags |= self.CAN_ISOTP_RX_EXT_ADDR
        else:
            rx_ext_address = 0

        if tx_padding is not None:
            flags |= self.CAN_ISOTP_TX_PADDING
        else:
            tx_padding = 0

        if rx_padding is not None:
            flags |= self.CAN_ISOTP_RX_PADDING
        else:
            rx_padding = 0

        data = struct.pack(
            "@IIBBBB",
            flags,
            frame_txtime,
            ext_address,
            tx_padding,
            rx_padding,
            rx_ext_address,
        )
        self._sock.setsockopt(self.SOL_CAN_ISOTP, self.CAN_ISOTP_OPTS, data)

    def _setsockfcopts(self, bs: int = 0, stmin: int = 0, wftmax: int = 0) -> None:
        data = struct.pack("@BBB", bs, stmin, wftmax)
        self._sock.setsockopt(self.SOL_CAN_ISOTP, self.CAN_ISOTP_RECV_FC, data)

    def _setsockllopts(self, canfd: bool, tx_dl: int) -> None:
        canmtu = 72 if canfd else 16
        # The flags are set to 0, since the author marks this as obsolete.
        data = struct.pack("@BBB", canmtu, tx_dl, 0)
        self._sock.setsockopt(self.SOL_CAN_ISOTP, self.CAN_ISOTP_LL_OPTS, data)

    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        self.logger.log_write(data.hex(), tags=tags)
        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, data), timeout)
        return len(data)

    async def read(
        self, timeout: Optional[float] = None, tags: Optional[list[str]] = None
    ) -> bytes:
        loop = asyncio.get_running_loop()
        try:
            data = await asyncio.wait_for(
                loop.sock_recv(self._sock, self.BUFSIZE), timeout
            )
        except OSError as e:
            if e.errno == errno.ECOMM:
                raise BrokenPipeError(f"isotp flow control frame missing: {e}") from e
            if e.errno == errno.EILSEQ:
                raise BrokenPipeError(f"invalid consecutive frame numbers: {e}") from e
            raise e
        self.logger.log_read(data.hex(), tags=tags)
        return data

    async def close(self) -> None:
        pass

    async def reconnect(self, timeout: Optional[float] = None) -> None:
        pass


class CANMessage(Message):  # type: ignore

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


_CAN_RAW_SPEC_TYPE = TypedDict(
    "_CAN_RAW_SPEC_TYPE",
    {
        "src_addr": Optional[int],
        "dst_addr": Optional[int],
        "is_extended": bool,
        "is_fd": bool,
        "bind": bool,
    },
)

spec_can_raw = {
    "src_addr": (_int_spec(None), False),
    "dst_addr": (_int_spec(None), False),
    "is_extended": (_bool_spec(False), False),
    "is_fd": (_bool_spec(False), False),
    "bind": (_bool_spec(False), False),
}


class RawCANTransport(BaseTransport, scheme="can-raw", spec=spec_can_raw):
    # Flags for setsockopt CAN_RAW_FILTER
    CAN_INV_FILTER = 0x20000000

    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)
        self.args = cast(_CAN_RAW_SPEC_TYPE, self._args)
        self.connected = False

        assert target.hostname is not None, "empty interface"
        self.interface = target.hostname
        self._sock: s.socket
        self.src_addr: int
        self.dst_addr: int

    async def connect(self, timeout: Optional[float] = None) -> None:
        self._sock = s.socket(s.PF_CAN, s.SOCK_RAW, s.CAN_RAW)
        self._sock.bind((self.interface,))
        if self.args["is_fd"] is True:
            self._sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_FD_FRAMES, 1)
        self._sock.setblocking(False)

        if self.args["bind"]:
            self.bind()

    def set_filter(self, can_ids: list[int], inv_filter: bool = False) -> None:
        if not can_ids:
            return
        filter_mask = s.CAN_EFF_MASK if self.args["is_extended"] else s.CAN_SFF_MASK
        data = b""
        for can_id in can_ids:
            if inv_filter:
                can_id |= self.CAN_INV_FILTER
            data += struct.pack("@II", can_id, filter_mask)
        self._sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_FILTER, data)
        if inv_filter:
            self._sock.setsockopt(s.SOL_CAN_RAW, s.CAN_RAW_JOIN_FILTERS, 1)

    def bind(self) -> None:
        if self.args["src_addr"] is None or self.args["dst_addr"] is None:
            raise RuntimeError("no src_addr/dst_addr set")

        self.set_filter([self.args["src_addr"]])
        self.src_addr = self.args["src_addr"]
        self.dst_addr = self.args["dst_addr"]
        self.connected = True

    async def read(
        self, timeout: Optional[float] = None, tags: Optional[list[str]] = None
    ) -> bytes:
        if not self.connected or not self.src_addr:
            raise RuntimeError("transport is not connected; set bind=true")
        _, data = await self.recvfrom(timeout, tags)
        return data

    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        if not self.connected or not self.dst_addr:
            raise RuntimeError("transport is not connected; set bind=true")
        return await self.sendto(data, self.dst_addr, timeout=timeout, tags=tags)

    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        msg = CANMessage(
            arbitration_id=dst,
            data=data,
            is_extended_id=self.args["is_extended"],
            is_fd=self.args["is_fd"],
            check=True,
        )
        if self.args["is_extended"]:
            self.logger.log_write(f"{dst:08x}#{data.hex()}", tags=tags)
        else:
            self.logger.log_write(f"{dst:03x}#{data.hex()}", tags=tags)

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, msg.pack()), timeout)
        return len(data)

    async def recvfrom(
        self, timeout: Optional[float] = None, tags: Optional[list[str]] = None
    ) -> tuple[int, bytes]:
        loop = asyncio.get_running_loop()
        can_frame = await asyncio.wait_for(
            loop.sock_recv(self._sock, self.BUFSIZE), timeout
        )
        msg = CANMessage.unpack(can_frame)

        if msg.is_extended_id:
            self.logger.log_read(
                f"{msg.arbitration_id:08x}#{msg.data.hex()}", tags=tags
            )
        else:
            self.logger.log_read(
                f"{msg.arbitration_id:03x}#{msg.data.hex()}", tags=tags
            )
        return msg.arbitration_id, msg.data

    async def close(self) -> None:
        pass

    async def reconnect(self, timeout: Optional[float] = None) -> None:
        pass

    async def get_idle_traffic(self, sniff_time: float) -> list[int]:
        """Listen to traffic on the bus and return list of IDs
        which are seen in the specified period of time.
        The output of this function can be used as input to set_filter.
        """
        addr_idle: list[int] = list()
        t1 = time.time()
        while time.time() - t1 < sniff_time:
            try:
                addr, _ = await self.recvfrom(timeout=1)
                if addr not in addr_idle:
                    self.logger.log_info(f"Received a message from {addr:03x}")
                    addr_idle.append(addr)
            except asyncio.TimeoutError:
                continue
        addr_idle.sort()
        return addr_idle
