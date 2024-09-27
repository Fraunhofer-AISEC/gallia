# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import errno
import socket as s
import struct
import sys
from typing import Self

assert sys.platform == "linux", "unsupported platform"

from pydantic import BaseModel, field_validator

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import auto_int

logger = get_logger(__name__)

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


class ISOTPConfig(BaseModel):
    src_addr: int
    dst_addr: int
    is_extended: bool = False
    is_fd: bool = False
    frame_txtime: int = 10
    ext_address: int | None = None
    rx_ext_address: int | None = None
    tx_padding: int | None = None
    rx_padding: int | None = None
    tx_dl: int = 64

    @field_validator(
        "src_addr",
        "dst_addr",
        "ext_address",
        "rx_ext_address",
        "tx_padding",
        "rx_padding",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class ISOTPTransport(BaseTransport, scheme="isotp"):
    def __init__(self, target: TargetURI, config: ISOTPConfig, sock: s.socket) -> None:
        super().__init__(target)
        self._sock = sock
        self.config = config

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        cls.check_scheme(t)

        if t.hostname is None:
            raise ValueError("empty interface")

        config = ISOTPConfig(**t.qs_flat)
        sock = s.socket(s.PF_CAN, s.SOCK_DGRAM, s.CAN_ISOTP)
        sock.setblocking(False)

        src_addr = cls._calc_flags(config.src_addr, config.is_extended)
        dst_addr = cls._calc_flags(config.dst_addr, config.is_extended)

        cls._setsockopts(
            sock,
            frame_txtime=config.frame_txtime,
            ext_address=config.ext_address,
            rx_ext_address=config.rx_ext_address,
            tx_padding=config.tx_padding,
            rx_padding=config.rx_padding,
        )
        # If CAN-FD is used, jumbo frames are possible.
        # This fails for non-fd configurations.
        if config.is_fd:
            cls._setsockllopts(sock, canfd=config.is_fd, tx_dl=config.tx_dl)

        sock.bind((t.hostname, dst_addr, src_addr))

        return cls(t, config, sock)

    @staticmethod
    def _calc_flags(can_id: int, extended: bool = False) -> int:
        if extended:
            return (can_id & s.CAN_EFF_MASK) | s.CAN_EFF_FLAG
        return can_id & s.CAN_SFF_MASK

    @staticmethod
    def _setsockopts(  # noqa: PLR0913
        sock: s.socket,
        frame_txtime: int,
        tx_padding: int | None = None,
        rx_padding: int | None = None,
        ext_address: int | None = None,
        rx_ext_address: int | None = None,
    ) -> None:
        flags = 0
        if ext_address is not None:
            flags |= CAN_ISOTP_EXTEND_ADDR
        else:
            ext_address = 0

        if rx_ext_address is not None:
            flags |= CAN_ISOTP_RX_EXT_ADDR
        else:
            rx_ext_address = 0

        if tx_padding is not None:
            flags |= CAN_ISOTP_TX_PADDING
        else:
            tx_padding = 0

        if rx_padding is not None:
            flags |= CAN_ISOTP_RX_PADDING
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
        sock.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_OPTS, data)

    @staticmethod
    def _setsockfcopts(
        sock: s.socket,
        bs: int = 0,
        stmin: int = 0,
        wftmax: int = 0,
    ) -> None:
        data = struct.pack("@BBB", bs, stmin, wftmax)
        sock.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, data)

    @staticmethod
    def _setsockllopts(sock: s.socket, canfd: bool, tx_dl: int) -> None:
        canmtu = 72 if canfd else 16
        # The flags are set to 0, since the author marks this as obsolete.
        data = struct.pack("@BBB", canmtu, tx_dl, 0)
        sock.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, data)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]
        logger.trace(data.hex(), extra={"tags": t})

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, data), timeout)
        return len(data)

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        loop = asyncio.get_running_loop()
        try:
            data = await asyncio.wait_for(loop.sock_recv(self._sock, self.BUFSIZE), timeout)
        except OSError as e:
            if e.errno == errno.ECOMM:
                raise BrokenPipeError(f"isotp flow control frame missing: {e}") from e
            if e.errno == errno.EILSEQ:
                raise BrokenPipeError(f"invalid consecutive frame numbers: {e}") from e
            raise e
        logger.trace(data.hex(), extra={"tags": tags})
        return data

    async def close(self) -> None:
        self._sock.close()
