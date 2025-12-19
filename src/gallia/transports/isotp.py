# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import errno
import socket as s
import struct
import sys

assert sys.platform == "linux", "unsupported platform"

from pydantic import BaseModel, field_validator

from gallia.dumpcap import dumpcap_argument_list_can
from gallia.log import get_logger
from gallia.transports._can_constants import (
    CAN_EFF_FLAG,
    CAN_EFF_MASK,
    CAN_ISOTP_EXTEND_ADDR,
    CAN_ISOTP_LL_OPTS,
    CAN_ISOTP_OPTS,
    CAN_ISOTP_RECV_FC,
    CAN_ISOTP_RX_EXT_ADDR,
    CAN_ISOTP_RX_PADDING,
    CAN_ISOTP_TX_PADDING,
    CAN_SFF_MASK,
    SOL_CAN_ISOTP,
)
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import auto_int

logger = get_logger(__name__)


class ISOTPConfig(BaseModel):
    tx_id: int
    rx_id: int
    force_extended: bool = False
    is_fd: bool = False
    frame_txtime: int = 10
    ext_address: int | None = None
    rx_ext_address: int | None = None
    tx_padding: int | None = None
    rx_padding: int | None = None
    tx_dl: int = 64

    @field_validator(
        "tx_id",
        "rx_id",
        "ext_address",
        "rx_ext_address",
        "tx_padding",
        "rx_padding",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class ISOTPTransport(BaseTransport, scheme="isotp"):
    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)

        self.config = ISOTPConfig.model_validate(self.target.qs_flat)
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

        sock = s.socket(s.PF_CAN, s.SOCK_DGRAM, s.CAN_ISOTP)
        sock.setblocking(False)

        self._setsockopts(
            sock,
            frame_txtime=self.config.frame_txtime,
            ext_address=self.config.ext_address,
            rx_ext_address=self.config.rx_ext_address,
            tx_padding=self.config.tx_padding,
            rx_padding=self.config.rx_padding,
        )
        # If CAN-FD is used, jumbo frames are possible.
        # This fails for non-fd configurations.
        if self.config.is_fd is True:
            self._setsockllopts(sock, tx_dl=self.config.tx_dl)

        sock.bind(
            (
                self.target.hostname,
                self._calc_flags(self.config.rx_id, self.config.force_extended),
                self._calc_flags(self.config.tx_id, self.config.force_extended),
            )
        )

        self._sock = sock

    @staticmethod
    def _calc_flags(can_id: int, force_extended: bool = False) -> int:
        if can_id > CAN_SFF_MASK or force_extended is True:
            return (can_id & CAN_EFF_MASK) | CAN_EFF_FLAG
        return can_id & CAN_SFF_MASK

    @staticmethod
    def _setsockopts(
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
    def _setsockllopts(sock: s.socket, tx_dl: int) -> None:
        canmtu = 72
        # The flags are set to 0, since the author marks this as obsolete.
        data = struct.pack("@BBB", canmtu, tx_dl, 0)
        sock.setsockopt(SOL_CAN_ISOTP, CAN_ISOTP_LL_OPTS, data)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        if self._sock is None:
            raise RuntimeError("Not connected, cannot write!")

        t = tags + ["write"] if tags is not None else ["write"]
        logger.trace(data.hex(), extra={"tags": t})

        loop = asyncio.get_running_loop()
        await asyncio.wait_for(loop.sock_sendall(self._sock, data), timeout)
        return len(data)

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        if self._sock is None:
            raise RuntimeError("Not connected, cannot read!")

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
        if self._sock is None:
            logger.debug("Socket already closed")
            return
        self._sock.close()
        self._sock = None

    async def dumpcap_argument_list(self) -> list[str] | None:
        return dumpcap_argument_list_can(
            self.target.netloc,
            [self.config.tx_id, self.config.rx_id],
        )
