from __future__ import annotations

import asyncio
import io
import selectors
import socket
from typing import Optional

from gallia.transports.base import BaseTransport, TargetURI


class UDPTransport(BaseTransport, scheme="udp", spec={}):
    BUFSIZE = io.DEFAULT_BUFFER_SIZE

    def __init__(
        self,
        target: TargetURI,
    ) -> None:
        super().__init__(target)
        self._sock: socket.socket

    async def connect(self, timeout: Optional[float] = None) -> None:
        assert self.target.hostname is not None, "no hostname"
        assert self.target.port is not None, "no port"

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)

    async def reconnect(self, timeout: Optional[float] = None) -> None:
        pass

    async def terminate(self) -> None:
        self._sock.close()

    def _sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
    ) -> int:
        sel = selectors.DefaultSelector()
        sel.register(self._sock, selectors.EVENT_WRITE)

        r = sel.select(timeout)
        if len(r) == 0:
            sel.close()
            raise asyncio.TimeoutError()

        self._sock.sendto(data, (self.target.hostname, dst))
        sel.close()
        return len(data)

    def _recvfrom(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[int, bytes]:
        sel = selectors.DefaultSelector()
        sel.register(self._sock, selectors.EVENT_READ)
        r = sel.select(timeout)
        if len(r) == 0:
            sel.close()
            raise asyncio.TimeoutError()
        data, addr = self._sock.recvfrom(self.BUFSIZE)
        sel.close()
        return addr[1], data

    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        raise RuntimeError("write() is not implemented")

    async def read(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        raise RuntimeError("read() is not implemented")

    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        r = await asyncio.to_thread(self._sendto, data, dst, timeout)
        self.logger.log_write(data.hex(), tags)
        return r

    async def recvfrom(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[int, bytes]:
        (
            addr,
            data,
        ) = await asyncio.to_thread(self._recvfrom, timeout)
        self.logger.log_read(data.hex(), tags)
        return addr, data
