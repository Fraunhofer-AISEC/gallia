from __future__ import annotations

import asyncio
import binascii
from typing import Optional, TypedDict

from gallia.transports.base import BaseTransport, TargetURI


_TCP_SPEC_TYPE = TypedDict("_TCP_SPEC_TYPE", {})
tcp_spec: dict = {}
assertion_str = "bug: transport is not connected"


class TCPTransport(BaseTransport, scheme="tcp", spec=tcp_spec):
    def __init__(
        self,
        target: TargetURI,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
    ) -> None:
        super().__init__(target)
        self.reader = reader
        self.writer = writer

    async def connect(self, timeout: Optional[float] = None) -> None:
        assert (
            self.reader is None and self.writer is None
        ), "bug: transport is already connected"
        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_connection(self.target.hostname, self.target.port), timeout
        )

    async def reconnect(self, timeout: Optional[float] = None) -> None:
        await self.terminate()
        await self.connect(timeout)

    async def terminate(self) -> None:
        assert self.reader is not None and self.writer is not None, assertion_str

        self.writer.close()
        await self.writer.wait_closed()
        self.reader = None
        self.writer = None

    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        assert self.reader is not None and self.writer is not None, assertion_str

        self.logger.log_write(data.hex(), tags=tags)
        self.writer.write(data)
        await asyncio.wait_for(self.writer.drain(), timeout)
        return len(data)

    async def read(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        assert self.reader is not None and self.writer is not None, assertion_str

        data = await asyncio.wait_for(self.reader.read(self.BUFSIZE), timeout)
        self.logger.log_read(data.hex(), tags=tags)
        return data

    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        raise RuntimeError("sendto() is not implemented")

    async def recvfrom(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[int, bytes]:
        raise RuntimeError("recvfrom() is not implemented")


class TCPLineSepTransport(TCPTransport, scheme="tcp-lines", spec=tcp_spec):
    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        assert self.reader is not None and self.writer is not None, assertion_str

        d = binascii.hexlify(data)
        self.logger.log_write(data.hex(), tags=tags)
        self.writer.write(d + b"\n")
        await asyncio.wait_for(self.writer.drain(), timeout)
        return len(data)

    async def read(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        assert self.reader is not None and self.writer is not None, assertion_str

        data = await asyncio.wait_for(self.reader.readline(), timeout)
        d = data.decode().strip()
        self.logger.log_read(d, tags=tags)
        return binascii.unhexlify(d)
