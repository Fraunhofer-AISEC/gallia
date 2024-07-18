# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from typing import Self

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, LinesTransportMixin, TargetURI

logger = get_logger("gallia.transport.tcp")


class TCPTransport(BaseTransport, scheme="tcp"):
    def __init__(
        self,
        target: TargetURI,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        super().__init__(target)
        self.reader = reader
        self.writer = writer

    @classmethod
    async def connect(cls, target: str | TargetURI, timeout: float | None = None) -> Self:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        cls.check_scheme(t)

        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(t.hostname, t.port)
        return cls(t, reader, writer)

    async def close(self) -> None:
        if self.is_closed:
            return
        self.is_closed = True
        self.writer.close()
        await self.writer.wait_closed()

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]
        logger.trace(data.hex(), extra={"tags": t})

        self.writer.write(data)
        async with asyncio.timeout(timeout):
            await self.writer.drain()
        return len(data)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        async with asyncio.timeout(timeout):
            data = await self.reader.read(self.BUFSIZE)

        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(data.hex(), extra={"tags": t})
        return data


class TCPLinesTransport(LinesTransportMixin, TCPTransport, scheme="tcp-lines"):
    def get_reader(self) -> asyncio.StreamReader:
        return self.reader

    def get_writer(self) -> asyncio.StreamWriter:
        return self.writer
