# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import binascii

from gallia.transports.base import BaseTransport, TargetURI


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
    async def connect(
        cls, target: TargetURI, timeout: float | None = None
    ) -> TCPTransport:
        cls.check_scheme(target)

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target.hostname, target.port), timeout
        )
        return cls(target, reader, writer)

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]
        self.logger.trace(data.hex(), tags=t)

        self.writer.write(data)
        await asyncio.wait_for(self.writer.drain(), timeout)
        return len(data)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await asyncio.wait_for(self.reader.read(self.BUFSIZE), timeout)

        t = tags + ["read"] if tags is not None else ["read"]
        self.logger.trace(data.hex(), extra={"tags": t})
        return data


class TCPLineSepTransport(TCPTransport, scheme="tcp-lines"):
    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]

        self.logger.trace(data.hex() + "0a", extra={"tags": t})

        self.writer.write(binascii.hexlify(data) + b"\n")
        await asyncio.wait_for(self.writer.drain(), timeout)
        return len(data)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await asyncio.wait_for(self.reader.readline(), timeout)
        d = data.decode().strip()

        t = tags + ["read"] if tags is not None else ["read"]
        self.logger.trace(d + "0a", extra={"tags": t})

        return binascii.unhexlify(d)
