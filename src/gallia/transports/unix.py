# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from typing import Self

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, LinesTransportMixin, TargetURI

logger = get_logger(__name__)


class UnixTransport(BaseTransport, scheme="unix"):
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

        reader, writer = await asyncio.wait_for(asyncio.open_unix_connection(t.path), timeout)

        return cls(t, reader, writer)

    async def close(self) -> None:
        if self.is_closed:
            return
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
        await asyncio.wait_for(self.writer.drain(), timeout)

        return len(data)

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await self.reader.read()
        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(data.hex(), extra={"tags": t})
        return data


class UnixLinesTransport(LinesTransportMixin, UnixTransport, scheme="unix-lines"):
    def get_reader(self) -> asyncio.StreamReader:
        return self.reader

    def get_writer(self) -> asyncio.StreamWriter:
        return self.writer
