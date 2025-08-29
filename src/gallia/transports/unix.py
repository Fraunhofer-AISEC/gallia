# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, LinesTransportMixin, TargetURI

logger = get_logger(__name__)


class UnixTransport(BaseTransport, scheme="unix"):
    def __init__(
        self,
        target: TargetURI,
    ) -> None:
        super().__init__(target)

        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self, timeout: float | None = None) -> None:
        if self.reader is not None or self.writer is not None:
            logger.warning("Unix socket already connected, not connecting a second time!")
            return

        self.reader, self.writer = await asyncio.wait_for(
            asyncio.open_unix_connection(self.target.path), timeout
        )

    async def close(self) -> None:
        if self.writer is None:  # FIXME: Check below whether self.reader is None is also needed
            logger.debug("Unix socket is already closed")
            return

        self.writer.close()
        await self.writer.wait_closed()
        # self.reader.feed_eof() FIXME: Is this needed?

        self.reader, self.writer = None, None

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        if self.writer is None:
            raise RuntimeError("Writer not connected, cannot write!")

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
        if self.reader is None:
            raise RuntimeError("Reader not connected, cannot read!")

        data = await self.reader.read()
        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(data.hex(), extra={"tags": t})
        return data


class UnixLinesTransport(LinesTransportMixin, UnixTransport, scheme="unix-lines"):
    def get_reader(self) -> asyncio.StreamReader:
        if self.reader is None:
            raise RuntimeError("Reader not connected!")
        return self.reader

    def get_writer(self) -> asyncio.StreamWriter:
        if self.writer is None:
            raise RuntimeError("Writer not connected!")
        return self.writer
