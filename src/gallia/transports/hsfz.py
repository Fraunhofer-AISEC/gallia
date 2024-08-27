# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import errno
import struct
import sys
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Self

from pydantic import BaseModel, field_validator

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import auto_int, handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


class HSFZStatus(IntEnum):
    UNDEFINED = -0x01
    Data = 0x01
    Ack = 0x02
    Klemme15 = 0x10
    Vin = 0x11
    AliveCheck = 0x12
    StatusDataInquiry = 0x13
    IncorrectTesterAddressError = 0x40
    IncorrectControlWordError = 0x41
    IncorrectFormatError = 0x42
    IncorrectDestinationAddressError = 0x43
    MessageTooLarge = 0x44
    ApplicationNotReady = 0x45
    OutOfMemory = 0xFF

    @classmethod
    def _missing_(cls, value: Any) -> HSFZStatus:
        return cls.UNDEFINED


@dataclass
class HSFZHeader:
    Len: int
    CWord: int

    def pack(self) -> bytes:
        return struct.pack("!IH", self.Len, self.CWord)

    @classmethod
    def unpack(cls, data: bytes) -> Self:
        len_, cword = struct.unpack("!IH", data)
        return cls(len_, cword)


@dataclass
class HSFZDiagReqHeader:
    src_addr: int
    dst_addr: int

    def pack(self) -> bytes:
        return struct.pack("!BB", self.src_addr, self.dst_addr)

    @classmethod
    def unpack(cls, data: bytes) -> HSFZDiagReqHeader:
        src_addr, dst_addr = struct.unpack("!BB", data)
        return cls(src_addr, dst_addr)


HSFZFrame = tuple[HSFZHeader, HSFZDiagReqHeader | None, bytes | None]
HSFZDiagFrame = tuple[HSFZHeader, HSFZDiagReqHeader, bytes]


class HSFZConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        src_addr: int,
        dst_addr: int,
        ack_timeout: float = 1.0,
    ):
        self.reader = reader
        self.writer = writer
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.ack_timeout = ack_timeout
        self._read_queue: asyncio.Queue[HSFZDiagFrame | int] = asyncio.Queue()
        self._read_task = asyncio.create_task(self._read_worker())
        self._read_task.add_done_callback(
            handle_task_error,
            context=set_task_handler_ctx_variable(__name__, "HsfzReader"),
        )
        self._closed = False
        self._mutex = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        src_addr: int,
        dst_addr: int,
        ack_timeout: float,
    ) -> HSFZConnection:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(
            reader,
            writer,
            src_addr,
            dst_addr,
            ack_timeout,
        )

    async def _read_frame(self) -> HSFZFrame:
        # Header is fixed size 6 byte.
        hdr_buf = await self.reader.readexactly(6)
        hdr = HSFZHeader.unpack(hdr_buf)

        # If a message without a RequestHeader is received,
        # the whole message must be read before erroring out.
        # Otherwise the partial read packet stays in the receive
        # buffer and causes further breakage…
        if hdr.Len < 2:
            data = None
            if hdr.Len > 0:
                data = await self.reader.readexactly(hdr.Len)
            data_str = data.hex() if data is not None else data
            logger.trace(f"hdr: {hdr}, req_hdr: None, data: {data_str}", extra={"tags": ["read"]})
            return hdr, None, data

        # DiagReqHeader is fixed size 2 byte.
        req_buf = await self.reader.readexactly(2)
        req_hdr = HSFZDiagReqHeader.unpack(req_buf)

        data_len = hdr.Len - 2
        data = await self.reader.readexactly(data_len)
        logger.trace(
            f"hdr: {hdr}, req_hdr: {req_hdr}, data: {data.hex()}",
            extra={"tags": ["read"]},
        )
        return hdr, req_hdr, data

    async def write_frame(self, frame: HSFZFrame) -> None:
        hdr, req_hdr, data = frame
        buf = b""
        buf += hdr.pack()
        log_msg = f"hdr: {hdr}"
        if req_hdr is not None:
            buf += req_hdr.pack()
            log_msg += f", req_hdr: {req_hdr}"
            if data is not None:
                buf += data
                log_msg += f", data: {data.hex()}"
        self.writer.write(buf)
        await self.writer.drain()

        logger.trace(log_msg, extra={"tags": ["write"]})

    async def _read_worker(self) -> None:
        try:
            while True:
                hdr, req_hdr, data = await self._read_frame()

                match hdr.CWord:
                    case HSFZStatus.AliveCheck:
                        await self.send_alive_msg()
                        continue
                    case HSFZStatus.Ack | HSFZStatus.Data:
                        if req_hdr is None:
                            logger.warning("unexpected frame: no hsfz request header")
                            continue
                        if data is None:
                            logger.warning("unexpected frame: no payload")
                            continue
                        await self._read_queue.put((hdr, req_hdr, data))
                    case _:
                        await self._read_queue.put(hdr.CWord)
                        continue

        except asyncio.CancelledError:
            logger.debug("read worker cancelled")
        except asyncio.IncompleteReadError as e:
            logger.debug(f"read worker received EOF: {e}")
        except Exception as e:
            logger.critical(f"read worker died: {e}")

    async def _unpack_frame(self, frame: HSFZDiagFrame | int) -> HSFZDiagFrame:
        # I little hack, but it is either a tuple or an int….
        match frame:
            case tuple():
                return frame
            case int():
                await self.close()
                raise BrokenPipeError(f"I can't even: {HSFZStatus(frame).name}")
            case _:
                raise RuntimeError(f"unexpected frame: {frame}")

    async def read_frame(self) -> HSFZDiagFrame | int:
        if self._closed:
            if sys.platform != "win32":
                raise OSError(errno.EBADFD)
            else:
                raise RuntimeError("connection already closed")

        return await self._read_queue.get()

    async def read_diag_request(self) -> bytes:
        unexpected_packets = []
        while True:
            hdr, req_hdr, data = await self._unpack_frame(await self.read_frame())
            if hdr.CWord != HSFZStatus.Data:
                logger.warning(
                    f"expected HSFZ data, instead got: {HSFZStatus(hdr.CWord).name} with payload {data.hex()}"
                )
                unexpected_packets.append((hdr, req_hdr, data))
                continue
            if req_hdr.src_addr != self.dst_addr or req_hdr.dst_addr != self.src_addr:
                logger.warning(
                    f"HSFZ Data has unexpected addresses (src:dst); should be {self.dst_addr:#04x}:{self.src_addr:#04x}, but is {req_hdr.src_addr:#04x}:{req_hdr.dst_addr:#04x}"
                )
                unexpected_packets.append((hdr, req_hdr, data))
                continue

            # We do not want to consume packets that we were not expecting; add them to queue again
            for item in unexpected_packets:
                await self._read_queue.put(item)

            return data

    async def _read_ack(self, prev_data: bytes) -> None:
        unexpected_packets = []
        while True:
            hdr, req_hdr, data = await self._unpack_frame(await self.read_frame())
            if hdr.CWord != HSFZStatus.Ack:
                logger.warning(
                    f"expected HSFZ Ack for {prev_data.hex()}, instead got: {HSFZStatus(hdr.CWord).name} with payload {data.hex()}"
                )
                unexpected_packets.append((hdr, req_hdr, data))
                continue
            if req_hdr.src_addr != self.src_addr or req_hdr.dst_addr != self.dst_addr:
                logger.warning(
                    f"HSFZ Ack has unexpected addresses (src:dst); should be {self.src_addr:#04x}:{self.dst_addr:#04x}, but is {req_hdr.src_addr:#04x}:{req_hdr.dst_addr:#04x}"
                )
                unexpected_packets.append((hdr, req_hdr, data))
                continue
            if prev_data[:5] != data:
                logger.warning(
                    f"HSFZ Ack has unexpected data of {data.hex()}, should be {prev_data[:5].hex()}"
                )
                unexpected_packets.append((hdr, req_hdr, data))
                continue

            # We do not want to consume packets that we were not expecting; add them to queue again
            for item in unexpected_packets:
                await self._read_queue.put(item)

            return

    async def write_diag_request_raw(
        self,
        hdr: HSFZHeader,
        req_hdr: HSFZDiagReqHeader,
        data: bytes,
    ) -> None:
        async with self._mutex:
            await self.write_frame((hdr, req_hdr, data))

            try:
                # Now an ACK message is expected.
                await asyncio.wait_for(self._read_ack(data), self.ack_timeout)
            except TimeoutError as e:
                await self.close()
                raise BrokenPipeError("no ack by gateway") from e

    async def write_diag_request(self, data: bytes) -> None:
        hdr = HSFZHeader(Len=len(data) + 2, CWord=HSFZStatus.Data)
        req_hdr = HSFZDiagReqHeader(src_addr=self.src_addr, dst_addr=self.dst_addr)
        await self.write_diag_request_raw(hdr, req_hdr, data)

    async def send_alive_msg(self) -> None:
        hdr = HSFZHeader(Len=2, CWord=HSFZStatus.AliveCheck)
        buf = b""
        buf += hdr.pack()
        # For reasons, the tester address is two bytes large in this path.
        buf += struct.pack("!H", self.src_addr)

        self.writer.write(buf)
        await self.writer.drain()

    async def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._read_task.cancel()
        self.writer.close()
        await self.writer.wait_closed()


class HSFZConfig(BaseModel):
    src_addr: int
    dst_addr: int
    ack_timeout: int = 1000

    @field_validator(
        "src_addr",
        "dst_addr",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class HSFZTransport(BaseTransport, scheme="hsfz"):
    def __init__(
        self,
        target: TargetURI,
        port: int,
        config: HSFZConfig,
        conn: HSFZConnection,
    ):
        super().__init__(target)
        self._conn = conn
        self.port = port

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> HSFZTransport:
        t = TargetURI(target) if isinstance(target, str) else target
        if t.hostname is None:
            raise ValueError("no hostname specified")

        port = t.port if t.port is not None else 6801
        config = HSFZConfig(**t.qs_flat)
        conn = await HSFZConnection.connect(
            t.hostname,
            port,
            config.src_addr,
            config.dst_addr,
            config.ack_timeout / 1000,
        )
        return cls(
            t,
            port,
            config,
            conn,
        )

    async def close(self) -> None:
        await self._conn.close()

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        return await asyncio.wait_for(self._conn.read_diag_request(), timeout)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        await asyncio.wait_for(self._conn.write_diag_request(data), timeout)
        return len(data)
