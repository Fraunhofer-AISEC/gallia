# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from enum import IntEnum, unique
from itertools import batched
from typing import ClassVar, Self, TypeAlias

from pydantic import BaseModel, ConfigDict, field_validator

from gallia.log import get_logger
from gallia.transports import BaseTransport, TargetURI, _ctypes_vector_xl, _ctypes_vector_xl_wrapper
from gallia.utils import auto_int

assert sys.platform == "win32", "unsupported platform"


logger = get_logger(__name__)


class RawFlexRayConfig(BaseModel):
    rx_queue_size: int = 0x20000
    channel_no: int | None = None

    @field_validator(
        "rx_queue_size",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class FlexRayFrame(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    slot_id: int
    data: bytes
    raw: (
        _ctypes_vector_xl.XLfrEvent
        | _ctypes_vector_xl.XL_FR_RX_FRAME_EV
        | _ctypes_vector_xl.XL_FR_TX_FRAME_EV
        | None
    )


class RawFlexRayTransport(BaseTransport, scheme="fr-raw"):
    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)

        self.check_scheme(target)
        self.config = RawFlexRayConfig(**target.qs_flat)

        self.backend = _ctypes_vector_xl_wrapper.FlexRayCtypesBackend.create(
            channel_no=self.config.channel_no,
            rx_queue_size=self.config.rx_queue_size,
        )
        self.backend.start_queue()

    def activate_channel(self) -> None:
        self.backend.activate_channel()

    def add_block_all_filter(self) -> None:
        self.backend.add_block_all_filter()

    def set_acceptance_filter(self, from_slot: int, to_slot: int | None = None) -> None:
        if to_slot is None:
            to_slot = from_slot

        self.backend.set_acceptance_filter(from_slot, to_slot)
        logger.debug(f"set accept filter: {from_slot}:{to_slot}")

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = TargetURI(target) if isinstance(target, str) else target
        return cls(t)

    async def write_frame_unsafe(self, frame: FlexRayFrame) -> None:
        await self.backend.transmit(frame.slot_id, frame.data)
        logger.trace("wrote FlexRayFrame: %s", frame)

    async def write_frame(self, frame: FlexRayFrame) -> None:
        async with self.mutex:
            await self.write_frame_unsafe(frame)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        raise NotImplementedError

    async def read_frame_unsafe(
        self,
        slot_id: int | None = None,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> FlexRayFrame:
        event = await self.backend.receive(slot_id, timeout)

        frame = FlexRayFrame(
            slot_id=event.slotID,
            data=bytes(event.data)[: int(event.payloadLength)],
            raw=event,
        )

        logger.trace("read FlexRayFrame: %s", frame)
        return frame

    async def read_frame(
        self,
        slot_id: int | None = None,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> FlexRayFrame:
        async with self.mutex:
            return await self.read_frame_unsafe(slot_id, timeout, tags)

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        async with self.mutex:
            await self.backend.close()


class FlexrayTPLegacyConfig(BaseModel):
    src_slot_id: int
    dst_slot_id: int
    src_address: int
    dst_address: int
    payload_rx_start_index: int
    payload_rx_end_index: int
    fc_block_size: int = 0xFF
    fc_separation_time: int = 0x04
    tx_sleep_time: float = 0.05

    @field_validator(
        "src_slot_id",
        "dst_slot_id",
        "src_address",
        "dst_address",
        "payload_rx_start_index",
        "payload_rx_end_index",
        "fc_block_size",
        "fc_separation_time",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


@unique
class FlexRayTPFrameType(IntEnum):
    SINGLE_FRAME = 0x00
    FIRST_FRAME = 0x01
    CONSECUTIVE_FRAME = 0x02
    FLOW_CONTROL_FRAME = 0x03


@unique
class FlexRayTPFlowControlFlag(IntEnum):
    CONTINUE_TO_SEND = 0
    WAIT = 1
    ABORT = 2


def parse_frame_type(data: bytes) -> FlexRayTPFrameType:
    return FlexRayTPFrameType(data[0] >> 4)


class FlexRayTPSingleFrame(BaseModel):
    type_: ClassVar[FlexRayTPFrameType] = FlexRayTPFrameType.SINGLE_FRAME
    data: bytes
    size: int

    def __bytes__(self) -> bytes:
        return self.frame_header + self.data

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} size: {self.size} data: {self.data.hex()}>"

    @property
    def frame_header(self) -> bytes:
        return bytes([((self.type_ << 4) & 0xF0) | self.size & 0x0F])

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type_ = parse_frame_type(data)
        if type_ != cls.type_:
            raise ValueError(f"wrong frame type: {type:x}")
        size = data[0] & 0xF
        return cls(data=data[1 : size + 1], size=size)


class FlexRayTPFirstFrame(BaseModel):
    type_: ClassVar[FlexRayTPFrameType] = FlexRayTPFrameType.FIRST_FRAME
    data: bytes
    size: int

    def __bytes__(self) -> bytes:
        return self.frame_header + self.data

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} size: {self.size} data: {self.data.hex()}>"

    @property
    def frame_header(self) -> bytes:
        return bytes([(((self.type_ << 4) & 0xF0) | (self.size >> 8) & 0x0F), self.size & 0xFF])

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type_ = parse_frame_type(data)
        if type_ != cls.type_:
            raise ValueError(f"wrong frame type_: {type:x}")

        size = ((data[0] & 0x0F) << 8) | data[1]
        return cls(data=data[2 : size + 1], size=size)


class FlexRayTPConsecutiveFrame(BaseModel):
    type_: ClassVar[FlexRayTPFrameType] = FlexRayTPFrameType.CONSECUTIVE_FRAME
    counter: int
    data: bytes

    def __bytes__(self) -> bytes:
        return self.frame_header + self.data

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} counter: {self.counter} data: {self.data.hex()}>"

    @property
    def frame_header(self) -> bytes:
        return bytes([((self.type_ << 4) & 0xF0) | self.counter & 0x0F])

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type_ = parse_frame_type(data)
        if type_ != cls.type_:
            raise ValueError(f"wrong frame type_: {type:x}")
        counter = data[0] & 0xF
        return cls(counter=counter, data=data[1:])


class FlexRayTPFlowControlFrame(BaseModel):
    type_: ClassVar[FlexRayTPFrameType] = FlexRayTPFrameType.FLOW_CONTROL_FRAME
    flag: FlexRayTPFlowControlFlag
    block_size: int
    separation_time: int

    def __bytes__(self) -> bytes:
        return bytes(
            [
                ((self.type_ << 4) & 0xF0) | (self.flag & 0x0F),
                self.block_size,
                self.separation_time,
            ]
        )

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} flag: {self.flag} block_size: {self.block_size} separation_time: {self.separation_time}>"

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type_ = FlexRayTPFrameType(data[0] >> 4)
        if type_ != cls.type_:
            raise ValueError(f"wrong frame type_: {type:x}")
        flag = FlexRayTPFlowControlFlag(data[0] & 0x0F)
        block_size = data[1]
        separation_time = data[2]
        return cls(
            flag=flag,
            block_size=block_size,
            separation_time=separation_time,
        )


FlexRayTPFrame: TypeAlias = (
    FlexRayTPSingleFrame
    | FlexRayTPFirstFrame
    | FlexRayTPConsecutiveFrame
    | FlexRayTPFlowControlFrame
)


def parse_frame(data: bytes) -> FlexRayTPFrame:
    t = parse_frame_type(data)
    match t:
        case FlexRayTPFrameType.SINGLE_FRAME:
            return FlexRayTPSingleFrame.parse(data)
        case FlexRayTPFrameType.FIRST_FRAME:
            return FlexRayTPFirstFrame.parse(data)
        case FlexRayTPFrameType.CONSECUTIVE_FRAME:
            return FlexRayTPConsecutiveFrame.parse(data)
        case FlexRayTPFrameType.FLOW_CONTROL_FRAME:
            return FlexRayTPFlowControlFrame.parse(data)


class FlexRayTPLegacyTransport(BaseTransport, scheme="fr-tp-legacy"):
    def __init__(self, target: TargetURI, fr_raw: RawFlexRayTransport) -> None:
        super().__init__(target)

        self.check_scheme(target)
        self.config = FlexrayTPLegacyConfig(**target.qs_flat)
        self.mutex = asyncio.Lock()

        self.fr_raw = fr_raw
        self.fr_raw.add_block_all_filter()
        self.fr_raw.set_acceptance_filter(self.config.src_slot_id, self.config.src_slot_id)
        self.fr_raw.set_acceptance_filter(self.config.dst_slot_id, self.config.dst_slot_id)
        self.fr_raw.activate_channel()

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = TargetURI(target) if isinstance(target, str) else target
        fr_raw = await RawFlexRayTransport.connect("fr-raw:", timeout)
        return cls(t, fr_raw)

    async def write_bytes(self, data: bytes) -> None:
        frame = FlexRayFrame(
            data=data,
            slot_id=self.config.dst_slot_id,
            raw=None,  # raw is constructed by the layers underneath
        )
        await self.fr_raw.write_frame(frame)

    async def write_tp_frame(self, frame: FlexRayTPFrame) -> None:
        logger.trace("write FlexRayTPFrame: %s", frame)
        address_header = bytes(
            [
                ((self.config.dst_address >> 8) & 0xFF),
                (self.config.dst_address & 0xFF),
                ((self.config.src_address >> 8) & 0xFF),
                (self.config.src_address & 0xFF),
            ],
        )
        await self.write_bytes(address_header + bytes(frame))

    async def write_unsafe(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        # Single Frame is sufficiant.
        if len(data) < 8:
            await self.write_tp_frame(FlexRayTPSingleFrame(data=data, size=len(data)))
            return len(data)

        # Write a first frame…
        first_frame = FlexRayTPFirstFrame(data=data[:6], size=len(data))
        await self.write_tp_frame(first_frame)

        # … then a flow control comes.
        fc_frame = await self.read_tp_frame()
        if not isinstance(fc_frame, FlexRayTPFlowControlFrame):
            raise RuntimeError(f"unexpected frame received: {fc_frame}")

        # Best effort, just send the data.
        # TODO: Not implemented: block size handling.
        # Maybe a further flow control comes after block size number of frames.

        counter = 1
        for batch in batched(data[6:], 7):
            cf_frame = FlexRayTPConsecutiveFrame(
                counter=counter,
                data=bytes(batch),
            )

            await self.write_tp_frame(cf_frame)

            # XXX: FlexRay has a defined schedule.
            # In the best case, we get notified that our
            # frame has been written to the bus. We do
            # not have this information, so we sleep for
            # a configurable time frame…
            await asyncio.sleep(self.config.tx_sleep_time)
            counter = (counter + 1) & 0x0F

        logger.debug("wrote data: %s", data.hex())
        return len(data)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        async with self.mutex:
            await self.write_unsafe(data, timeout, tags)
            return len(data)

    async def read_bytes(self) -> bytes:
        while True:
            frame = await self.fr_raw.read_frame(self.config.src_slot_id)
            if frame.data[0] == 0x00:
                continue
            return frame.data[self.config.payload_rx_start_index : self.config.payload_rx_end_index]

    @staticmethod
    def _parse_address(data: bytes) -> tuple[int, int]:
        dst_address = data[0] << 8 | data[1]
        src_address = data[2] << 8 | data[3]
        return dst_address, src_address

    async def read_tp_frame(self) -> FlexRayTPFrame:
        data = await self.read_bytes()
        dst_address, src_address = self._parse_address(data)
        # logger.trace("got frame for addresses: %x %x", dst_address, src_address)
        frame = parse_frame(data[4:])
        logger.trace("read FlexRayTPFrame %s", repr(frame))
        return frame

    def _require_fc_frame(self, block_size: int, read_bytes: int) -> bool:
        # 6 bytes already read in first frame.
        return ((read_bytes - 6) & block_size) == 0

    async def _send_flow_control_frame(self) -> None:
        block_size = self.config.fc_block_size
        fc_frame = FlexRayTPFlowControlFrame(
            flag=FlexRayTPFlowControlFlag.CONTINUE_TO_SEND,
            separation_time=self.config.fc_separation_time,
            block_size=block_size,
        )
        await self.write_tp_frame(fc_frame)

    async def _handle_fragmented(self, expected_len: int) -> bytes:
        # 6 bytes already read in first frame.
        # Headersize is 2 byte.
        read_bytes = 6
        counter = 1
        data = b""

        while read_bytes < expected_len:
            # Reordering is not implemented.
            logger.debug(f"expected_len: {expected_len}; read_bytes: {read_bytes}")

            if self._require_fc_frame(self.config.fc_block_size, read_bytes):
                await self._send_flow_control_frame()

            # TODO: Make this configurable. Maybe align with separation_time.
            async with asyncio.timeout(10):
                frame = await self.read_tp_frame()

            if not isinstance(frame, FlexRayTPConsecutiveFrame):
                raise RuntimeError(f"expected consecutive frame, got: {frame}")
            if frame.counter != (counter & 0x0F):
                raise RuntimeError(f"got unexpected consecutive counter: {frame.counter}")

            # Header size needs to be respected here.
            read_bytes += len(frame.data)
            data += frame.data
            counter = (counter + 1) & 0x0F

        return data

    async def read_unsafe(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        async with asyncio.timeout(timeout):
            frame = await self.read_tp_frame()
            match frame:
                case FlexRayTPSingleFrame():
                    return frame.data
                case FlexRayTPFirstFrame():
                    data = frame.data + await self._handle_fragmented(frame.size)
                    data = data[: frame.size]
                    logger.debug("read data: %s", data.hex())
                    return data
                case _:
                    raise RuntimeError(f"got unexpected tp frame: {frame}")

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        async with self.mutex:
            return await self.read_unsafe(timeout, tags)

    async def close(self) -> None:
        await self.fr_raw.close()
