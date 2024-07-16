# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import ctypes
import ctypes.util
import os
import sys
import time
from enum import IntEnum, unique
from typing import ClassVar, Self, TypeAlias

from more_itertools import chunked

assert sys.platform == "win32", "unsupported platform"

# Configures the behaviour of ctypes.util.find_library().
# Since this is used within the xldriver module of the can library,
# the path variable needs to be changed before the import.
if "GALLIA_VXLAPI_PATH" in os.environ:
    gallia_setting = os.environ["GALLIA_VXLAPI_PATH"]
    os.environ["PATH"] = os.path.dirname(gallia_setting) + os.pathsep + os.environ["PATH"]  # noqa: PTH120

from can.interfaces.vector import canlib, xlclass, xldefine, xldriver
from pydantic import BaseModel, ConfigDict, field_validator

from gallia.log import get_logger
from gallia.transports import BaseTransport, TargetURI, vector_ctypes
from gallia.utils import auto_int

assert canlib.HAS_EVENTS and canlib.WaitForSingleObject, "event support is not available"


logger = get_logger(__name__)


class RawFlexrayConfig(BaseModel):
    rx_fifo_size: int = 0x20000

    @field_validator(
        "rx_fifo_size",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class FlexrayFrame(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    slot_id: int
    data: bytes
    raw: (
        vector_ctypes.XLfrEvent
        | vector_ctypes.XL_FR_RX_FRAME_EV
        | vector_ctypes.XL_FR_TX_FRAME_EV
        | None
    )


class RawFlexrayTransport(BaseTransport, scheme="flexray-raw"):
    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)

        self.check_scheme(target)
        self.config = RawFlexrayConfig(**target.qs_flat)

        xldriver.xlOpenDriver()  # type: ignore
        self.port_handle = xlclass.XLportHandle()
        self.channel_mask = xlclass.XLaccess()
        init_mask = xlclass.XLaccess()

        self.driver_config = canlib.get_channel_configs()

        for channel in self.driver_config:
            if (
                channel.channel_bus_capabilities
                & xldefine.XL_BusCapabilities.XL_BUS_ACTIVE_CAP_FLEXRAY
            ):
                self.channel_mask = xlclass.XLaccess(channel.channel_mask)
                break
        else:
            raise RuntimeError("no flexray channel found")

        logger.debug(f"found flexray channel: {self.channel_mask}")

        # Enable license stuff.
        out = ctypes.c_uint()
        vector_ctypes.xlGetKeymanBoxes(ctypes.byref(out))

        xldriver.xlOpenPort(  # type: ignore
            ctypes.byref(self.port_handle),
            ctypes.create_string_buffer(b"Flex"),
            self.channel_mask,
            ctypes.byref(init_mask),
            ctypes.c_uint(self.config.rx_fifo_size),
            xldefine.XL_InterfaceVersion.XL_INTERFACE_VERSION_V4,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
        )

        logger.debug(f"opened flexray port: {self.port_handle}")

    def activate_channel(self) -> None:
        self.event_handle = xlclass.XLhandle()
        xldriver.xlSetNotification(self.port_handle, self.event_handle, 1)  # type: ignore

        xldriver.xlActivateChannel(  # type: ignore
            self.port_handle,
            self.channel_mask,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
            vector_ctypes.XL_ACTIVATE_RESET_CLOCK,
        )
        logger.debug(f"activated flexray channel: {self.port_handle}:{self.channel_mask}")

    def deactivate_channel(self) -> None:
        raise NotImplementedError()

    def add_block_all_filter(self) -> None:
        filter = vector_ctypes.XLfrAcceptanceFilter(
            vector_ctypes.XL_FR_FILTER_BLOCK,
            vector_ctypes.XL_FR_FILTER_TYPE_DATA
            | vector_ctypes.XL_FR_FILTER_TYPE_NF
            | vector_ctypes.XL_FR_FILTER_TYPE_FILLUP_NF,
            ctypes.c_uint(1),
            ctypes.c_uint(255),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

    def set_acceptance_filter(self, from_slot: int, to_slot: int) -> None:
        filter = vector_ctypes.XLfrAcceptanceFilter(
            vector_ctypes.XL_FR_FILTER_PASS,
            vector_ctypes.XL_FR_FILTER_TYPE_DATA,
            ctypes.c_uint(from_slot),
            ctypes.c_uint(to_slot),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

        logger.debug(f"set accept filter: {from_slot}:{to_slot}")

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = TargetURI(target) if isinstance(target, str) else target
        return cls(t)

    async def write_frame_unsafe(self, frame: FlexrayFrame) -> None:
        event = vector_ctypes.XLfrEvent()
        event.tag = vector_ctypes.XL_FR_TX_FRAME
        event.flagsChip = vector_ctypes.XL_FR_CHANNEL_A
        event.size = 0  # calculated inside XL-API DLL
        event.userHandle = 0

        event.tagData.frTxFrame.flags = 0x08  # TODO: what is 0x08?
        event.tagData.frTxFrame.offset = 0
        event.tagData.frTxFrame.repetition = 1

        # TODO: why is the 0x80 needed??
        data = bytearray(frame.data.ljust(vector_ctypes.XL_FR_MAX_DATA_LENGTH, b"\x00"))
        data[73] = 0x80

        event.tagData.frTxFrame.payloadLength = 48
        event.tagData.frTxFrame.slotID = frame.slot_id
        event.tagData.frTxFrame.txMode = vector_ctypes.XL_FR_TX_MODE_SINGLE_SHOT
        event.tagData.frTxFrame.incrementOffset = 0
        event.tagData.frTxFrame.incrementSize = 0

        if len(frame.data) > vector_ctypes.XL_FR_MAX_DATA_LENGTH:
            raise ValueError("frame exceeds max data length")

        event.tagData.frTxFrame.data = (
            ctypes.c_ubyte * vector_ctypes.XL_FR_MAX_DATA_LENGTH
        ).from_buffer_copy(data)

        await asyncio.to_thread(
            vector_ctypes.xlFrTransmit,
            self.port_handle,
            self.channel_mask,
            ctypes.byref(event),
        )

        # logger.trace(f"wrote RawFlexRayFrame: {event.tagData.frTxFrame}")

    async def write_frame(self, frame: FlexrayFrame) -> None:
        async with self.mutex:
            await self.write_frame_unsafe(frame)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        raise NotImplementedError()

    async def read_frame_unsafe(
        self,
        slot_id: int | None = None,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> FlexrayFrame:
        assert canlib.WaitForSingleObject is not None
        assert canlib.INFINITE is not None
        assert self.event_handle.value is not None

        end_time = time.time() + timeout if timeout is not None else None

        while True:
            if end_time is not None and time.time() > end_time:
                raise TimeoutError()

            if end_time is None:
                time_left_ms = canlib.INFINITE
            else:
                time_left = end_time - time.time()
                time_left_ms = max(0, int(time_left * 1000))

            await asyncio.to_thread(
                canlib.WaitForSingleObject,
                self.event_handle.value,
                time_left_ms,
            )

            event = vector_ctypes.XLfrEvent()
            vector_ctypes.xlFrReceive(self.port_handle, ctypes.byref(event))
            if event.tag != vector_ctypes.XL_FR_RX_FRAME:
                continue
            if event.tagData.frRxFrame.payloadLength == 0:
                continue

            frame = FlexrayFrame(
                slot_id=event.tagData.frRxFrame.slotID,
                data=bytes(event.tagData.frRxFrame.data)[: int(event.size)],
                raw=event.tagData.frRxFrame,
            )

            if slot_id is not None:
                if frame.slot_id != slot_id:
                    continue

            # logger.trace(f"read RawFlexRayFrame: {event.tagData.frRxFrame}")
            return frame

    async def read_frame(
        self,
        slot_id: int | None = None,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> FlexrayFrame:
        async with self.mutex:
            return await self.read_frame_unsafe(slot_id, timeout, tags)

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        raise NotImplementedError()

    async def close(self) -> None:
        async with self.mutex:
            await asyncio.to_thread(xldriver.xlClosePort, self.port_handle)  # type: ignore
            await asyncio.to_thread(xldriver.xlCloseDriver)  # type: ignore


class FlexrayTPLegacyConfig(BaseModel):
    src_slot_id: int
    dst_slot_id: int
    src_address: int
    dst_address: int
    payload_rx_start_index: int
    payload_rx_end_index: int

    @field_validator(
        "src_slot_id",
        "dst_slot_id",
        "src_address",
        "dst_address",
        "payload_rx_start_index",
        "payload_rx_end_index",
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
        flag = FlexRayTPFlowControlFlag(data[0] >> 4)
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


class FlexRayTPLegacyTransport(BaseTransport, scheme="flexray-tp-legacy"):
    def __init__(self, target: TargetURI, fr_raw: RawFlexrayTransport) -> None:
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
        fr_raw = await RawFlexrayTransport.connect("flexray-raw:", timeout)
        return cls(t, fr_raw)

    async def write_bytes(self, data: bytes) -> None:
        frame = FlexrayFrame(
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
        first_frame = FlexRayTPFirstFrame(data=data[:7], size=7)
        await self.write_tp_frame(first_frame)

        # … then a flow control comes.
        fc_frame = self.read_tp_frame()
        if not isinstance(fc_frame, FlexRayTPFlowControlFrame):
            raise RuntimeError(f"unexpected frame received: {fc_frame}")

        # Best effort, just send the data.
        # TODO: Not implemented: block size handling.

        counter = 0
        for chunk in chunked(data[7:], 7):
            cf_frame = FlexRayTPConsecutiveFrame(
                counter=counter,
                data=chunk,
            )
            await self.write_tp_frame(cf_frame)
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

    async def _handle_fragmented(self, expected_len: int) -> bytes:
        # 6 bytes already read in first frame.
        # Headersize is 2 byte.
        read_bytes = 6
        counter = 1
        data = b""

        while read_bytes < expected_len:
            # Reordering is not implemented.
            logger.debug(f"expected_len: {expected_len}; read_bytes: {read_bytes}")
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
        frame = await self.read_tp_frame()
        match frame:
            case FlexRayTPSingleFrame():
                return frame.data
            case FlexRayTPFirstFrame():
                fc_frame = FlexRayTPFlowControlFrame(
                    flag=FlexRayTPFlowControlFlag.CONTINUE_TO_SEND,
                    separation_time=0xA0,  # Try 10 ms.
                    block_size=0xFF,  # TODO: send again after block_size is read.
                )
                await self.write_tp_frame(fc_frame)
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
