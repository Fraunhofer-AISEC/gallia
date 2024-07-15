import asyncio
import ctypes
import ctypes.util
import sys
import time
from enum import IntEnum, unique
from typing import Self

assert sys.platform == "win32", "unsupported platform"

from can.interfaces.vector import canlib, xlclass, xldefine, xldriver  # noqa: E402
from pydantic import BaseModel, field_validator  # noqa: E402

assert canlib.HAS_EVENTS and canlib.WaitForSingleObject, "event support is not available"

from gallia.log import get_logger  # noqa: E402
from gallia.transports import BaseTransport, TargetURI, vector_ctypes  # noqa: E402
from gallia.utils import auto_int  # noqa: E402

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
    slot_id: int
    data: bytes
    raw: vector_ctypes.XLfrEvent | None


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

    def activate_channel(self) -> None:
        self.event_handle = xlclass.XLhandle()
        xldriver.xlSetNotification(self.port_handle, self.event_handle, 1)  # type: ignore

        xldriver.xlActivateChannel(  # type: ignore
            self.port_handle,
            self.channel_mask,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
            vector_ctypes.XL_ACTIVATE_RESET_CLOCK,
        )

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
            ctypes.c_uint(from_slot),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

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
        event.tagData.frTxFrame.payloadLength = len(frame.data) // 2  # word size, for reasons
        event.tagData.frTxFrame.slotID = frame.slot_id
        event.tagData.frTxFrame.txMode = vector_ctypes.XL_FR_TX_MODE_SINGLE_SHOT
        event.tagData.frTxFrame.incrementOffset = 0
        event.tagData.frTxFrame.incrementSize = 0

        if len(frame.data) > vector_ctypes.XL_FR_MAX_DATA_LENGTH:
            raise ValueError("frame exceeds max data length")

        data = frame.data.ljust(vector_ctypes.XL_FR_MAX_DATA_LENGTH, b"\x00")

        event.tagData.frTxFrame.data = (
            ctypes.c_ubyte * vector_ctypes.XL_FR_MAX_DATA_LENGTH
        ).from_buffer_copy(data)

        await asyncio.to_thread(
            vector_ctypes.xlFrTransmit,
            self.port_handle,
            self.channel_mask,
            ctypes.byref(event),
        )

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
        slot_id: int | None,
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

            frame = FlexrayFrame(
                slot_id=event.tagData.frRxFrame.slotID,
                data=bytes(event.tagData.frRxFrame.data)[: int(event.size)],
                raw=event,
            )

            if frame.slot_id != slot_id:
                continue

            return frame

    async def read_frame(
        self,
        slot_id: int | None,
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

    @field_validator(
        "src_slot_id",
        "dst_slot_id",
        "src_address",
        "dst_address",
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


class _FlexRayTPFrameBase(BaseModel):
    type: FlexRayTPFrameType = FlexRayTPFrameType.SINGLE_FRAME
    data: bytes

    @property
    def frame_header(self) -> bytes:
        return bytes([((self.type << 4) & 0xF0) | len(self.data) & 0x0F])

    def __bytes__(self) -> bytes:
        return self.frame_header + self.data

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type = FlexRayTPFrameType(data[0] >> 4)
        if type != cls.type:
            raise ValueError(f"wrong frame type: {type:x}")
        return cls(data=data)


class FlexRayTPSingleFrame(_FlexRayTPFrameBase):
    type: FlexRayTPFrameType = FlexRayTPFrameType.SINGLE_FRAME


class FlexRayTPFirstFrame(_FlexRayTPFrameBase):
    type: FlexRayTPFrameType = FlexRayTPFrameType.FIRST_FRAME


class FlexRayTPConsecutiveFrame(BaseModel):
    type: FlexRayTPFrameType = FlexRayTPFrameType.CONSECUTIVE_FRAME
    counter: int
    data: bytes

    @property
    def frame_header(self) -> bytes:
        return bytes([((self.type << 4) & 0xF0) | self.counter & 0x0F])

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type = FlexRayTPFrameType(data[0] >> 4)
        if type != cls.type:
            raise ValueError(f"wrong frame type: {type:x}")
        counter = data[0] & 0xF
        return cls(counter=counter, data=data)


class FlexRayTPFlowControlFrame(BaseModel):
    type: FlexRayTPFrameType = FlexRayTPFrameType.FLOW_CONTROL_FRAME
    flag: FlexRayTPFlowControlFlag
    block_size: int
    separation_time: int

    def __bytes__(self) -> bytes:
        return bytes(
            [
                ((self.type << 4) & 0xF0) | self.flag & 0x0F,
                self.block_size,
                self.separation_time,
            ]
        )

    @classmethod
    def parse(cls, data: bytes) -> Self:
        type = FlexRayTPFrameType(data[0] >> 4)
        if type != cls.type:
            raise ValueError(f"wrong frame type: {type:x}")
        flag = FlexRayTPFlowControlFlag(data[0] >> 4)
        block_size = data[1]
        separation_time = data[2]
        return cls(
            flag=flag,
            block_size=block_size,
            separation_time=separation_time,
        )


class FlexRayTPFrame(BaseModel):
    type: FlexRayTPFrameType
    payload: (
        FlexRayTPSingleFrame
        | FlexRayTPFirstFrame
        | FlexRayTPConsecutiveFrame
        | FlexRayTPFlowControlFrame
    )


@auto
@unique
class FlexRayTPRxStates(IntEnum):
    SF_RECEIVING = auto()
    CF_RECEIVING = auto()


class FlexRayTPLegacyTransport(BaseTransport, scheme="flexray-tp-legacy"):
    def __init__(self, target: TargetURI, fr_raw: RawFlexrayTransport) -> None:
        super().__init__(target)

        self.check_scheme(target)
        self.config = FlexrayTPLegacyConfig(**target.qs_flat)

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
        fr_raw = await RawFlexrayTransport.connect(target, timeout)
        return cls(t, fr_raw)

    async def _write_bytes(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> None:
        frame = FlexrayFrame(
            data=data,
            slot_id=self.config.dst_slot_id,
            raw=None,  # raw is constructed by the layers underneath
        )
        await self.fr_raw.write_frame(frame)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        # Single Frame is possible.
        if len(data) < 8:
            frame = FlexRayTPSingleFrame(data=data)
            await self._write_bytes(bytes(frame))

        raise NotImplementedError()

    async def _read_bytes(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        frame = await self.fr_raw.read_frame(
            self.config.src_slot_id,
            timeout=timeout,
            tags=tags,
        )
        return frame.data

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        # TODO: Add CF support
        data = await self._read_bytes(timeout, tags)
        frame = FlexRayTPSingleFrame(data)
        return frame.data

    async def close(self) -> None:
        await self.fr_raw.close()
