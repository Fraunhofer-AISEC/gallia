import asyncio
import ctypes
import ctypes.util
import sys
import time
from typing import Self, Any

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
    slot_id: int

    @field_validator(
        "rx_fifo_size",
        "slot_id",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class FlexrayFrame:
    pass


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

        print(f"channel mask: {self.channel_mask}")

        out = ctypes.c_uint()
        vector_ctypes.xlGetKeymanBoxes(ctypes.byref(out))
        print(f"dongle foo: {out}")

        xldriver.xlOpenPort(  # type: ignore
            ctypes.byref(self.port_handle),
            ctypes.create_string_buffer(b"Flex"),
            self.channel_mask,
            ctypes.byref(init_mask),
            ctypes.c_uint(self.config.rx_fifo_size),
            xldefine.XL_InterfaceVersion.XL_INTERFACE_VERSION_V4,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
        )

        print(f"port handle: {self.port_handle}")

        filter = vector_ctypes.XLfrAcceptanceFilter(
            vector_ctypes.XL_FR_FILTER_BLOCK,
            vector_ctypes.XL_FR_FILTER_TYPE_DATA | vector_ctypes.XL_FR_FILTER_TYPE_NF | vector_ctypes.XL_FR_FILTER_TYPE_FILLUP_NF,
            ctypes.c_uint(1),
            ctypes.c_uint(255),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

        filter = vector_ctypes.XLfrAcceptanceFilter(
            vector_ctypes.XL_FR_FILTER_PASS,
            vector_ctypes.XL_FR_FILTER_TYPE_DATA,
            ctypes.c_uint(33),
            ctypes.c_uint(33),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

        filter = vector_ctypes.XLfrAcceptanceFilter(
            vector_ctypes.XL_FR_FILTER_PASS,
            vector_ctypes.XL_FR_FILTER_TYPE_DATA,
            ctypes.c_uint(59),
            ctypes.c_uint(59),
            ctypes.c_uint(self.channel_mask.value),
        )

        vector_ctypes.xlFrSetAcceptanceFilter(
            self.port_handle,
            self.channel_mask,
            ctypes.byref(filter),
        )

        self.event_handle = xlclass.XLhandle()
        xldriver.xlSetNotification(self.port_handle, self.event_handle, 1)  # type: ignore

        xldriver.xlActivateChannel(  # type: ignore
            self.port_handle,
            self.channel_mask,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
            vector_ctypes.XL_ACTIVATE_RESET_CLOCK,
        )

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = TargetURI(target) if isinstance(target, str) else target
        return cls(t)

    async def write_frame(self) -> None:
        pass

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        event = vector_ctypes.XLfrEvent()
        event.tag = vector_ctypes.XL_FR_TX_FRAME
        event.flagsChip = vector_ctypes.XL_FR_CHANNEL_A
        event.size = 0  # calculated inside XL-API DLL
        event.userHandle = 0
        # event.tagData = vector_ctypes.
        event.tagData.frTxFrame = vector_ctypes.XL_FR_TX_FRAME_EV()
        # event.tagData.frTxFrame.flags = 0
        # event.tagData.frTxFrame.offset = 0
        # event.tagData.frTxFrame.repetition = 1
        # event.tagData.frTxFrame.payloadLength = len(data)
        # event.tagData.frTxFrame.slotID = self.config.slot_id
        # event.tagData.frTxFrame.txMode = vector_ctypes.XL_FR_TX_MODE_SINGLE_SHOT
        # event.tagData.frTxFrame.incrementOffset = 0
        # event.tagData.frTxFrame.incrementSize = 0

        if len(data) > vector_ctypes.XL_FR_MAX_DATA_LENGTH:
            raise ValueError("frame exceeds max data length")

        # event.tagData.frTxFrame.data = ctypes.create_string_buffer(data, 254)
        print(type(event.tagData))
        print(type(event.tagData.frTxFrame))
        print(type(event.tagData.frTxFrame.flags))
        print(type(event.tagData.frTxFrame.data))
        print(event.tagData.frTxFrame.data)
        # event.tagData.frTxFrame.data = data

        await asyncio.to_thread(
            vector_ctypes.xlFrTransmit,
            self.port_handle,
            self.channel_mask,
            ctypes.byref(event),
        )
        return len(data)

    async def read_frame(self, timeout: float | None = None, tags: list[str] | None = None) -> Any:
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

            
            slot_id = event.tagData.frRxFrame.slotID

            if slot_id not in (33, 59):
                continue
            # if cycle_count % 2 == 0 and slot_id == 33:
            #     continue

            data = bytes(event.tagData.frRxFrame.data)[: int(event.size)]

            if slot_id == 33:
                d = data[4:12]
                if d != bytes.fromhex("0000000000000000"):
                    return event.tagData.frRxFrame
            else:
                return event.tagData.frRxFrame

            continue

            if (slot_id := event.tagData.frRxFrame.slotID) in (46, 59, 33):
                data = bytes(event.tagData.frRxFrame.data)[: int(event.size)]
                continue

            # if (event_tag := event.tag) != vector_ctypes.XL_FR_RX_FRAME:
            #     print(f"received and continue event tag: {event_tag}")
            #     continue
            #
            # if (slot_id := event.tagData.frRxFrame.slotID) != self.config.slot_id:
            #     data = bytes(event.tagData.frRxFrame.data)[: int(event.size)]
            #     print(f"received and continue slot id: {slot_id} {data.hex()}")
            #     continue

            # TODO: slicing is correct?
            return bytes(event.tagData.frRxFrame.data)[: int(event.size)]


    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        raise NotImplementedError()

    async def close(self) -> None:
        await asyncio.to_thread(xldriver.xlClosePort, self.port_handle)  # type: ignore
        await asyncio.to_thread(xldriver.xlCloseDriver)  # type: ignore
