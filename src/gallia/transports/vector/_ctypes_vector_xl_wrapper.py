# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import ctypes
import math
import sys
from collections.abc import Callable
from typing import Self, cast

assert sys.platform == "win32", "unsupported platform"

from gallia.log import get_logger
from gallia.transports import _ctypes_vector_xl
from gallia.utils import handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)

WaitForSingleObject: Callable[[int, int], int]
INFINITE: int
try:
    # Try builtin Python 3 Windows API
    from _winapi import WaitForSingleObject
except ImportError:
    raise RuntimeError("platform does not provide WaitForSingleObject")


class FlexRayCtypesBackend:
    def __init__(self, channel_mask: int, port_handle: int) -> None:
        self.channel_mask = channel_mask
        self.port_handle = port_handle
        self.queue: asyncio.Queue[_ctypes_vector_xl.XL_FR_RX_FRAME_EV] = asyncio.Queue()
        self.background_task: asyncio.Task[None] | None = None
        self.event_handle: _ctypes_vector_xl.XLhandle | None = None

    @classmethod
    def create(
        cls,
        channel_no: int | None,
        rx_queue_size: int = 0x2000,
    ) -> Self:
        cls._enable_vector_license()
        cls._open_driver()

        channel_mask = cls._find_flexray_channel(channel_no)
        port_handle = cls._open_flexray_port(
            cls.__class__.__name__,
            channel_mask,
            rx_queue_size,
        )

        return cls(
            channel_mask=channel_mask,
            port_handle=port_handle,
        )

    def set_configuration(self, config: _ctypes_vector_xl.XLfrClusterConfig) -> None:
        _ctypes_vector_xl.xlFrSetConfiguration(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
            ctypes.byref(config),
        )

    def get_configuration(self) -> _ctypes_vector_xl.XLfrClusterConfig:
        config = _ctypes_vector_xl.XLfrChannelConfig()
        _ctypes_vector_xl.xlFrGetChannelConfiguration(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
            ctypes.byref(config),
        )
        return cast(_ctypes_vector_xl.XLfrClusterConfig, config.xlFrClusterConfig)

    @staticmethod
    def _open_driver() -> None:
        _ctypes_vector_xl.xlOpenDriver()

    @staticmethod
    def _close_driver() -> None:
        _ctypes_vector_xl.xlCloseDriver()

    @classmethod
    def _find_flexray_channel(cls, no: int | None = None) -> int:
        driver_config = cls.get_xl_driver_config()

        # If no is None, then use the first one, otherwise count.
        for i in range(driver_config.channelCount):
            xlcc: _ctypes_vector_xl.XLchannelConfig = driver_config.channel[i]
            bus_caps = _ctypes_vector_xl.XL_BusCapabilities(xlcc.channelBusCapabilities)
            if bus_caps & _ctypes_vector_xl.XL_BusCapabilities.XL_BUS_ACTIVE_CAP_FLEXRAY:
                if no is not None:
                    if i == no:
                        return _ctypes_vector_xl.XLaccess(xlcc.channelMask).value
                else:
                    return _ctypes_vector_xl.XLaccess(xlcc.channelMask).value

        raise ValueError("no flexray channel found")

    @staticmethod
    def _enable_vector_license() -> None:
        out = ctypes.c_uint()
        _ctypes_vector_xl.xlGetKeymanBoxes(ctypes.byref(out))

    @staticmethod
    def _open_flexray_port(user_name: str, channel_mask: int, rx_queue_size: int) -> int:
        if not math.log2(rx_queue_size).is_integer():
            raise ValueError("rx_queue_size must be a power of 2")
        if not (rx_queue_size >= 8192 and rx_queue_size <= 1048576):
            raise ValueError("rx_queue_size must be within 8192…1048576 bytes (1 MB)")

        port_handle = _ctypes_vector_xl.XLportHandle()
        permission_mask = _ctypes_vector_xl.XLaccess()

        _ctypes_vector_xl.xlOpenPort(
            ctypes.byref(port_handle),
            ctypes.create_string_buffer(user_name.encode("ascii")),
            _ctypes_vector_xl.XLaccess(channel_mask),
            ctypes.byref(permission_mask),
            ctypes.c_uint(rx_queue_size),
            _ctypes_vector_xl.XL_InterfaceVersion.XL_INTERFACE_VERSION_V4,
            _ctypes_vector_xl.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
        )

        return int(port_handle.value)

    def _close_port(self) -> None:
        _ctypes_vector_xl.xlClosePort(_ctypes_vector_xl.XLportHandle(self.port_handle))

    def _set_notification(self) -> _ctypes_vector_xl.XLhandle:
        event_handle = _ctypes_vector_xl.XLhandle()
        _ctypes_vector_xl.xlSetNotification(
            self.port_handle,
            event_handle,
            1,
        )
        return event_handle

    @staticmethod
    def get_xl_driver_config() -> _ctypes_vector_xl.XLdriverConfig:
        driver_config = _ctypes_vector_xl.XLdriverConfig()
        _ctypes_vector_xl.xlGetDriverConfig(driver_config)
        return driver_config

    def activate_channel(self) -> None:
        _ctypes_vector_xl.xlActivateChannel(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
            _ctypes_vector_xl.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
            _ctypes_vector_xl.XL_ACTIVATE_RESET_CLOCK,
        )

    def _deactivate_channel(self) -> None:
        _ctypes_vector_xl.xlDeactivateChannel(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
        )

    def add_block_all_filter(self) -> None:
        filter_ = _ctypes_vector_xl.XLfrAcceptanceFilter(
            _ctypes_vector_xl.XL_FR_FILTER_BLOCK,
            _ctypes_vector_xl.XL_FR_FILTER_TYPE_DATA
            | _ctypes_vector_xl.XL_FR_FILTER_TYPE_NF
            | _ctypes_vector_xl.XL_FR_FILTER_TYPE_FILLUP_NF,
            ctypes.c_uint(1),
            ctypes.c_uint(255),
            ctypes.c_uint(self.channel_mask),
        )

        _ctypes_vector_xl.xlFrSetAcceptanceFilter(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
            ctypes.byref(filter_),
        )

    def set_acceptance_filter(
        self,
        from_slot: int,
        to_slot: int,
    ) -> None:
        filter_ = _ctypes_vector_xl.XLfrAcceptanceFilter(
            _ctypes_vector_xl.XL_FR_FILTER_PASS,
            _ctypes_vector_xl.XL_FR_FILTER_TYPE_DATA,
            ctypes.c_uint(from_slot),
            ctypes.c_uint(to_slot),
            ctypes.c_uint(self.channel_mask),
        )

        _ctypes_vector_xl.xlFrSetAcceptanceFilter(
            _ctypes_vector_xl.XLportHandle(self.port_handle),
            _ctypes_vector_xl.XLaccess(self.channel_mask),
            ctypes.byref(filter_),
        )

    def start_queue(self) -> None:
        self.event_handle = self._set_notification()
        self.background_task = asyncio.create_task(self._receive_worker())
        self.background_task.add_done_callback(
            handle_task_error,
            context=set_task_handler_ctx_variable(__name__),
        )

    async def stop_queue(self) -> None:
        assert self.background_task is not None

        self.background_task.cancel()
        await self.background_task

    async def _read_frame(self) -> None:
        while True:
            # Provide a context switch possibility.
            await asyncio.sleep(0)

            event = _ctypes_vector_xl.XLfrEvent()

            try:
                logger.trace("reading from XL queue…")
                _ctypes_vector_xl.xlFrReceive(
                    _ctypes_vector_xl.XLportHandle(self.port_handle),
                    ctypes.byref(event),
                )
            except _ctypes_vector_xl.VectorQueueIsEmptyError:
                logger.trace("XL queue is empty")
                break
            except _ctypes_vector_xl.VectorQueueIsFullError:
                logger.error("receive queue is full, gallia is too slow")
                logger.warn("flushing queue, packages will be dropped")
                _ctypes_vector_xl.xlFlushReceiveQueue(
                    _ctypes_vector_xl.XLportHandle(self.port_handle),
                )
                break

            if event.tag != _ctypes_vector_xl.XL_FR_RX_FRAME:
                continue
            if event.tagData.frRxFrame.payloadLength == 0:
                continue

            logger.trace("got raw event from XL: %s", event.tagData.frRxFrame)
            logger.trace("submitting fr event to queue…")
            await self.queue.put(cast(_ctypes_vector_xl.XL_FR_RX_FRAME_EV, event.tagData.frRxFrame))

    async def _receive_worker(self) -> None:
        assert self.event_handle is not None
        assert self.event_handle.value is not None

        logger.debug("_receive_worker() started")

        try:
            while True:
                poll_intervall = 100

                logger.trace("poller waiting…")
                await asyncio.to_thread(
                    WaitForSingleObject,
                    self.event_handle.value,
                    poll_intervall,
                )

                await self._read_frame()
        except asyncio.CancelledError:
            logger.debug("read worker cancelled")

    async def receive(
        self,
        slot_id: int | None,
        timeout: float | None,
    ) -> _ctypes_vector_xl.XL_FR_RX_FRAME_EV:
        async with asyncio.timeout(timeout):
            while True:
                event = await self.queue.get()
                received_slot_id = event.slotID

                if slot_id is not None:
                    if received_slot_id != slot_id:
                        continue
                return event

    async def transmit(self, slot_id: int, data: bytes) -> None:
        event = _ctypes_vector_xl.XLfrEvent()
        event.tag = _ctypes_vector_xl.XL_FR_TX_FRAME
        event.flagsChip = _ctypes_vector_xl.XL_FR_CHANNEL_A
        event.size = 0  # calculated inside XL-API DLL
        event.userHandle = 0

        event.tagData.frTxFrame.flags = 0x08  # TODO: what is 0x08?
        event.tagData.frTxFrame.offset = 0
        event.tagData.frTxFrame.repetition = 1

        data = bytearray(data.ljust(_ctypes_vector_xl.XL_FR_MAX_DATA_LENGTH, b"\x00"))
        # TODO: why is the 0x80 needed???????????
        data[73] = 0x80

        # TODO: is this somthing that needs to be configured??
        event.tagData.frTxFrame.payloadLength = 48
        event.tagData.frTxFrame.slotID = slot_id
        event.tagData.frTxFrame.txMode = _ctypes_vector_xl.XL_FR_TX_MODE_SINGLE_SHOT
        event.tagData.frTxFrame.incrementOffset = 0
        event.tagData.frTxFrame.incrementSize = 0

        if len(data) > _ctypes_vector_xl.XL_FR_MAX_DATA_LENGTH:
            raise ValueError("frame exceeds max data length")

        event.tagData.frTxFrame.data = (
            ctypes.c_ubyte * _ctypes_vector_xl.XL_FR_MAX_DATA_LENGTH
        ).from_buffer_copy(data)

        await asyncio.to_thread(
            _ctypes_vector_xl.xlFrTransmit,
            self.port_handle,
            self.channel_mask,
            ctypes.byref(event),
        )

    async def close(self) -> None:
        await self.stop_queue()
        self._deactivate_channel()
        self._close_port()
        self._close_driver()
