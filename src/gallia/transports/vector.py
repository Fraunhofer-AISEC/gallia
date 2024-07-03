import asyncio
import ctypes
import ctypes.util
import sys
from typing import Self

from can.interfaces.vector import xlclass, xldefine, xldriver

# from pydantic import BaseModel, field_validator
from gallia.log import get_logger
from gallia.transports import BaseTransport, TargetURI

# from gallia.utils import auto_int

if (p := sys.platform) != "windows":
    raise RuntimeError(f"gallia.transports.vector: unsupported platform: {p}")

logger = get_logger(__name__)


# class FlexrayConfig(BaseModel):
#     src_addr: int
#     dst_addr: int
#     is_extended: bool = False
#     is_fd: bool = False
#     frame_txtime: int = 10
#     ext_address: int | None = None
#     rx_ext_address: int | None = None
#     tx_padding: int | None = None
#     rx_padding: int | None = None
#     tx_dl: int = 64
#
#     @field_validator(
#         "src_addr",
#         "dst_addr",
#         "ext_address",
#         "rx_ext_address",
#         "tx_padding",
#         "rx_padding",
#         mode="before",
#     )
#     def auto_int(cls, v: str) -> int:
#         return auto_int(v)


class RawFlexrayTransport(BaseTransport, scheme="flexray"):
    def __init__(self, target: TargetURI) -> None:
        super().__init__(target)

        # if dll_path := ctypes.util.find_library(DLL_NAME):
        #     xlapi_dll = ctypes.windll.LoadLibrary(dll_path)
        # else:
        #     raise FileNotFoundError(f"Vector XL library not found: {DLL_NAME}")

        xldriver.xlOpenDriver()
        rx_fifo_size = ctypes.c_uint(0x20000)
        self.port_handle = xlclass.XLportHandle()
        channel_mask = xlclass.XLaccess()
        init_mask = xlclass.XLaccess()

        # TODO: Implement this.
        # // -- Get the first channel with Flexray support
        # for (unsigned channel = 0; channel < driverConfig.channelCount; channel++) {
        #     if ( driverConfig.channel[channel].channelBusCapabilities & XL_BUS_ACTIVE_CAP_FLEXRAY) {
        #         channelMask = driverConfig.channel[channel].channelMask;
        #         break;
        #     }
        # }

        status = xldriver.xlOpenPort(
            ctypes.pointer(self.port_handle),
            "Flex",
            ctypes.pointer(channel_mask),
            ctypes.pointer(init_mask),
            rx_fifo_size,
            xldefine.XL_InterfaceVersion.XL_INTERFACE_VERSION_V4,
            xldefine.XL_BusTypes.XL_BUS_TYPE_FLEXRAY,
        )
        print(status)

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        # TODO: No ctypes wrapper available for this.
        # XLfrEvent event;
        # char* data = "\x30\x7c\x61\x00\x3e\x00";
        #
        # event.tag                               = XL_FR_TX_FRAME;
        # event.flagsChip                         = XL_FR_CHANNEL_A;
        # event.size                              = 0;    // calculated inside XL-API DLL
        # event.userHandle                        = 0;
        # event.tagData.frTxFrame.flags           = 0;
        # event.tagData.frTxFrame.offset          = 0;
        # event.tagData.frTxFrame.repetition      = 1;
        # event.tagData.frTxFrame.payloadLength   = sizeof(data);
        # event.tagData.frTxFrame.slotID          = 42; // 42 works, sending at slot 59 like CANoe did not work, maybe one of the parameters needs to be changed
        # event.tagData.frTxFrame.txMode          = XL_FR_TX_MODE_CYCLIC;
        # event.tagData.frTxFrame.incrementOffset = 0;
        # event.tagData.frTxFrame.incrementSize   = 0;
        #
        # memcpy(event.tagData.frTxFrame.data, data, sizeof(data) * 2);
        #
        # status = xlFrTransmit(portHandle, channelMask, &event);

        # TODO: No ctypes wrapper available for this.
        # xlclass.xlFrTransmit()
        return 0

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        t = TargetURI(target) if isinstance(target, str) else target
        return cls(t)

    async def close(self) -> None:
        status = await asyncio.to_thread(xldriver.xlClosePort, self.port_handle)
        print(status)
        status = await asyncio.to_thread(xldriver.xlCloseDriver)
        print(status)

