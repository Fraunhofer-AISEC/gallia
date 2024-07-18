# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# Most of this file is copied from the C header file.

import ctypes
import ctypes.util
import os
import platform
import sys
from enum import IntEnum, IntFlag
from typing import Any, Protocol

assert sys.platform == "win32", "unsupported platform"


# Configures the behaviour of ctypes.util.find_library().
if "GALLIA_VXLAPI_PATH" in os.environ:
    gallia_setting = os.environ["GALLIA_VXLAPI_PATH"]
    os.environ["PATH"] = os.path.dirname(gallia_setting) + os.pathsep + os.environ["PATH"]  # noqa: PTH120


DLL_NAME = "vxlapi64" if platform.architecture()[0] == "64bit" else "vxlapi"
if dll_path := ctypes.util.find_library(DLL_NAME):
    _xlapi_dll = ctypes.windll.LoadLibrary(dll_path)
else:
    raise FileNotFoundError(f"Vector XL library not found: {DLL_NAME}")


XLuint64 = ctypes.c_int64
XLaccess = XLuint64
XLhandle = ctypes.c_void_p
XLstatus = ctypes.c_short
XLportHandle = ctypes.c_long
XLeventTag = ctypes.c_ubyte
XLstringType = ctypes.c_char_p

xlGetErrorString = _xlapi_dll.xlGetErrorString
xlGetErrorString.argtypes = [XLstatus]
xlGetErrorString.restype = XLstringType


class VectorError(Exception):
    def __init__(self, error_code: int, error_string: str, function: str):
        msg = f'[VectorError {error_code}] in {function}: "{error_string}"'
        super().__init__(msg)


class VectorInitializationError(VectorError):
    pass


class VectorOperationError(VectorError):
    pass


class VectorQueueIsFullError(VectorError):
    pass


class VectorQueueIsEmptyError(VectorError):
    pass


class XL_Status(IntEnum):
    XL_SUCCESS = 0  # =0x0000
    XL_PENDING = 1  # =0x0001
    XL_ERR_QUEUE_IS_EMPTY = 10  # =0x000A
    XL_ERR_QUEUE_IS_FULL = 11  # =0x000B
    XL_ERR_TX_NOT_POSSIBLE = 12  # =0x000C
    XL_ERR_NO_LICENSE = 14  # =0x000E
    XL_ERR_WRONG_PARAMETER = 101  # =0x0065
    XL_ERR_TWICE_REGISTER = 110  # =0x006E
    XL_ERR_INVALID_CHAN_INDEX = 111  # =0x006F
    XL_ERR_INVALID_ACCESS = 112  # =0x0070
    XL_ERR_PORT_IS_OFFLINE = 113  # =0x0071
    XL_ERR_CHAN_IS_ONLINE = 116  # =0x0074
    XL_ERR_NOT_IMPLEMENTED = 117  # =0x0075
    XL_ERR_INVALID_PORT = 118  # =0x0076
    XL_ERR_HW_NOT_READY = 120  # =0x0078
    XL_ERR_CMD_TIMEOUT = 121  # =0x0079
    XL_ERR_CMD_HANDLING = 122  # = 0x007A
    XL_ERR_HW_NOT_PRESENT = 129  # =0x0081
    XL_ERR_NOTIFY_ALREADY_ACTIVE = 131  # =0x0083
    XL_ERR_INVALID_TAG = 132  # = 0x0084
    XL_ERR_INVALID_RESERVED_FLD = 133  # = 0x0085
    XL_ERR_INVALID_SIZE = 134  # = 0x0086
    XL_ERR_INSUFFICIENT_BUFFER = 135  # = 0x0087
    XL_ERR_ERROR_CRC = 136  # = 0x0088
    XL_ERR_BAD_EXE_FORMAT = 137  # = 0x0089
    XL_ERR_NO_SYSTEM_RESOURCES = 138  # = 0x008A
    XL_ERR_NOT_FOUND = 139  # = 0x008B
    XL_ERR_INVALID_ADDRESS = 140  # = 0x008C
    XL_ERR_REQ_NOT_ACCEP = 141  # = 0x008D
    XL_ERR_INVALID_LEVEL = 142  # = 0x008E
    XL_ERR_NO_DATA_DETECTED = 143  # = 0x008F
    XL_ERR_INTERNAL_ERROR = 144  # = 0x0090
    XL_ERR_UNEXP_NET_ERR = 145  # = 0x0091
    XL_ERR_INVALID_USER_BUFFER = 146  # = 0x0092
    XL_ERR_INVALID_PORT_ACCESS_TYPE = 147  # = 0x0093
    XL_ERR_NO_RESOURCES = 152  # =0x0098
    XL_ERR_WRONG_CHIP_TYPE = 153  # =0x0099
    XL_ERR_WRONG_COMMAND = 154  # =0x009A
    XL_ERR_INVALID_HANDLE = 155  # =0x009B
    XL_ERR_RESERVED_NOT_ZERO = 157  # =0x009D
    XL_ERR_INIT_ACCESS_MISSING = 158  # =0x009E
    XL_ERR_WRONG_VERSION = 160  # = 0x00A0
    XL_ERR_CANNOT_OPEN_DRIVER = 201  # =0x00C9
    XL_ERR_WRONG_BUS_TYPE = 202  # =0x00CA
    XL_ERR_DLL_NOT_FOUND = 203  # =0x00CB
    XL_ERR_INVALID_CHANNEL_MASK = 204  # =0x00CC
    XL_ERR_NOT_SUPPORTED = 205  # =0x00CD
    XL_ERR_CONNECTION_BROKEN = 210  # =0x00D2
    XL_ERR_CONNECTION_CLOSED = 211  # =0x00D3
    XL_ERR_INVALID_STREAM_NAME = 212  # =0x00D4
    XL_ERR_CONNECTION_FAILED = 213  # =0x00D5
    XL_ERR_STREAM_NOT_FOUND = 214  # =0x00D6
    XL_ERR_STREAM_NOT_CONNECTED = 215  # =0x00D7
    XL_ERR_QUEUE_OVERRUN = 216  # =0x00D8
    XL_ERROR = 255  # =0x00FF

    # CAN FD Error Codes
    XL_ERR_INVALID_DLC = 513  # =0x0201
    XL_ERR_INVALID_CANID = 514  # =0x0202
    XL_ERR_INVALID_FDFLAG_MODE20 = 515  # =0x203
    XL_ERR_EDL_RTR = 516  # =0x204
    XL_ERR_EDL_NOT_SET = 517  # =0x205
    XL_ERR_UNKNOWN_FLAG = 518  # =0x206


def check_status_operation(result, function, arguments):  # type: ignore
    if result > 0:
        raise VectorOperationError(
            result,
            xlGetErrorString(result).decode(),
            function.__name__,
        )
    return result


def check_rxtx_operation(result, function, arguments):  # type: ignore
    match result:
        case XL_Status.XL_ERR_QUEUE_IS_FULL:
            raise VectorQueueIsFullError(
                result,
                xlGetErrorString(result).decode(),
                function.__name__,
            )
        case XL_Status.XL_ERR_QUEUE_IS_EMPTY:
            raise VectorQueueIsEmptyError(
                result,
                xlGetErrorString(result).decode(),
                function.__name__,
            )
        case XL_Status.XL_SUCCESS:
            return result
        case _:
            raise VectorOperationError(
                result,
                xlGetErrorString(result).decode(),
                function.__name__,
            )
    return result


def check_status_initialization(result, function, arguments):  # type: ignore
    if result > 0:
        raise VectorInitializationError(
            result,
            xlGetErrorString(result).decode(),
            function.__name__,
        )
    return result


XLfrEventTag = ctypes.c_ushort

# activate - channel flags
XL_ACTIVATE_NONE = 0
XL_ACTIVATE_RESET_CLOCK = 8  # using this flag with time synchronisation protocols supported by Vector Timesync Service is not recommended


# Extended error codes
# Too many PDUs configured or too less system memory free
XL_ERR_PDU_OUT_OF_MEMORY = 0x0104
# No cluster configuration has been sent to the driver but is needed for the command which failed
XL_ERR_FR_CLUSTERCONFIG_MISSING = 0x0105
# Invalid offset and/or repetition value specified
XL_ERR_PDU_OFFSET_REPET_INVALID = 0x0106
# Specified PDU payload size is invalid (e.g. size is too large) Frame-API: size is different than static payload length configured in cluster config
XL_ERR_PDU_PAYLOAD_SIZE_INVALID = 0x0107
# Too many frames specified in parameter
XL_ERR_FR_NBR_FRAMES_OVERFLOW = 0x0109
# Specified slot-ID exceeds biggest possible ID specified by the cluster configuration
XL_ERR_FR_SLOT_ID_INVALID = 0x010B
# Specified slot cannot be used by Coldstart-Controller because it's already in use by the eRay
XL_ERR_FR_SLOT_ALREADY_OCCUPIED_BY_ERAY = 0x010C
# Specified slot cannot be used by eRay because it's already in use by the Coldstart-Controller
XL_ERR_FR_SLOT_ALREADY_OCCUPIED_BY_COLDC = 0x010D
# Specified slot cannot be used because it's already in use by another application
XL_ERR_FR_SLOT_OCCUPIED_BY_OTHER_APP = 0x010E
# Specified slot is not in correct segment. E.g.: A dynamic slot was specified for startup&sync
XL_ERR_FR_SLOT_IN_WRONG_SEGMENT = 0x010F
# The given frame-multiplexing rule (specified by offset and repetition) cannot be done because some of the slots are already in use
XL_ERR_FR_FRAME_CYCLE_MULTIPLEX_ERROR = 0x0110


XL_FR_FRAMEFLAG_REQ_TXACK = 0x0020  # used for Tx events only
XL_FR_FRAMEFLAG_TXACK_SS = (
    XL_FR_FRAMEFLAG_REQ_TXACK  # indicates TxAck of SingleShot; used for TxAck events only
)
XL_FR_FRAMEFLAG_RX_UNEXPECTED = (
    XL_FR_FRAMEFLAG_REQ_TXACK  # indicates unexpected Rx frame; used for Rx events only
)

XL_FR_FRAMEFLAG_NEW_DATA_TX = (
    0x0040  # flag used with TxAcks to indicate first TxAck after data update
)
XL_FR_FRAMEFLAG_DATA_UPDATE_LOST = (
    0x0080  # flag used with TxAcks indicating that data update has been lost
)

XL_FR_FRAMEFLAG_SYNTAX_ERROR = 0x0200
XL_FR_FRAMEFLAG_CONTENT_ERROR = 0x0400
XL_FR_FRAMEFLAG_SLOT_BOUNDARY_VIOLATION = 0x0800
XL_FR_FRAMEFLAG_TX_CONFLICT = 0x1000
XL_FR_FRAMEFLAG_EMPTY_SLOT = 0x2000
# Only used with TxAcks: Frame has been transmitted. If not set after transmission, an error has occurred.
XL_FR_FRAMEFLAG_FRAME_TRANSMITTED = 0x8000

# XL_FR_SPY_FRAME_EV event: frameError value
XL_FR_SPY_FRAMEFLAG_FRAMING_ERROR = 0x01
XL_FR_SPY_FRAMEFLAG_HEADER_CRC_ERROR = 0x02
XL_FR_SPY_FRAMEFLAG_FRAME_CRC_ERROR = 0x04
XL_FR_SPY_FRAMEFLAG_BUS_ERROR = 0x08

# FlexRay event tags
XL_FR_START_CYCLE = 0x0080
XL_FR_RX_FRAME = 0x0081
XL_FR_TX_FRAME = 0x0082
XL_FR_TXACK_FRAME = 0x0083
XL_FR_INVALID_FRAME = 0x0084
XL_FR_WAKEUP = 0x0085
XL_FR_SYMBOL_WINDOW = 0x0086
XL_FR_ERROR = 0x0087
XL_FR_ERROR_POC_MODE = 0x01
XL_FR_ERROR_SYNC_FRAMES_BELOWMIN = 0x02
XL_FR_ERROR_SYNC_FRAMES_OVERLOAD = 0x03
XL_FR_ERROR_CLOCK_CORR_FAILURE = 0x04
XL_FR_ERROR_NIT_FAILURE = 0x05
XL_FR_ERROR_CC_ERROR = 0x06
XL_FR_STATUS = 0x0088
XL_FR_NM_VECTOR = 0x008A
XL_FR_TRANCEIVER_STATUS = 0x008B
XL_FR_SPY_FRAME = 0x008E
XL_FR_SPY_SYMBOL = 0x008F


# FlexRay XL API

XL_FR_MAX_DATA_LENGTH = 254


class XL_BusTypes(IntFlag):
    XL_BUS_TYPE_NONE = 0  # =0x00000000
    XL_BUS_TYPE_CAN = 1  # =0x00000001
    XL_BUS_TYPE_LIN = 2  # =0x00000002
    XL_BUS_TYPE_FLEXRAY = 4  # =0x00000004
    XL_BUS_TYPE_AFDX = 8  # =0x00000008
    XL_BUS_TYPE_MOST = 16  # =0x00000010
    XL_BUS_TYPE_DAIO = 64  # =0x00000040
    XL_BUS_TYPE_J1708 = 256  # =0x00000100
    XL_BUS_TYPE_KLINE = 2048  # =0x00000800
    XL_BUS_TYPE_ETHERNET = 4096  # =0x00001000
    XL_BUS_TYPE_A429 = 8192  # =0x00002000


class XL_HardwareType(IntEnum):
    XL_HWTYPE_NONE = 0
    XL_HWTYPE_VIRTUAL = 1
    XL_HWTYPE_CANCARDX = 2
    XL_HWTYPE_CANAC2PCI = 6
    XL_HWTYPE_CANCARDY = 12
    XL_HWTYPE_CANCARDXL = 15
    XL_HWTYPE_CANCASEXL = 21
    XL_HWTYPE_CANCASEXL_LOG_OBSOLETE = 23
    XL_HWTYPE_CANBOARDXL = 25
    XL_HWTYPE_CANBOARDXL_PXI = 27
    XL_HWTYPE_VN2600 = 29
    XL_HWTYPE_VN2610 = XL_HWTYPE_VN2600
    XL_HWTYPE_VN3300 = 37
    XL_HWTYPE_VN3600 = 39
    XL_HWTYPE_VN7600 = 41
    XL_HWTYPE_CANCARDXLE = 43
    XL_HWTYPE_VN8900 = 45
    XL_HWTYPE_VN8950 = 47
    XL_HWTYPE_VN2640 = 53
    XL_HWTYPE_VN1610 = 55
    XL_HWTYPE_VN1630 = 57
    XL_HWTYPE_VN1640 = 59
    XL_HWTYPE_VN8970 = 61
    XL_HWTYPE_VN1611 = 63
    XL_HWTYPE_VN5240 = 64
    XL_HWTYPE_VN5610 = 65
    XL_HWTYPE_VN5620 = 66
    XL_HWTYPE_VN7570 = 67
    XL_HWTYPE_VN5650 = 68
    XL_HWTYPE_IPCLIENT = 69
    XL_HWTYPE_VN5611 = 70
    XL_HWTYPE_IPSERVER = 71
    XL_HWTYPE_VN5612 = 72
    XL_HWTYPE_VX1121 = 73
    XL_HWTYPE_VN5601 = 74
    XL_HWTYPE_VX1131 = 75
    XL_HWTYPE_VT6204 = 77
    XL_HWTYPE_VN1630_LOG = 79
    XL_HWTYPE_VN7610 = 81
    XL_HWTYPE_VN7572 = 83
    XL_HWTYPE_VN8972 = 85
    XL_HWTYPE_VN0601 = 87
    XL_HWTYPE_VN5640 = 89
    XL_HWTYPE_VX0312 = 91
    XL_HWTYPE_VH6501 = 94
    XL_HWTYPE_VN8800 = 95
    XL_HWTYPE_IPCL8800 = 96
    XL_HWTYPE_IPSRV8800 = 97
    XL_HWTYPE_CSMCAN = 98
    XL_HWTYPE_VN5610A = 101
    XL_HWTYPE_VN7640 = 102
    XL_HWTYPE_VX1135 = 104
    XL_HWTYPE_VN4610 = 105
    XL_HWTYPE_VT6306 = 107
    XL_HWTYPE_VT6104A = 108
    XL_HWTYPE_VN5430 = 109
    XL_HWTYPE_VTSSERVICE = 110
    XL_HWTYPE_VN1530 = 112
    XL_HWTYPE_VN1531 = 113
    XL_HWTYPE_VX1161A = 114
    XL_HWTYPE_VX1161B = 115
    XL_HWTYPE_VGNSS = 116
    XL_HWTYPE_VXLAPINIC = 118
    XL_MAX_HWTYPE = 120


class XL_InterfaceVersion(IntEnum):
    XL_INTERFACE_VERSION_V2 = 2
    XL_INTERFACE_VERSION_V3 = 3
    XL_INTERFACE_VERSION = XL_INTERFACE_VERSION_V3
    XL_INTERFACE_VERSION_V4 = 4


class XL_BusCapabilities(IntFlag):
    XL_BUS_COMPATIBLE_CAN = 1
    XL_BUS_ACTIVE_CAP_CAN = 1 << 16
    XL_BUS_COMPATIBLE_LIN = 2
    XL_BUS_ACTIVE_CAP_LIN = 2 << 16
    XL_BUS_COMPATIBLE_FLEXRAY = 4
    XL_BUS_ACTIVE_CAP_FLEXRAY = 4 << 16
    XL_BUS_COMPATIBLE_MOST = 16
    XL_BUS_ACTIVE_CAP_MOST = 16 << 16
    XL_BUS_COMPATIBLE_DAIO = 64
    XL_BUS_ACTIVE_CAP_DAIO = 64 << 16
    XL_BUS_COMPATIBLE_J1708 = 256
    XL_BUS_ACTIVE_CAP_J1708 = 256 << 16
    XL_BUS_COMPATIBLE_KLINE = 2048
    XL_BUS_ACTIVE_CAP_KLINE = 2048 << 16
    XL_BUS_COMPATIBLE_ETHERNET = 4096
    XL_BUS_ACTIVE_CAP_ETHERNET = 4096 << 16
    XL_BUS_COMPATIBLE_A429 = 8192
    XL_BUS_ACTIVE_CAP_A429 = 8192 << 16


# function structures


# structure for xlFrSetConfiguration


class CtypeLike(Protocol):
    @property
    def _fields_(self) -> list[tuple[str, Any]]: ...


class IntrospectMixin:
    def __repr__(self: CtypeLike) -> str:
        fields = []
        for name, _ in self._fields_:
            fields.append(f"{name}: {getattr(self, name)}")

        fields_str = ", ".join(fields)
        return f"{self.__class__.__name__}: {fields_str}"


class s_xl_bus_params_data_can(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("bitRate", ctypes.c_uint),
        ("sjw", ctypes.c_ubyte),
        ("tseg1", ctypes.c_ubyte),
        ("tseg2", ctypes.c_ubyte),
        ("sam", ctypes.c_ubyte),
        ("outputMode", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte * 7),
        ("canOpMode", ctypes.c_ubyte),
    ]


class s_xl_bus_params_data_canfd(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("arbitrationBitRate", ctypes.c_uint),
        ("sjwAbr", ctypes.c_ubyte),
        ("tseg1Abr", ctypes.c_ubyte),
        ("tseg2Abr", ctypes.c_ubyte),
        ("samAbr", ctypes.c_ubyte),
        ("outputMode", ctypes.c_ubyte),
        ("sjwDbr", ctypes.c_ubyte),
        ("tseg1Dbr", ctypes.c_ubyte),
        ("tseg2Dbr", ctypes.c_ubyte),
        ("dataBitRate", ctypes.c_uint),
        ("canOpMode", ctypes.c_ubyte),
    ]


class s_xl_bus_params_data(IntrospectMixin, ctypes.Union):
    _fields_ = [
        ("can", s_xl_bus_params_data_can),
        ("canFD", s_xl_bus_params_data_canfd),
        ("most", ctypes.c_ubyte * 12),
        ("flexray", ctypes.c_ubyte * 12),
        ("ethernet", ctypes.c_ubyte * 12),
        ("a429", ctypes.c_ubyte * 28),
    ]


class XLbusParams(IntrospectMixin, ctypes.Structure):
    _fields_ = [("busType", ctypes.c_uint), ("data", s_xl_bus_params_data)]


class XLchannelConfig(IntrospectMixin, ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("name", ctypes.c_char * 32),
        ("hwType", ctypes.c_ubyte),
        ("hwIndex", ctypes.c_ubyte),
        ("hwChannel", ctypes.c_ubyte),
        ("transceiverType", ctypes.c_ushort),
        ("transceiverState", ctypes.c_ushort),
        ("configError", ctypes.c_ushort),
        ("channelIndex", ctypes.c_ubyte),
        ("channelMask", XLuint64),
        ("channelCapabilities", ctypes.c_uint),
        ("channelBusCapabilities", ctypes.c_uint),
        ("isOnBus", ctypes.c_ubyte),
        ("connectedBusType", ctypes.c_uint),
        ("busParams", XLbusParams),
        ("_doNotUse", ctypes.c_uint),
        ("driverVersion", ctypes.c_uint),
        ("interfaceVersion", ctypes.c_uint),
        ("raw_data", ctypes.c_uint * 10),
        ("serialNumber", ctypes.c_uint),
        ("articleNumber", ctypes.c_uint),
        ("transceiverName", ctypes.c_char * 32),
        ("specialCabFlags", ctypes.c_uint),
        ("dominantTimeout", ctypes.c_uint),
        ("dominantRecessiveDelay", ctypes.c_ubyte),
        ("recessiveDominantDelay", ctypes.c_ubyte),
        ("connectionInfo", ctypes.c_ubyte),
        ("currentlyAvailableTimestamps", ctypes.c_ubyte),
        ("minimalSupplyVoltage", ctypes.c_ushort),
        ("maximalSupplyVoltage", ctypes.c_ushort),
        ("maximalBaudrate", ctypes.c_uint),
        ("fpgaCoreCapabilities", ctypes.c_ubyte),
        ("specialDeviceStatus", ctypes.c_ubyte),
        ("channelBusActiveCapabilities", ctypes.c_ushort),
        ("breakOffset", ctypes.c_ushort),
        ("delimiterOffset", ctypes.c_ushort),
        ("reserved", ctypes.c_uint * 3),
    ]


class XLdriverConfig(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("dllVersion", ctypes.c_uint),
        ("channelCount", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 10),
        ("channel", XLchannelConfig * 64),
    ]


class s_xl_fr_cluster_configuration(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("busGuardianEnable", ctypes.c_uint),
        ("busGuardianTick", ctypes.c_uint),
        ("externalClockCorrectionMode", ctypes.c_uint),
        ("gColdStartAttempts", ctypes.c_uint),
        ("gListenNoise", ctypes.c_uint),
        ("gMacroPerCycle", ctypes.c_uint),
        ("gMaxWithoutClockCorrectionFatal", ctypes.c_uint),
        ("gMaxWithoutClockCorrectionPassive", ctypes.c_uint),
        ("gNetworkManagementVectorLength", ctypes.c_uint),
        ("gNumberOfMinislots", ctypes.c_uint),
        ("gNumberOfStaticSlots", ctypes.c_uint),
        ("gOffsetCorrectionStart", ctypes.c_uint),
        ("gPayloadLengthStatic", ctypes.c_uint),
        ("gSyncNodeMax", ctypes.c_uint),
        ("gdActionPointOffset", ctypes.c_uint),
        ("gdDynamicSlotIdlePhase", ctypes.c_uint),
        ("gdMacrotick", ctypes.c_uint),
        ("gdMinislot", ctypes.c_uint),
        ("gdMiniSlotActionPointOffset", ctypes.c_uint),
        ("gdNIT", ctypes.c_uint),
        ("gdStaticSlot", ctypes.c_uint),
        ("gdSymbolWindow", ctypes.c_uint),
        ("gdTSSTransmitter", ctypes.c_uint),
        ("gdWakeupSymbolRxIdle", ctypes.c_uint),
        ("gdWakeupSymbolRxLow", ctypes.c_uint),
        ("gdWakeupSymbolRxWindow", ctypes.c_uint),
        ("gdWakeupSymbolTxIdle", ctypes.c_uint),
        ("gdWakeupSymbolTxLow", ctypes.c_uint),
        ("pAllowHaltDueToClock", ctypes.c_uint),
        ("pAllowPassiveToActive", ctypes.c_uint),
        ("pChannels", ctypes.c_uint),
        ("pClusterDriftDamping", ctypes.c_uint),
        ("pDecodingCorrection", ctypes.c_uint),
        ("pDelayCompensationA", ctypes.c_uint),
        ("pDelayCompensationB", ctypes.c_uint),
        ("pExternOffsetCorrection", ctypes.c_uint),
        ("pExternRateCorrection", ctypes.c_uint),
        ("pKeySlotUsedForStartup", ctypes.c_uint),
        ("pKeySlotUsedForSync", ctypes.c_uint),
        ("pLatestTx", ctypes.c_uint),
        ("pMacroInitialOffsetA", ctypes.c_uint),
        ("pMacroInitialOffsetB", ctypes.c_uint),
        ("pMaxPayloadLengthDynamic", ctypes.c_uint),
        ("pMicroInitialOffsetA", ctypes.c_uint),
        ("pMicroInitialOffsetB", ctypes.c_uint),
        ("pMicroPerCycle", ctypes.c_uint),
        ("pMicroPerMacroNom", ctypes.c_uint),
        ("pOffsetCorrectionOut", ctypes.c_uint),
        ("pRateCorrectionOut", ctypes.c_uint),
        ("pSamplesPerMicrotick", ctypes.c_uint),
        ("pSingleSlotEnabled", ctypes.c_uint),
        ("pWakeupChannel", ctypes.c_uint),
        ("pWakeupPattern", ctypes.c_uint),
        ("pdAcceptedStartupRange", ctypes.c_uint),
        ("pdListenTimeout", ctypes.c_uint),
        ("pdMaxDrift", ctypes.c_uint),
        ("pdMicrotick", ctypes.c_uint),
        ("gdCASRxLowMax", ctypes.c_uint),
        ("gChannels", ctypes.c_uint),
        ("vExternOffsetControl", ctypes.c_uint),
        ("vExternRateControl", ctypes.c_uint),
        ("pChannelsMTS", ctypes.c_uint),
        (
            "framePresetData",
            ctypes.c_uint,
        ),  # 16-bit value with data for pre-initializing the Flexray payload data words
        ("reserved", ctypes.c_uint * 15),
    ]


XLfrClusterConfig = s_xl_fr_cluster_configuration


# structure and defines for function xlFrGetChannelConfig
class s_xl_fr_channel_config(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_uint),  # XL_FR_CHANNEL_CFG_STATUS_xxx
        ("cfgMode", ctypes.c_uint),  # XL_FR_CHANNEL_CFG_MODE_xxx
        ("reserved", ctypes.c_uint * 6),
        ("xlFrClusterConfig", XLfrClusterConfig),  # same as used in function xlFrSetConfig
    ]


XLfrChannelConfig = s_xl_fr_channel_config

# defines for XLfrChannelConfig::status and XLbusParams::data::flexray::status
XL_FR_CHANNEL_CFG_STATUS_INIT_APP_PRESENT = 0x01
XL_FR_CHANNEL_CFG_STATUS_CHANNEL_ACTIVATED = 0x02
XL_FR_CHANNEL_CFG_STATUS_VALID_CLUSTER_CFG = 0x04
XL_FR_CHANNEL_CFG_STATUS_VALID_CFG_MODE = 0x08

# defines for XLfrChannelConfig::cfgMode and XLbusParams::data::flexray::cfgMode
XL_FR_CHANNEL_CFG_MODE_SYNCHRONOUS = 1
XL_FR_CHANNEL_CFG_MODE_COMBINED = 2
XL_FR_CHANNEL_CFG_MODE_ASYNCHRONOUS = 3


# defines for xlFrSetMode (frModes)
XL_FR_MODE_NORMAL = 0x00  # setup the VN3000 (eRay) normal operation mode. (default mode)
XL_FR_MODE_COLD_NORMAL = 0x04  # setup the VN3000 (Fujitsu) normal operation mode. (default mode)

# defines for xlFrSetMode (frStartupAttributes)
XL_FR_MODE_NONE = 0x00  # for normal use
XL_FR_MODE_WAKEUP = 0x01  # for wakeup
XL_FR_MODE_COLDSTART_LEADING = 0x02  # Coldstart path initiating the schedule synchronization
XL_FR_MODE_COLDSTART_FOLLOWING = 0x03  # Coldstart path joining other coldstart nodes
XL_FR_MODE_WAKEUP_AND_COLDSTART_LEADING = (
    0x04  # Send Wakeup and Coldstart path initiating the schedule synchronization
)
XL_FR_MODE_WAKEUP_AND_COLDSTART_FOLLOWING = (
    0x05  # Send Wakeup and Coldstart path joining other coldstart nodes
)


class s_xl_fr_set_modes(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("frMode", ctypes.c_uint),
        ("frStartupAttributes", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 30),
    ]


XLfrMode = s_xl_fr_set_modes

# defines for xlFrSetupSymbolWindow
XL_FR_SYMBOL_MTS = 0x01  # defines a MTS (Media Access Test Symbol)
XL_FR_SYMBOL_CAS = 0x02  # defines a CAS (Collision Avoidance Symbol)


# FR transceiver xlFrSetTransceiverMode modes
XL_FR_TRANSCEIVER_MODE_SLEEP = 0x01
XL_FR_TRANSCEIVER_MODE_NORMAL = 0x02
XL_FR_TRANSCEIVER_MODE_RECEIVE_ONLY = 0x03
XL_FR_TRANSCEIVER_MODE_STANDBY = 0x04

# defines for XL_FR_SYNC_PULSE_EV::triggerSource
# XL_FR_SYNC_PULSE_EXTERNAL    =      XL_SYNC_PULSE_EXTERNAL
# XL_FR_SYNC_PULSE_OUR         =           XL_SYNC_PULSE_OUR
# XL_FR_SYNC_PULSE_OUR_SHARED  =    XL_SYNC_PULSE_OUR_SHARED

# defines for xlFrActivateSpy, mode
XL_FR_SPY_MODE_ASYNCHRONOUS = 0x01
# include <poppack.h>

# include <pshpack8.h>

# defines for xlFrSetAcceptanceFilter
# filterStatus
XL_FR_FILTER_PASS = 0x00000000  # maching frame passes the filter
XL_FR_FILTER_BLOCK = 0x00000001  # maching frame is blocked

# filterTypeMask
XL_FR_FILTER_TYPE_DATA = 0x00000001  # specifies a data frame
XL_FR_FILTER_TYPE_NF = 0x00000002  # specifies a null frame in an used cycle
XL_FR_FILTER_TYPE_FILLUP_NF = 0x00000004  # specifies a null frame in an unused cycle

# filterChannelMask
XL_FR_FILTER_CHANNEL_A = 0x00000001  # specifies FlexRay channel A for the PC
XL_FR_FILTER_CHANNEL_B = 0x00000002  # specifies FlexRay channel B for the PC


class s_xl_fr_acceptance_filter(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("filterStatus", ctypes.c_uint),
        ("filterTypeMask", ctypes.c_uint),
        ("filterFirstSlot", ctypes.c_uint),  # beginning of the slot range
        (
            "filterLastSlot",
            ctypes.c_uint,
        ),  #  end of the slot range (can be the same as filterFirstSlot)
        ("filterChannelMask", ctypes.c_uint),  # channel A, B for PC, channel A, B for COB
    ]


XLfrAcceptanceFilter = s_xl_fr_acceptance_filter


# Flags for the flagsChip parameter
XL_FR_CHANNEL_A = 0x01
XL_FR_CHANNEL_B = 0x02
XL_FR_CHANNEL_AB = XL_FR_CHANNEL_A | XL_FR_CHANNEL_B
XL_FR_CC_COLD_A = 0x04  # second CC channel A to initiate the coldstart
XL_FR_CC_COLD_B = 0x08  # second CC channel B to initiate the coldstart
XL_FR_CC_COLD_AB = XL_FR_CC_COLD_A | XL_FR_CC_COLD_B
XL_FR_SPY_CHANNEL_A = 0x10  # Spy mode flags
XL_FR_SPY_CHANNEL_B = 0x20  # Spy mode flags

XL_FR_QUEUE_OVERFLOW = 0x0100  # driver queue overflow


# T_FLEXRAY_FRAME structure flags / defines
# defines for T_FLEXRAY_FRAME member flags
XL_FR_FRAMEFLAG_STARTUP = 0x0001  # indicates a startup frame
XL_FR_FRAMEFLAG_SYNC = 0x0002  # indicates a sync frame
XL_FR_FRAMEFLAG_NULLFRAME = 0x0004  # indicates a null frame
XL_FR_FRAMEFLAG_PAYLOAD_PREAMBLE = 0x0008  # indicates a present payload preamble bit
XL_FR_FRAMEFLAG_FR_RESERVED = 0x0010  # reserved by Flexray protocol


XL_FR_FRAMEFLAG_REQ_TXACK = 0x0020  # used for Tx events only
XL_FR_FRAMEFLAG_TXACK_SS = (
    XL_FR_FRAMEFLAG_REQ_TXACK  # indicates TxAck of SingleShot; used for TxAck events only
)
XL_FR_FRAMEFLAG_RX_UNEXPECTED = (
    XL_FR_FRAMEFLAG_REQ_TXACK  # indicates unexpected Rx frame; used for Rx events only
)

XL_FR_FRAMEFLAG_NEW_DATA_TX = (
    0x0040  # flag used with TxAcks to indicate first TxAck after data update
)
XL_FR_FRAMEFLAG_DATA_UPDATE_LOST = (
    0x0080  # flag used with TxAcks indicating that data update has been lost
)

XL_FR_FRAMEFLAG_SYNTAX_ERROR = 0x0200
XL_FR_FRAMEFLAG_CONTENT_ERROR = 0x0400
XL_FR_FRAMEFLAG_SLOT_BOUNDARY_VIOLATION = 0x0800
XL_FR_FRAMEFLAG_TX_CONFLICT = 0x1000
XL_FR_FRAMEFLAG_EMPTY_SLOT = 0x2000
XL_FR_FRAMEFLAG_FRAME_TRANSMITTED = 0x8000  # Only used with TxAcks: Frame has been transmitted. If not set after transmission, an error has occurred.

# XL_FR_SPY_FRAME_EV event: frameError value
XL_FR_SPY_FRAMEFLAG_FRAMING_ERROR = 0x01
XL_FR_SPY_FRAMEFLAG_HEADER_CRC_ERROR = 0x02
XL_FR_SPY_FRAMEFLAG_FRAME_CRC_ERROR = 0x04
XL_FR_SPY_FRAMEFLAG_BUS_ERROR = 0x08

# XL_FR_SPY_FRAME_EV event: frameCRC value
XL_FR_SPY_FRAMEFLAG_FRAME_CRC_NEW_LAYOUT = 0x80000000

# XL_FR_SPY_FRAME_EV event: frameFlags value
XL_FR_SPY_FRAMEFLAG_STATIC_FRAME = 0x01

# XL_FR_TX_FRAME event: txMode flags
XL_FR_TX_MODE_CYCLIC = 0x01  # 'normal' cyclic mode
XL_FR_TX_MODE_SINGLE_SHOT = 0x02  # sends only a single shot
XL_FR_TX_MODE_NONE = 0xFF  # switch off TX

# XL_FR_TX_FRAME event: incrementSize values
XL_FR_PAYLOAD_INCREMENT_8BIT = 8
XL_FR_PAYLOAD_INCREMENT_16BIT = 16
XL_FR_PAYLOAD_INCREMENT_32BIT = 32
XL_FR_PAYLOAD_INCREMENT_NONE = 0

# XL_FR_STATUS event: statusType (POC status)
XL_FR_STATUS_DEFAULT_CONFIG = 0x00  # indicates the actual state of the POC in operation control
XL_FR_STATUS_READY = 0x01  # ...
XL_FR_STATUS_NORMAL_ACTIVE = 0x02  # ...
XL_FR_STATUS_NORMAL_PASSIVE = 0x03  # ...
XL_FR_STATUS_HALT = 0x04  # ...
XL_FR_STATUS_MONITOR_MODE = 0x05  # ...
XL_FR_STATUS_CONFIG = 0x0F  # ...

XL_FR_STATUS_WAKEUP_STANDBY = 0x10  # indicates the actual state of the POC in the wakeup path
XL_FR_STATUS_WAKEUP_LISTEN = 0x11  # ...
XL_FR_STATUS_WAKEUP_SEND = 0x12  # ...
XL_FR_STATUS_WAKEUP_DETECT = 0x13  # ...

XL_FR_STATUS_STARTUP_PREPARE = 0x20  # indicates the actual state of the POC in the startup path
XL_FR_STATUS_COLDSTART_LISTEN = 0x21  # ...
XL_FR_STATUS_COLDSTART_COLLISION_RESOLUTION = 0x22  # ...
XL_FR_STATUS_COLDSTART_CONSISTENCY_CHECK = 0x23  # ...
XL_FR_STATUS_COLDSTART_GAP = 0x24  # ...
XL_FR_STATUS_COLDSTART_JOIN = 0x25  # ...
XL_FR_STATUS_INTEGRATION_COLDSTART_CHECK = 0x26  # ...
XL_FR_STATUS_INTEGRATION_LISTEN = 0x27  # ...
XL_FR_STATUS_INTEGRATION_CONSISTENCY_CHECK = 0x28  # ...
XL_FR_STATUS_INITIALIZE_SCHEDULE = 0x29  # ...
XL_FR_STATUS_ABORT_STARTUP = 0x2A  # ...
XL_FR_STATUS_STARTUP_SUCCESS = 0x2B  # ...

# XL_FR_ERROR event: XL_FR_ERROR_POC_MODE, errorMode
XL_FR_ERROR_POC_ACTIVE = 0x00  # Indicates the actual error mode of the POC: active (green)
XL_FR_ERROR_POC_PASSIVE = 0x01  # Indicates the actual error mode of the POC: passive (yellow)
XL_FR_ERROR_POC_COMM_HALT = 0x02  # Indicates the actual error mode of the POC: comm-halt (red)

# XL_FR_ERROR event: XL_FR_ERROR_NIT_FAILURE, flags
XL_FR_ERROR_NIT_SENA = 0x100  # Syntax Error during NIT Channel A
XL_FR_ERROR_NIT_SBNA = 0x200  # Slot Boundary Violation during NIT Channel B
XL_FR_ERROR_NIT_SENB = 0x400  # Syntax Error during NIT Channel A
XL_FR_ERROR_NIT_SBNB = 0x800  # Slot Boundary Violation during NIT Channel B

# XL_FR_ERROR event: XL_FR_ERROR_CLOCK_CORR_FAILURE, flags
XL_FR_ERROR_MISSING_OFFSET_CORRECTION = (
    0x00000001  # Set if no sync frames were received. -> no offset correction possible.
)
XL_FR_ERROR_MAX_OFFSET_CORRECTION_REACHED = (
    0x00000002  # Set if max. offset correction limit is reached.
)
XL_FR_ERROR_MISSING_RATE_CORRECTION = (
    0x00000004  # Set if no even/odd sync frames were received -> no rate correction possible.
)
XL_FR_ERROR_MAX_RATE_CORRECTION_REACHED = (
    0x00000008  # Set if max. rate correction limit is reached.
)

# XL_FR_ERROR event: XL_FR_ERROR_CC_ERROR, erayEir
XL_FR_ERROR_CC_PERR = 0x00000040  # Parity Error, data from MHDS (internal ERay error)
XL_FR_ERROR_CC_IIBA = 0x00000200  # Illegal Input Buffer Access (internal ERay error)
XL_FR_ERROR_CC_IOBA = 0x00000400  # Illegal Output Buffer Access (internal ERay error)
XL_FR_ERROR_CC_MHF = (
    0x00000800  # Message Handler Constraints Flag data from MHDF (internal ERay error)
)
XL_FR_ERROR_CC_EDA = 0x00010000  # Error Detection on channel A, data from ACS
XL_FR_ERROR_CC_LTVA = 0x00020000  # Latest Transmit Violation on channel A
XL_FR_ERROR_CC_TABA = 0x00040000  # Transmit Across Boundary on Channel A
XL_FR_ERROR_CC_EDB = 0x01000000  # Error Detection on channel B, data from ACS
XL_FR_ERROR_CC_LTVB = 0x02000000  # Latest Transmit Violation on channel B
XL_FR_ERROR_CC_TABB = 0x04000000  # Transmit Across Boundary on Channel B

# XL_FR_WAKEUP event: wakeupStatus
XL_FR_WAKEUP_UNDEFINED = 0x00  # No wakeup attempt since CONFIG state was left. (e.g. when a wakeup pattern A|B is received)
XL_FR_WAKEUP_RECEIVED_HEADER = 0x01  # Frame header without coding violation received.
XL_FR_WAKEUP_RECEIVED_WUP = 0x02  # Wakeup pattern on the configured wakeup channel received.
XL_FR_WAKEUP_COLLISION_HEADER = (
    0x03  # Detected collision during wakeup pattern transmission received.
)
XL_FR_WAKEUP_COLLISION_WUP = 0x04  # Collision during wakeup pattern transmission received.
XL_FR_WAKEUP_COLLISION_UNKNOWN = 0x05  # Set when the CC stops wakeup.
XL_FR_WAKEUP_TRANSMITTED = 0x06  # Completed the transmission of the wakeup pattern.
XL_FR_WAKEUP_EXTERNAL_WAKEUP = 0x07  # wakeup comes from external
XL_FR_WAKEUP_WUP_RECEIVED_WITHOUT_WUS_TX = 0x10  # wakeupt pattern received from flexray bus
XL_FR_WAKEUP_RESERVED = 0xFF

# XL_FR_SYMBOL_WINDOW event: flags
XL_FR_SYMBOL_STATUS_SESA = 0x01  # Syntax Error in Symbol Window Channel A
XL_FR_SYMBOL_STATUS_SBSA = 0x02  # Slot Boundary Violation in Symbol Window Channel A
XL_FR_SYMBOL_STATUS_TCSA = 0x04  # Transmission Conflict in Symbol Window Channel A
XL_FR_SYMBOL_STATUS_SESB = 0x08  # Syntax Error in Symbol Window Channel B
XL_FR_SYMBOL_STATUS_SBSB = 0x10  # Slot Boundary Violation in Symbol Window Channel B
XL_FR_SYMBOL_STATUS_TCSB = 0x20  # Transmission Conflict in Symbol Window Channel B
XL_FR_SYMBOL_STATUS_MTSA = 0x40  # MTS received in Symbol Window Channel A
XL_FR_SYMBOL_STATUS_MTSB = 0x80  # MTS received in Symbol Window Channel B


# include <pshpack8.h>

XL_FR_RX_EVENT_HEADER_SIZE = 32
XL_FR_MAX_EVENT_SIZE = 512

# Structures for FlexRay events


class s_xl_fr_start_cycle(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("cycleCount", ctypes.c_uint),
        ("vRateCorrection", ctypes.c_int),
        ("vOffsetCorrection", ctypes.c_int),
        ("vClockCorrectionFailed", ctypes.c_uint),
        ("vAllowPassivToActive", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 3),
    ]


XL_FR_START_CYCLE_EV = s_xl_fr_start_cycle


class s_xl_fr_rx_frame(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ushort),
        ("headerCRC", ctypes.c_ushort),
        ("slotID", ctypes.c_ushort),
        ("cycleCount", ctypes.c_uint8),
        ("payloadLength", ctypes.c_uint8),
        ("data", ctypes.c_uint8 * XL_FR_MAX_DATA_LENGTH),
    ]


XL_FR_RX_FRAME_EV = s_xl_fr_rx_frame


class s_xl_fr_tx_frame(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ushort),
        ("slotID", ctypes.c_ushort),
        ("offset", ctypes.c_uint8),
        ("repetition", ctypes.c_uint8),
        ("payloadLength", ctypes.c_uint8),
        ("txMode", ctypes.c_uint8),
        ("incrementSize", ctypes.c_uint8),
        ("incrementOffset", ctypes.c_uint8),
        ("reserved0", ctypes.c_uint8),
        ("reserved1", ctypes.c_uint8),
        ("data", ctypes.c_ubyte * XL_FR_MAX_DATA_LENGTH),
    ]


XL_FR_TX_FRAME_EV = s_xl_fr_tx_frame


class s_xl_fr_wakeup(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("cycleCount", ctypes.c_uint8),
        ("wakeupStatus", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 6),
    ]


XL_FR_WAKEUP_EV = s_xl_fr_wakeup


class s_xl_fr_symbol_window(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("symbol", ctypes.c_uint),
        ("flags", ctypes.c_uint),
        ("cycleCount", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 7),
    ]


XL_FR_SYMBOL_WINDOW_EV = s_xl_fr_symbol_window


class s_xl_fr_status(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("statusType", ctypes.c_uint),
        ("reserved", ctypes.c_uint),
    ]


XL_FR_STATUS_EV = s_xl_fr_status


class s_xl_fr_nm_vector(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("nmVector", ctypes.c_uint8 * 12),
        ("cycleCount", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 3),
    ]


XL_FR_NM_VECTOR_EV = s_xl_fr_nm_vector


class s_xl_fr_sync_pulse_ev(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("triggerSource", ctypes.c_uint),
        ("reserved", ctypes.c_uint),
        ("time", XLuint64),
    ]


XL_SYNC_PULSE_EV = s_xl_fr_sync_pulse_ev
XL_FR_SYNC_PULSE_EV = XL_SYNC_PULSE_EV


class s_xl_fr_error_poc_mode(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("errorMode", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 4),
    ]


XL_FR_ERROR_POC_MODE_EV = s_xl_fr_error_poc_mode


class s_xl_fr_error_sync_frames(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("evenSyncFramesA", ctypes.c_short),
        ("oddSyncFramesA", ctypes.c_short),
        ("evenSyncFramesB", ctypes.c_short),
        ("oddSyncFramesB", ctypes.c_short),
        ("reserved", ctypes.c_uint),
    ]


XL_FR_ERROR_SYNC_FRAMES_EV = s_xl_fr_error_sync_frames


class s_xl_fr_error_clock_corr_failure(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("evenSyncFramesA", ctypes.c_short),
        ("oddSyncFramesA", ctypes.c_short),
        ("evenSyncFramesB", ctypes.c_short),
        ("oddSyncFramesB", ctypes.c_short),
        ("flags", ctypes.c_uint),
        ("clockCorrFailedCounter", ctypes.c_uint),
        ("reserved", ctypes.c_uint),
    ]


XL_FR_ERROR_CLOCK_CORR_FAILURE_EV = s_xl_fr_error_clock_corr_failure


class s_xl_fr_error_nit_failure(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint),
        ("reserved", ctypes.c_uint),
    ]


XL_FR_ERROR_NIT_FAILURE_EV = s_xl_fr_error_nit_failure


class s_xl_fr_error_cc_error(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("ccError", ctypes.c_uint),
        ("reserved", ctypes.c_uint),
    ]


XL_FR_ERROR_CC_ERROR_EV = s_xl_fr_error_cc_error


class s_xl_fr_error_info(ctypes.Union):
    _fields_ = [
        ("frPocMode", XL_FR_ERROR_POC_MODE_EV),
        ("frSyncFramesBelowMin", XL_FR_ERROR_SYNC_FRAMES_EV),
        ("frSyncFramesOverload", XL_FR_ERROR_SYNC_FRAMES_EV),
        ("frClockCorrectionFailure", XL_FR_ERROR_CLOCK_CORR_FAILURE_EV),
        ("frNitFailure", XL_FR_ERROR_NIT_FAILURE_EV),
        ("frCCError", XL_FR_ERROR_CC_ERROR_EV),
    ]


class s_xl_fr_error(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("tag", ctypes.c_uint8),
        ("cycleCount", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8 * 6),
        ("errorInfo", s_xl_fr_error_info),
    ]


XL_FR_ERROR_EV = s_xl_fr_error


class s_xl_fr_spy_frame(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("frameLength", ctypes.c_uint),
        ("frameError", ctypes.c_uint8),
        ("tssLength", ctypes.c_uint8),
        ("headerFlags", ctypes.c_ushort),
        ("slotID", ctypes.c_ushort),
        ("headerCRC", ctypes.c_ushort),
        ("payloadLength", ctypes.c_uint8),
        ("cycleCount", ctypes.c_uint8),
        ("frameFlags", ctypes.c_uint8),
        ("reserved", ctypes.c_uint8),
        ("frameCRC", ctypes.c_uint),
        ("data", ctypes.c_uint8 * XL_FR_MAX_DATA_LENGTH),
    ]


XL_FR_SPY_FRAME_EV = s_xl_fr_spy_frame


class s_xl_fr_spy_symbol(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("lowLength", ctypes.c_ushort),
        ("reserved", ctypes.c_ushort),
    ]


XL_FR_SPY_SYMBOL_EV = s_xl_fr_spy_symbol


class s_xl_application_notification(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("notifyReason", ctypes.c_uint),
        ("reserved", ctypes.c_uint * 7),
    ]


XL_APPLICATION_NOTIFICATION_EV = s_xl_application_notification


class s_xl_fr_tag_data(IntrospectMixin, ctypes.Union):
    _fields_ = [
        ("frStartCycle", XL_FR_START_CYCLE_EV),
        ("frRxFrame", XL_FR_RX_FRAME_EV),
        ("frTxFrame", XL_FR_TX_FRAME_EV),
        ("frWakeup", XL_FR_WAKEUP_EV),
        ("frSymbolWindow", XL_FR_SYMBOL_WINDOW_EV),
        ("frError", XL_FR_ERROR_EV),
        ("frStatus", XL_FR_STATUS_EV),
        ("frNmVector", XL_FR_NM_VECTOR_EV),
        ("frSyncPulse", XL_FR_SYNC_PULSE_EV),
        ("frSpyFrame", XL_FR_SPY_FRAME_EV),
        ("frSpySymbol", XL_FR_SPY_SYMBOL_EV),
        ("applicationNotification", XL_APPLICATION_NOTIFICATION_EV),
        ("raw", ctypes.c_uint8 * (XL_FR_MAX_EVENT_SIZE - XL_FR_RX_EVENT_HEADER_SIZE)),
    ]


class s_xl_fr_event(IntrospectMixin, ctypes.Structure):
    _fields_ = [
        ("size", ctypes.c_int),
        ("tag", XLfrEventTag),
        ("channelIndex", ctypes.c_short),
        ("userHandle", ctypes.c_int),
        ("flagsChip", ctypes.c_short),
        ("reserved", ctypes.c_ushort),
        ("timeStamp", XLuint64),
        ("timeStampSync", XLuint64),
        ("tagData", s_xl_fr_tag_data),
    ]


XLfrEvent = s_xl_fr_event


xlOpenDriver = _xlapi_dll.xlOpenDriver
xlOpenDriver.argtypes = []
xlOpenDriver.restype = XLstatus
xlOpenDriver.errcheck = check_status_initialization

xlCloseDriver = _xlapi_dll.xlCloseDriver
xlCloseDriver.argtypes = []
xlCloseDriver.restype = XLstatus
xlCloseDriver.errcheck = check_status_operation

xlGetChannelMask = _xlapi_dll.xlGetChannelMask
xlGetChannelMask.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
xlGetChannelMask.restype = XLaccess

xlOpenPort = _xlapi_dll.xlOpenPort
xlOpenPort.argtypes = [
    ctypes.POINTER(XLportHandle),
    ctypes.c_char_p,
    XLaccess,
    ctypes.POINTER(XLaccess),
    ctypes.c_uint,
    ctypes.c_uint,
    ctypes.c_uint,
]
xlOpenPort.restype = XLstatus
xlOpenPort.errcheck = check_status_initialization

xlClosePort = _xlapi_dll.xlClosePort
xlClosePort.argtypes = [XLportHandle]
xlClosePort.restype = XLstatus
xlClosePort.errcheck = check_status_operation

xlActivateChannel = _xlapi_dll.xlActivateChannel
xlActivateChannel.argtypes = [
    XLportHandle,
    XLaccess,
    ctypes.c_uint,
    ctypes.c_uint,
]
xlActivateChannel.restype = XLstatus
xlActivateChannel.errcheck = check_status_operation

xlDeactivateChannel = _xlapi_dll.xlDeactivateChannel
xlDeactivateChannel.argtypes = [XLportHandle, XLaccess]
xlDeactivateChannel.restype = XLstatus
xlDeactivateChannel.errcheck = check_status_operation

xlFrTransmit = _xlapi_dll.xlFrTransmit
xlFrTransmit.argtypes = [
    XLportHandle,
    XLaccess,
    ctypes.POINTER(XLfrEvent),
]
xlFrTransmit.restype = XLstatus
xlFrTransmit.errcheck = check_rxtx_operation

xlFrReceive = _xlapi_dll.xlFrReceive
xlFrReceive.argtypes = [
    XLportHandle,
    ctypes.POINTER(XLfrEvent),
]
xlFrReceive.restype = XLstatus
xlFrReceive.errcheck = check_rxtx_operation

xlFrSetAcceptanceFilter = _xlapi_dll.xlFrSetAcceptanceFilter
xlFrSetAcceptanceFilter.argtypes = [
    XLportHandle,
    XLaccess,
    ctypes.POINTER(XLfrAcceptanceFilter),
]
xlFrSetAcceptanceFilter.restype = XLstatus
xlFrSetAcceptanceFilter.errcheck = check_status_initialization

xlGetKeymanBoxes = _xlapi_dll.xlGetKeymanBoxes
xlGetKeymanBoxes.argtypes = [
    ctypes.POINTER(ctypes.c_uint),
]
xlGetKeymanBoxes.restype = XLstatus
xlGetKeymanBoxes.errcheck = check_status_initialization

xlSetNotification = _xlapi_dll.xlSetNotification
xlSetNotification.argtypes = [
    XLportHandle,
    ctypes.POINTER(XLhandle),
    ctypes.c_int,
]
xlSetNotification.restype = XLstatus
xlSetNotification.errcheck = check_status_initialization

xlGetDriverConfig = _xlapi_dll.xlGetDriverConfig
xlGetDriverConfig.argtypes = [ctypes.POINTER(XLdriverConfig)]
xlGetDriverConfig.restype = XLstatus
xlGetDriverConfig.errcheck = check_status_operation

xlFlushReceiveQueue = _xlapi_dll.xlFlushReceiveQueue
xlFlushReceiveQueue.argtypes = [XLportHandle]
xlFlushReceiveQueue.restype = XLstatus
xlFlushReceiveQueue.errcheck = check_status_operation

xlFrSetConfiguration = _xlapi_dll.xlFrSetConfiguration
xlFrSetConfiguration.argtypes = [XLportHandle, XLaccess, ctypes.POINTER(XLfrClusterConfig)]
xlFrSetConfiguration.restype = XLstatus
xlFrSetConfiguration.errcheck = check_status_initialization

xlFrGetChannelConfiguration = _xlapi_dll.xlFrGetChannelConfiguration
xlFrGetChannelConfiguration.argtypes = [XLportHandle, XLaccess, ctypes.POINTER(XLfrChannelConfig)]
xlFrGetChannelConfiguration.restype = XLstatus
xlFrGetChannelConfiguration.errcheck = check_status_operation
