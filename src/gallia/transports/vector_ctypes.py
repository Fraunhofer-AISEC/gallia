import ctypes

from can.interfaces.vector import xldriver, xlclass

if dll_path := ctypes.find_library(xldriver.DLL_NAME):
    _xlapi_dll = ctypes.windll.LoadLibrary(dll_path)
else:
    raise FileNotFoundError(f"Vector XL library not found: {xldriver.DLL_NAME}")

# struct s_xl_fr_event {
#   unsigned int                          size;             // 4 - overall size of the complete event
#   XLfrEventTag                          tag;              // 2 - type of the event
#   unsigned short                        channelIndex;     // 2
#   unsigned int                          userHandle;       // 4
#   unsigned short                        flagsChip;        // 2 - frChannel e.g. XL_FR_CHANNEL_A (lower 8 bit), queue overflow (upper 8bit)
#   unsigned short                        reserved;         // 2
#   XLuint64                              timeStamp;        // 8 - raw timestamp
#   XLuint64                              timeStampSync;    // 8 - timestamp which is synchronized by the driver
#                                                           // ---------
#                                                           // 32 bytes -> XL_FR_RX_EVENT_HEADER_SIZE
#   union s_xl_fr_tag_data                tagData;
# };
#
# typedef struct s_xl_fr_event            XLfrEvent;

# typedef unsigned short                  XLfrEventTag;

XLfrEventTag = ctypes.c_ushort

class s_xl_fr_event(ctypes.Structure):
    _fields_ = [
        ctypes.c_int,
        XLfrEventTag,
        ctypes.c_short,
        ctypes.c_int,
        ctypes.c_short,
        ctypes.c_ushort,
        xlclass.XLuint64,
        xlclass.XLuint64,
    ]

XLfrEvent = s_xl_fr_event

xlFrTransmit = _xlapi_dll.xlFrTransmit
xlFrTransmit.argtypes = [
       xlclass.XLportHandle,
       xlclass.XLaccess,
       XLfrEvent,
]
xlFrTransmit.restype = [xlclass.XLstatus]
xlFrTransmit.errcheck = xldriver.check_status_operation


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
XL_ERR_FR_SLOT_ID_INVALID =     0x010B  
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


# function structures


# structure for xlFrSetConfiguration
# typedef struct s_xl_fr_cluster_configuration {
#   unsigned int      busGuardianEnable;
#   unsigned int	    baudrate;
#   unsigned int	    busGuardianTick;
#   unsigned int	    externalClockCorrectionMode;
#   unsigned int	    gColdStartAttempts;
#   unsigned int	    gListenNoise;
#   unsigned int	    gMacroPerCycle;
#   unsigned int	    gMaxWithoutClockCorrectionFatal;
#   unsigned int	    gMaxWithoutClockCorrectionPassive;
#   unsigned int	    gNetworkManagementVectorLength;
#   unsigned int	    gNumberOfMinislots;
#   unsigned int	    gNumberOfStaticSlots;
#   unsigned int	    gOffsetCorrectionStart;
#   unsigned int	    gPayloadLengthStatic;
#   unsigned int	    gSyncNodeMax;
#   unsigned int	    gdActionPointOffset;
#   unsigned int	    gdDynamicSlotIdlePhase;
#   unsigned int	    gdMacrotick;
#   unsigned int	    gdMinislot;
#   unsigned int	    gdMiniSlotActionPointOffset;
#   unsigned int	    gdNIT;
#   unsigned int	    gdStaticSlot;
#   unsigned int	    gdSymbolWindow;
#   unsigned int	    gdTSSTransmitter;
#   unsigned int	    gdWakeupSymbolRxIdle;
#   unsigned int	    gdWakeupSymbolRxLow;
#   unsigned int	    gdWakeupSymbolRxWindow;
#   unsigned int	    gdWakeupSymbolTxIdle;
#   unsigned int      gdWakeupSymbolTxLow;
#   unsigned int	    pAllowHaltDueToClock;
#   unsigned int	    pAllowPassiveToActive;
#   unsigned int	    pChannels;
#   unsigned int	    pClusterDriftDamping;
#   unsigned int	    pDecodingCorrection;
#   unsigned int	    pDelayCompensationA;
#   unsigned int	    pDelayCompensationB;
#   unsigned int	    pExternOffsetCorrection;
#   unsigned int	    pExternRateCorrection;
#   unsigned int	    pKeySlotUsedForStartup;
#   unsigned int	    pKeySlotUsedForSync;
#   unsigned int	    pLatestTx;
#   unsigned int	    pMacroInitialOffsetA;
#   unsigned int	    pMacroInitialOffsetB;
#   unsigned int	    pMaxPayloadLengthDynamic;
#   unsigned int	    pMicroInitialOffsetA;
#   unsigned int	    pMicroInitialOffsetB;
#   unsigned int	    pMicroPerCycle;
#   unsigned int	    pMicroPerMacroNom;
#   unsigned int      pOffsetCorrectionOut;
#   unsigned int      pRateCorrectionOut;
#   unsigned int      pSamplesPerMicrotick;
#   unsigned int      pSingleSlotEnabled;
#   unsigned int      pWakeupChannel;
#   unsigned int      pWakeupPattern;
#   unsigned int      pdAcceptedStartupRange;
#   unsigned int      pdListenTimeout;
#   unsigned int      pdMaxDrift;
#   unsigned int      pdMicrotick;
#   unsigned int      gdCASRxLowMax;
#   unsigned int      gChannels;
#   unsigned int      vExternOffsetControl;
#   unsigned int      vExternRateControl;
#   unsigned int      pChannelsMTS;
#
#   unsigned int      framePresetData;          //!< 16-bit value with data for pre-initializing the Flexray payload data words
#
#   unsigned int      reserved[15];
# } XLfrClusterConfig;


# TODO: Remove this; is just a template
# xlGetApplConfig = _xlapi_dll.xlGetApplConfig
# xlGetApplConfig.argtypes = [
#     ctypes.c_char_p,
#     ctypes.c_uint,
#     ctypes.POINTER(ctypes.c_uint),
#     ctypes.POINTER(ctypes.c_uint),
#     ctypes.POINTER(ctypes.c_uint),
#     ctypes.c_uint,
# ]
# xlGetApplConfig.restype = xlclass.XLstatus
# xlGetApplConfig.errcheck = check_status_initialization


# structure and defines for function xlFrGetChannelConfig
class s_xl_fr_channel_config(ctypes.Structure):
    _fields_ = [
        ("status", ctypes.c_uint),  # XL_FR_CHANNEL_CFG_STATUS_xxx
        ("cfgMode", ctypes.c_uint),  # XL_FR_CHANNEL_CFG_MODE_xxx
        ("reserved", ctypes.c_uint * 6),
        # TODO: ("xlFrClusterConfig", TODO),  // same as used in function xlFrSetConfig
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

# // structure for xlFrSetMode
# typedef struct s_xl_fr_set_modes {
#   unsigned int 	    frMode;
#   unsigned int 	    frStartupAttributes;
#   unsigned int 	    reserved[30];
# } XLfrMode;

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

# typedef struct  s_xl_fr_acceptance_filter {
#   unsigned int  filterStatus;                                     //!< defines if the specified frame should be blocked or pass the filter
#   unsigned int  filterTypeMask;                                   //!< specifies the frame type that should be filtered
#   unsigned int  filterFirstSlot;                                  //!< beginning of the slot range
#   unsigned int  filterLastSlot;                                   //!< end of the slot range (can be the same as filterFirstSlot)
#   unsigned int  filterChannelMask;                                //!< channel A, B for PC, channel A, B for COB
# } XLfrAcceptanceFilter;
# include <poppack.h>

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

# typedef struct s_xl_fr_start_cycle {
#   unsigned int                          cycleCount;
#   int                                   vRateCorrection;
#   int                                   vOffsetCorrection;
#   unsigned int                          vClockCorrectionFailed;
#   unsigned int                          vAllowPassivToActive;
#   unsigned int                          reserved[3];
# } XL_FR_START_CYCLE_EV;
#
# typedef struct s_xl_fr_rx_frame {
#   unsigned short                        flags;
#   unsigned short                        headerCRC;
#   unsigned short                        slotID;
#   unsigned char                         cycleCount;
#   unsigned char                         payloadLength;
#   unsigned char	                        data[XL_FR_MAX_DATA_LENGTH];
# } XL_FR_RX_FRAME_EV;
#
# typedef struct s_xl_fr_tx_frame {
#   unsigned short                        flags;
#   unsigned short                        slotID;
#   unsigned char                         offset;
#   unsigned char	                        repetition;
#   unsigned char                         payloadLength;
#   unsigned char	                        txMode;
#   unsigned char                         incrementSize;
#   unsigned char                         incrementOffset;
#   unsigned char                         reserved0;
#   unsigned char                         reserved1;
#   unsigned char	                        data[XL_FR_MAX_DATA_LENGTH];
# } XL_FR_TX_FRAME_EV;
#
# typedef struct s_xl_fr_wakeup {
#   unsigned char                         cycleCount;              //!< Actual cyclecount.
#   unsigned char                         wakeupStatus;            //!< XL_FR_WAKEUP_UNDEFINED, ...
#   unsigned char                         reserved[6];
# } XL_FR_WAKEUP_EV;
#
# typedef struct s_xl_fr_symbol_window {
#   unsigned int                          symbol;                  //!< XL_FR_SYMBOL_MTS, ...
#   unsigned int                          flags;                   //!< XL_FR_SYMBOL_STATUS_SESA, ...
#   unsigned char                         cycleCount;              //!< Actual cyclecount.
#   unsigned char                         reserved[7];
# } XL_FR_SYMBOL_WINDOW_EV;
#
# typedef struct s_xl_fr_status {
#   unsigned int                          statusType;              //!< POC status XL_FR_STATUS_ defines like, normal, active...
#   unsigned int                          reserved;
# } XL_FR_STATUS_EV;
#
# typedef struct s_xl_fr_nm_vector {
#   unsigned char                         nmVector[12];
#   unsigned char                         cycleCount;              //!< Actual cyclecount.
#   unsigned char                         reserved[3];
# } XL_FR_NM_VECTOR_EV;
#
# typedef XL_SYNC_PULSE_EV XL_FR_SYNC_PULSE_EV;
#
# typedef struct s_xl_fr_error_poc_mode {
#   unsigned char                         errorMode;               //!< error mode like: active, passive, comm_halt
#   unsigned char                         reserved[3];
# } XL_FR_ERROR_POC_MODE_EV;
#
# typedef struct s_xl_fr_error_sync_frames {
#   unsigned short                        evenSyncFramesA;         //!< valid RX/TX sync frames on frCh A for even cycles
#   unsigned short                        oddSyncFramesA;          //!< valid RX/TX sync frames on frCh A for odd cycles
#   unsigned short                        evenSyncFramesB;         //!< valid RX/TX sync frames on frCh B for even cycles
#   unsigned short                        oddSyncFramesB;          //!< valid RX/TX sync frames on frCh B for odd cycles
#   unsigned int                          reserved;
# } XL_FR_ERROR_SYNC_FRAMES_EV;
#
# typedef struct s_xl_fr_error_clock_corr_failure {
#   unsigned short                        evenSyncFramesA;         //!< valid RX/TX sync frames on frCh A for even cycles
#   unsigned short                        oddSyncFramesA;          //!< valid RX/TX sync frames on frCh A for odd cycles
#   unsigned short                        evenSyncFramesB;         //!< valid RX/TX sync frames on frCh B for even cycles
#   unsigned short                        oddSyncFramesB;          //!< valid RX/TX sync frames on frCh B for odd cycles
#   unsigned int                          flags;                   //!< missing/maximum rate/offset correction flags.
#   unsigned int                          clockCorrFailedCounter;  //!< E-Ray: CCEV register (CCFC value)
#   unsigned int                          reserved;
# } XL_FR_ERROR_CLOCK_CORR_FAILURE_EV;
#
# typedef struct s_xl_fr_error_nit_failure {
#   unsigned int                          flags;                   //!< flags for NIT boundary, syntax error...
#   unsigned int                          reserved;
# } XL_FR_ERROR_NIT_FAILURE_EV;
#
# typedef struct s_xl_fr_error_cc_error {
#   unsigned int                          ccError;                 //!< internal CC errors (Transmit Across Boundary, Transmit Violation...)
#   unsigned int                          reserved;
# } XL_FR_ERROR_CC_ERROR_EV;
#
# union s_xl_fr_error_info {
#   XL_FR_ERROR_POC_MODE_EV               frPocMode;               //!< E-RAY: EIR_PEMC
#   XL_FR_ERROR_SYNC_FRAMES_EV            frSyncFramesBelowMin;    //!< E-RAY: EIR_SFBM
#   XL_FR_ERROR_SYNC_FRAMES_EV            frSyncFramesOverload;    //!< E-RAY: EIR_SFO
#   XL_FR_ERROR_CLOCK_CORR_FAILURE_EV     frClockCorrectionFailure;//!< E-RAY: EIR_CCF
#   XL_FR_ERROR_NIT_FAILURE_EV            frNitFailure;            //!< NIT part of the E_RAY: SWNIT register
#   XL_FR_ERROR_CC_ERROR_EV               frCCError;               //!< internal CC error flags (E-RAY: EIR)
# };
#
# typedef struct s_xl_fr_error {
#   unsigned char                         tag;
#   unsigned char                         cycleCount;
#   unsigned char                         reserved[6];
#   union s_xl_fr_error_info              errorInfo;
# } XL_FR_ERROR_EV;
#
# typedef struct s_xl_fr_spy_frame {
#   unsigned int                          frameLength;
#   unsigned char                         frameError;	             //!< XL_FR_SPY_FRAMEFLAG_XXX values
#   unsigned char                         tssLength;
#   unsigned short                        headerFlags;
#   unsigned short                        slotID;
#   unsigned short                        headerCRC;
#   unsigned char                         payloadLength;
#   unsigned char                         cycleCount;
#   unsigned char                         frameFlags;
#   unsigned char                         reserved;
#   unsigned int                          frameCRC;
#   unsigned char                         data[XL_FR_MAX_DATA_LENGTH];
# } XL_FR_SPY_FRAME_EV;
#
# typedef struct s_xl_fr_spy_symbol {
#   unsigned short                        lowLength;
#   unsigned short                        reserved;
#  } XL_FR_SPY_SYMBOL_EV;


# rx event definition

# union s_xl_fr_tag_data {
#   XL_FR_START_CYCLE_EV                  frStartCycle;
#   XL_FR_RX_FRAME_EV                     frRxFrame;
#   XL_FR_TX_FRAME_EV                     frTxFrame;
#   XL_FR_WAKEUP_EV                       frWakeup;
#   XL_FR_SYMBOL_WINDOW_EV                frSymbolWindow;
#   XL_FR_ERROR_EV                        frError;
#   XL_FR_STATUS_EV                       frStatus;
#   XL_FR_NM_VECTOR_EV                    frNmVector;
#   XL_FR_SYNC_PULSE_EV                   frSyncPulse;
#   XL_FR_SPY_FRAME_EV                    frSpyFrame;
#   XL_FR_SPY_SYMBOL_EV                   frSpySymbol;
#
#   XL_APPLICATION_NOTIFICATION_EV        applicationNotification;
#
#   unsigned char                         raw[XL_FR_MAX_EVENT_SIZE - XL_FR_RX_EVENT_HEADER_SIZE];
# };
#
# typedef unsigned short                  XLfrEventTag;
#
