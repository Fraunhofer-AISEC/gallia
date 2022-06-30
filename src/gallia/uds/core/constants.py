# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum, unique


@unique
class UDSIsoServices(IntEnum):
    ShowCurrentData = 0x01
    ShowFreezeFrameData = 0x02
    ShowstoredDiagnosticTroubleCodes = 0x03
    ClearDiagnosticTroubleCodesAndStoredValues = 0x04
    TestResultsOxygenSensorMonitoring = 0x05
    TestResultsOtherComponentSystemMonitoring = 0x06
    ShowPendingDiagnosticTroubleCodes = 0x07
    ControlOperationOfOnBoardComponentSystem = 0x08
    RequestVehicleInformation = 0x09
    PermanentDiagnosticTroubleCodes = 0x0A
    DiagnosticSessionControl = 0x10
    EcuReset = 0x11
    SecurityAccess = 0x27
    CommunicationControl = 0x28
    TesterPresent = 0x3E
    Authentication = 0x29
    AccessTimingParameter = 0x83
    SecuredDataTransmission = 0x84
    ControlDTCSetting = 0x85
    ResponseOnEvent = 0x86
    LinkControl = 0x87
    ReadDataByIdentifier = 0x22
    ReadMemoryByAddress = 0x23
    ReadScalingDataByIdentifier = 0x24
    ReadDataByPeriodicIdentifier = 0x2A
    DynamicallyDefineDataIdentifier = 0x2C
    WriteDataByIdentifier = 0x2E
    WriteMemoryByAddress = 0x3D
    ClearDiagnosticInformation = 0x14
    ReadDTCInformation = 0x19
    InputOutputControlByIdentifier = 0x2F
    RoutineControl = 0x31
    RequestDownload = 0x34
    RequestUpload = 0x35
    TransferData = 0x36
    RequestTransferExit = 0x37
    RequestFileTransfer = 0x38
    NegativeResponse = 0x7F


@unique
class UDSErrorCodes(IntEnum):
    generalReject = 0x10
    serviceNotSupported = 0x11
    subFunctionNotSupported = 0x12
    incorrectMessageLengthOrInvalidFormat = 0x13
    responseTooLong = 0x14
    busyRepeatRequest = 0x21
    conditionsNotCorrect = 0x22
    requestSequenceError = 0x24
    noResponseFromSubnetComponent = 0x25
    failurePreventsExecutionOfRequestedAction = 0x26
    requestOutOfRange = 0x31
    securityAccessDenied = 0x33
    authenticationRequired = 0x34
    invalidKey = 0x35
    exceededNumberOfAttempts = 0x36
    requiredTimeDelayNotExpired = 0x37
    secureDataTransmissionRequired = 0x38
    secureDataTransmissionNotAllowed = 0x39
    secureDataVerificationFailed = 0x3A
    certificateVerificationFailedInvalidTimePeriod = 0x50
    certificateVerificationFailedInvalidSignature = 0x51
    certificateVerificationFailedInvalidChainOfTrust = 0x52
    certificateVerificationFailedInvalidType = 0x53
    certificateVerificationFailedInvalidFormat = 0x54
    certificateVerificationFailedInvalidContent = 0x55
    certificateVerificationFailedInvalidScope = 0x56
    certificateVerificationFailedInvalidCertificateRevoked = 0x57
    ownershipVerificationFailed = 0x58
    challengeCalculationFailed = 0x59
    settingAccessRightsFailed = 0x5A
    sessionKeyCreationOrDerivationFailed = 0x5B
    configurationDataUsageFailed = 0x5C
    deAuthenticationFailed = 0x5D
    uploadDownloadNotAccepted = 0x70
    transferDataSuspended = 0x71
    generalProgrammingFailure = 0x72
    wrongBlockSequenceCounter = 0x73
    requestCorrectlyReceivedResponsePending = 0x78
    subFunctionNotSupportedInActiveSession = 0x7E
    serviceNotSupportedInActiveSession = 0x7F
    rpmTooHigh = 0x81
    rpmTooLow = 0x82
    engineIsRunning = 0x83
    engineIsNotRunning = 0x84
    engineRunTimeTooLow = 0x85
    temperatureTooHigh = 0x86
    temperatureTooLow = 0x87
    vehicleSpeedTooHigh = 0x88
    vehicleSpeedTooLow = 0x89
    throttlePedalTooHigh = 0x8A
    throttlePedalTooLow = 0x8B
    transmissionRangeNotInNeutral = 0x8C
    transmissionRangeNotInGear = 0x8D
    brakeSwitchNotClosed = 0x8F
    shifterLeverNotInPark = 0x90
    torqueConverterClutchLocked = 0x91
    voltageTooHigh = 0x92
    voltageTooLow = 0x93
    resourceTemporarilyNotAvailable = 0x94
    vehicleManufacturerSpecificConditionsNotCorrectF0 = 0xF0
    vehicleManufacturerSpecificConditionsNotCorrectF1 = 0xF1
    vehicleManufacturerSpecificConditionsNotCorrectF2 = 0xF2
    vehicleManufacturerSpecificConditionsNotCorrectF3 = 0xF3
    vehicleManufacturerSpecificConditionsNotCorrectF4 = 0xF4
    vehicleManufacturerSpecificConditionsNotCorrectF5 = 0xF5
    vehicleManufacturerSpecificConditionsNotCorrectF6 = 0xF6
    vehicleManufacturerSpecificConditionsNotCorrectF7 = 0xF7
    vehicleManufacturerSpecificConditionsNotCorrectF8 = 0xF8
    vehicleManufacturerSpecificConditionsNotCorrectF9 = 0xF9
    vehicleManufacturerSpecificConditionsNotCorrectFA = 0xFA
    vehicleManufacturerSpecificConditionsNotCorrectFB = 0xFB
    vehicleManufacturerSpecificConditionsNotCorrectFC = 0xFC
    vehicleManufacturerSpecificConditionsNotCorrectFD = 0xFD
    vehicleManufacturerSpecificConditionsNotCorrectFE = 0xFE


@unique
class DSCSubFuncs(IntEnum):
    # defaultSession
    DS = 0x01
    # programmingSession
    PRGS = 0x02
    # extendedDiagnosticSession
    EXTDS = 0x03
    # safetySystemDiagnosticSession
    SSDS = 0x04


@unique
class RCSubFuncs(IntEnum):
    # start routine
    STR = 0x01
    # stop routine
    STPR = 0x02
    # request routine results
    RRR = 0x03


@unique
class CCSubFuncs(IntEnum):
    # enableRxAndTx
    ERXTX = 0x00
    # enableRxAndDisableTx
    ERXDTX = 0x01
    # disableRxAndEnableTx
    DRXETX = 0x02
    # disableRxAndTx
    DRXTX = 0x03
    # Plus vendor specific stuff...


@unique
class CDTCSSubFuncs(IntEnum):
    ON = 0x01
    OFF = 0x02
    # Plus vendor specific stuff...


@unique
class RDTCISubFuncs(IntEnum):
    # reportNumberOfDTCByStatusMask
    RNODTCBSM = 0x01
    # reportDTCByStatusMask
    RDTCBSM = 0x02
    # reportSupportedDTC
    RSUPDTC = 0x0A
    # reportFirstTestFailedDTC
    RFTFDTC = 0x0B
    # reportFirstConfirmedDTC
    RFCDTC = 0x0C
    # reportMostRecentTestFailedDTC
    RMRTFDTC = 0x0D
    # reportMostRecentConfirmedDTC
    RMRCDTC = 0x0E
    # reportMirrorMemoryDTCByStatusMask
    RMMDTCBSM = 0x0F
    # reportNumberOfMirrorMemoryDTCByStatusMask
    RNOMMDTCBSM = 0x11
    # reportNumberOfEmissionsRelatedOBDDTCByStatusMask
    RNOOBDDTCBSM = 0x12
    # reportEmissionsRelatedOBDDTCByStatusMask
    ROBDDTCBSM = 0x13
    # reportDTCFaultDetectionCounter
    RDTCFDC = 0x14
    # reportDTCWithPermanentStatus
    RDTCWPS = 0x15


@unique
class ERSubFuncs(IntEnum):
    # hardReset
    HR = 0x01
    # keyOffOnReset
    KOFFONR = 0x02
    # softReset
    SR = 0x03
    # enableRapidPowerShutDown
    ERPSD = 0x04
    # disableRapidPowerShutDown
    DRPSD = 0x05


@unique
class InputOutputControlParameter(IntEnum):
    # returnControlToECU
    RCTECU = 0x00
    # resetToDefault
    RTD = 0x01
    # freezeCurrentState
    FCS = 0x02
    # shortTermAdjustment
    STA = 0x03


@unique
class DTCFormatIdentifier(IntEnum):
    # ISO15031-6DTCFormat
    ISO_15031_6 = 0x00
    # ISO14229-1DTCFormat
    ISO_14229_1 = 0x01
    # SAEJ1939-73DTCFormat
    SAE_J1939_73 = 0x02
    # ISO11992-4DTCFormat
    ISO_11992_4 = 0x03


# This dictionary maps UDS services to the echo length of their responses.
# Echos in that context are values which are identical to the corresponding entry in a request.
# Therefore they can be used to match responses to requests but are not adding any new information.
# Some services (e.g. rdbi) can accept more data records in a request and response accordingly.
# In that case there can be several echos. However, as of the time of writing, multiple data
# records are not considered in the rest of the code.
# For a complete handling one might need to transfer this to a function.
UDSIsoServicesEchoLength = {
    UDSIsoServices.DiagnosticSessionControl: 1,
    UDSIsoServices.EcuReset: 1,
    UDSIsoServices.SecurityAccess: 1,
    UDSIsoServices.CommunicationControl: 1,
    UDSIsoServices.TesterPresent: 1,
    UDSIsoServices.AccessTimingParameter: 1,
    UDSIsoServices.ControlDTCSetting: 1,
    UDSIsoServices.ResponseOnEvent: 1,  # There are a number of echos but only one byte is a prefix
    UDSIsoServices.LinkControl: 1,
    UDSIsoServices.ReadDataByIdentifier: 2,
    UDSIsoServices.ReadScalingDataByIdentifier: 2,
    UDSIsoServices.ReadDataByPeriodicIdentifier: 1,  # This one is a little weird
    UDSIsoServices.DynamicallyDefineDataIdentifier: 3,
    UDSIsoServices.WriteDataByIdentifier: 2,
    # This one would require to parse the addressAndLengthFormatIdentifier field
    # UDSIsoServices.WriteMemoryByAddress: None,
    UDSIsoServices.ReadDTCInformation: 1,
    UDSIsoServices.InputOutputControlByIdentifier: 2,
    UDSIsoServices.RoutineControl: 3,
    UDSIsoServices.TransferData: 1,
}


@unique
class DataIdentifier(IntEnum):
    ActiveDiagnosticSessionDataIdentifier = 0xF186
