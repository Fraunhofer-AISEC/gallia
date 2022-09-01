# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from abc import ABC
from typing import Any

from gallia.services.uds.core.constants import UDSErrorCodes
from gallia.services.uds.core.service import NegativeResponse, UDSRequest, UDSResponse

# ****************
# * Base classes *
# ****************


class UDSException(Exception):
    def __init__(self, request: UDSRequest, message: str | None = None):
        self.request = request
        self.message = message

        super().__init__(message)

    def _message_core(self) -> str:
        return f"triggered by {self.request}"

    def __str__(self) -> str:
        message = self._message_core()

        if self.message is not None:
            message = f"{message}; {self.message}"

        return message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({repr(str(self))})"


class MissingResponse(UDSException, asyncio.TimeoutError):
    def _message_core(self) -> str:
        return f"triggered by {self.request}"


class ResponseException(UDSException):
    def __init__(
        self, request: UDSRequest, response: UDSResponse, message: str | None = None
    ):
        self.response = response

        super().__init__(request, message)

    def _message_core(self) -> str:
        return f"{self.response} to {self.request}"


class IllegalResponse(ResponseException):
    pass


class RequestResponseMismatch(IllegalResponse):
    def _message_core(self) -> str:
        return f"{repr(self.response)} to {self.request}"


class MalformedResponse(IllegalResponse):
    pass


class UnexpectedResponse(ResponseException):
    pass


class UnexpectedNegativeResponse(UnexpectedResponse, ABC):
    RESPONSE_CODE: UDSErrorCodes
    _CONCRETE_EXCEPTIONS: dict[
        UDSErrorCodes | None, type[UnexpectedNegativeResponse]
    ] = {}

    def __init_subclass__(cls, /, response_code: UDSErrorCodes, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        cls.RESPONSE_CODE = response_code
        UnexpectedNegativeResponse._CONCRETE_EXCEPTIONS[response_code] = cls

    def __init__(
        self,
        request: UDSRequest,
        response: NegativeResponse,
        message: str | None = None,
    ):
        self.response: NegativeResponse = response

        super().__init__(request, response, message)

    @staticmethod
    def parse_dynamic(
        request: UDSRequest, response: NegativeResponse, message: str | None = None
    ) -> UnexpectedNegativeResponse:
        return UnexpectedNegativeResponse._CONCRETE_EXCEPTIONS[response.response_code](
            request, response, message
        )


# ******************************************
# * Concrete Unexpected Negative Responses *
# ******************************************

# Auto-generated using the following code snippet:
# for ec in UDSErrorCodes:
#     print(f'class {ec.name[0].upper()}{ec.name[1:]}('
#           f'\n        UnexpectedNegativeResponse, response_code={str(ec)}):\n    pass\n\n')


class GeneralReject(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.generalReject
):
    pass


class ServiceNotSupported(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.serviceNotSupported
):
    pass


class SubFunctionNotSupported(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.subFunctionNotSupported
):
    pass


class IncorrectMessageLengthOrInvalidFormat(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.incorrectMessageLengthOrInvalidFormat,
):
    pass


class ResponseTooLong(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.responseTooLong
):
    pass


class BusyRepeatRequest(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.busyRepeatRequest
):
    pass


class ConditionsNotCorrect(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.conditionsNotCorrect
):
    pass


class RequestSequenceError(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.requestSequenceError
):
    pass


class NoResponseFromSubnetComponent(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.noResponseFromSubnetComponent,
):
    pass


class RequestOutOfRange(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.requestOutOfRange
):
    pass


class SecurityAccessDenied(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.securityAccessDenied
):
    pass


class AuthenticationRequired(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.authenticationRequired
):
    pass


class InvalidKey(UnexpectedNegativeResponse, response_code=UDSErrorCodes.invalidKey):
    pass


class ExceededNumberOfAttempts(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.exceededNumberOfAttempts
):
    pass


class RequiredTimeDelayNotExpired(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.requiredTimeDelayNotExpired
):
    pass


class SecureDataTransmissionRequired(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.secureDataTransmissionRequired,
):
    pass


class SecureDataTransmissionNotAllowed(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.secureDataTransmissionNotAllowed,
):
    pass


class SecureDataVerificationFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.secureDataVerificationFailed
):
    pass


class CertificateVerificationFailedInvalidTimePeriod(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidTimePeriod,
):
    pass


class CertificateVerificationFailedInvalidSignature(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidSignature,
):
    pass


class CertificateVerificationFailedInvalidChainOfTrust(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidChainOfTrust,
):
    pass


class CertificateVerificationFailedInvalidType(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidType,
):
    pass


class CertificateVerificationFailedInvalidFormat(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidFormat,
):
    pass


class CertificateVerificationFailedInvalidContent(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidContent,
):
    pass


class CertificateVerificationFailedInvalidScope(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidScope,
):
    pass


class CertificateVerificationFailedInvalidCertificateRevoked(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.certificateVerificationFailedInvalidCertificateRevoked,
):
    pass


class OwnershipVerificationFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.ownershipVerificationFailed
):
    pass


class ChallengeCalculationFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.challengeCalculationFailed
):
    pass


class SettingAccessRightsFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.settingAccessRightsFailed
):
    pass


class SessionKeyCreationOrDerivationFailed(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.sessionKeyCreationOrDerivationFailed,
):
    pass


class ConfigurationDataUsageFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.configurationDataUsageFailed
):
    pass


class DeAuthenticationFailed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.deAuthenticationFailed
):
    pass


class UploadDownloadNotAccepted(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.uploadDownloadNotAccepted
):
    pass


class TransferDataSuspended(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.transferDataSuspended
):
    pass


class GeneralProgrammingFailure(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.generalProgrammingFailure
):
    pass


class WrongBlockSequenceCounter(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.wrongBlockSequenceCounter
):
    pass


class RequestCorrectlyReceivedResponsePending(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.requestCorrectlyReceivedResponsePending,
):
    pass


class SubFunctionNotSupportedInActiveSession(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.subFunctionNotSupportedInActiveSession,
):
    pass


class ServiceNotSupportedInActiveSession(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.serviceNotSupportedInActiveSession,
):
    pass


class RpmTooHigh(UnexpectedNegativeResponse, response_code=UDSErrorCodes.rpmTooHigh):
    pass


class RpmTooLow(UnexpectedNegativeResponse, response_code=UDSErrorCodes.rpmTooLow):
    pass


class EngineIsRunning(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.engineIsRunning
):
    pass


class EngineIsNotRunning(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.engineIsNotRunning
):
    pass


class EngineRunTimeTooLow(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.engineRunTimeTooLow
):
    pass


class TemperatureTooHigh(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.temperatureTooHigh
):
    pass


class TemperatureTooLow(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.temperatureTooLow
):
    pass


class VehicleSpeedTooHigh(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.vehicleSpeedTooHigh
):
    pass


class VehicleSpeedTooLow(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.vehicleSpeedTooLow
):
    pass


class ThrottlePedalTooHigh(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.throttlePedalTooHigh
):
    pass


class ThrottlePedalTooLow(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.throttlePedalTooLow
):
    pass


class TransmissionRangeNotInNeutral(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.transmissionRangeNotInNeutral,
):
    pass


class TransmissionRangeNotInGear(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.transmissionRangeNotInGear
):
    pass


class BrakeSwitchNotClosed(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.brakeSwitchNotClosed
):
    pass


class ShifterLeverNotInPark(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.shifterLeverNotInPark
):
    pass


class TorqueConverterClutchLocked(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.torqueConverterClutchLocked
):
    pass


class VoltageTooHigh(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.voltageTooHigh
):
    pass


class VoltageTooLow(
    UnexpectedNegativeResponse, response_code=UDSErrorCodes.voltageTooLow
):
    pass


class ResourceTemporarilyNotAvailable(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.resourceTemporarilyNotAvailable,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF0(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF0,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF1(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF1,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF2(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF2,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF3(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF3,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF4(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF4,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF5(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF5,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF6(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF6,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF7(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF7,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF8(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF8,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectF9(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectF9,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectFA(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectFA,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectFB(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectFB,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectFC(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectFC,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectFD(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectFD,
):
    pass


class VehicleManufacturerSpecificConditionsNotCorrectFE(
    UnexpectedNegativeResponse,
    response_code=UDSErrorCodes.vehicleManufacturerSpecificConditionsNotCorrectFE,
):
    pass
