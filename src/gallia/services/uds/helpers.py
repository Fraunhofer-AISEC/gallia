# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from gallia.services.uds.core import service
from gallia.services.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import (
    MalformedResponse,
    RequestResponseMismatch,
    UnexpectedNegativeResponse,
)


def raise_for_error(response: service.UDSResponse, message: str | None = None) -> None:
    if isinstance(response, service.NegativeResponse):
        if response.trigger_request is None:
            raise ValueError("The response has not been assigned a trigger request")

        raise UnexpectedNegativeResponse.parse_dynamic(
            response.trigger_request, response, message
        )


def as_exception(
    response: service.NegativeResponse, message: str | None = None
) -> UnexpectedNegativeResponse:
    if response.trigger_request is None:
        raise ValueError("The response has not been assigned a trigger request")

    return UnexpectedNegativeResponse.parse_dynamic(
        response.trigger_request, response, message
    )


def raise_for_mismatch(
    request: service.UDSRequest,
    response: service.UDSResponse,
    message: str | None = None,
) -> None:
    if not response.matches(request):
        raise RequestResponseMismatch(request, response, message)


def _suggests_not_supported(
    response: service.UDSResponse | UDSErrorCodes,
    not_supported_codes: list[UDSErrorCodes],
) -> bool:
    if isinstance(response, service.UDSResponse):
        if not isinstance(response, service.NegativeResponse):
            return False

        response_code = response.response_code
    else:
        response_code = response

    return response_code in not_supported_codes


def suggests_service_not_supported(
    response: service.UDSResponse | UDSErrorCodes,
) -> bool:
    return _suggests_not_supported(
        response,
        [
            UDSErrorCodes.serviceNotSupported,
            UDSErrorCodes.serviceNotSupportedInActiveSession,
        ],
    )


def suggests_sub_function_not_supported(
    response: service.UDSResponse | UDSErrorCodes,
) -> bool:
    return _suggests_not_supported(
        response,
        [
            UDSErrorCodes.serviceNotSupported,
            UDSErrorCodes.serviceNotSupportedInActiveSession,
            UDSErrorCodes.subFunctionNotSupported,
            UDSErrorCodes.subFunctionNotSupportedInActiveSession,
        ],
    )


def suggests_identifier_not_supported(
    response: service.UDSResponse | UDSErrorCodes,
) -> bool:
    return _suggests_not_supported(
        response,
        [
            UDSErrorCodes.serviceNotSupported,
            UDSErrorCodes.serviceNotSupportedInActiveSession,
            UDSErrorCodes.subFunctionNotSupported,
            UDSErrorCodes.subFunctionNotSupportedInActiveSession,
            UDSErrorCodes.requestOutOfRange,
        ],
    )


def parse_pdu(pdu: bytes, request: service.UDSRequest) -> service.UDSResponse:
    parsed_request = service.UDSRequest.parse_dynamic(request.pdu)

    try:
        response = service.UDSResponse.parse_dynamic(pdu)
    except Exception as e:
        if pdu[0] == UDSIsoServices.NegativeResponse:
            response = service.RawNegativeResponse(pdu)
        else:
            response = service.RawPositiveResponse(pdu)

        raise MalformedResponse(request, response, str(e)) from e

    if not response.matches(parsed_request):
        raise RequestResponseMismatch(request, response)

    response.trigger_request = request

    return response
