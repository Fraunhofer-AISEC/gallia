import asyncio
import ipaddress
import re
import subprocess
from typing import Optional, Union
from urllib.parse import urlparse

from gallia.uds.core import service
from gallia.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.uds.core.exception import (
    UnexpectedNegativeResponse,
    RequestResponseMismatch,
    MalformedResponse,
)


async def cmd_output(cmd: list[str]) -> str:
    """cmd_output runs the command given as a list and returns a string
    of the corresponding output from STDOUT. If any error occurs, an error
    string is returned instead.
    """
    try:
        p = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await p.communicate()
    except Exception as e:
        return f"Error {cmd}: {e}"
    return stdout.decode().strip()


def split_host_port(
    hostport: str, default_port: Optional[int] = None
) -> tuple[str, Optional[int]]:
    """Splits a combination of ip address/hostname + port into hostname/ip address
    and port.  The default_port argument can be used to return a port if it is
    absent in the hostport argument."""
    # Special case: If hostport is an ipv6 then the urlparser does some weird
    # things with the colons and tries to parse ports. Catch this case early.
    host = ""
    port = default_port
    try:
        # If hostport is a valid ip address (v4 or v6) there
        # is no port included
        host = str(ipaddress.ip_address(hostport))
    except ValueError:
        pass

    # Only parse of hostport is not a valid ip address.
    if host == "":
        # urlparse() and urlsplit() insists on absolute URLs starting with "//".
        url = urlparse(f"//{hostport}")
        host = url.hostname if url.hostname else url.netloc
        port = url.port if url.port else default_port
    return host, port


def camel_to_snake(s: str) -> str:
    """Convert a CamelCase string to a snake_case string."""
    # https://stackoverflow.com/a/12867228
    return re.sub(r"((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))", r"_\1", s).lower()


def raise_for_error(
    response: service.UDSResponse, message: Optional[str] = None
) -> None:
    if isinstance(response, service.NegativeResponse):
        if response.trigger_request is None:
            raise ValueError("The response has not been assigned a trigger request")

        raise UnexpectedNegativeResponse.parse_dynamic(
            response.trigger_request, response, message
        )


def as_exception(
    response: service.NegativeResponse, message: Optional[str] = None
) -> UnexpectedNegativeResponse:
    if response.trigger_request is None:
        raise ValueError("The response has not been assigned a trigger request")

    return UnexpectedNegativeResponse.parse_dynamic(
        response.trigger_request, response, message
    )


def raise_for_mismatch(
    request: service.UDSRequest,
    response: service.UDSResponse,
    message: Optional[str] = None,
) -> None:
    if not response.matches(request):
        raise RequestResponseMismatch(request, response, message)


def _suggests_not_supported(
    response: Union[service.UDSResponse, UDSErrorCodes],
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
    response: Union[service.UDSResponse, UDSErrorCodes]
) -> bool:
    return _suggests_not_supported(
        response,
        [
            UDSErrorCodes.serviceNotSupported,
            UDSErrorCodes.serviceNotSupportedInActiveSession,
        ],
    )


def suggests_sub_function_not_supported(
    response: Union[service.UDSResponse, UDSErrorCodes]
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
    response: Union[service.UDSResponse, UDSErrorCodes]
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
