# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=too-many-lines, useless-super-delegation

from __future__ import annotations

import inspect
import struct
from abc import ABC, abstractmethod
from collections.abc import Sequence
from struct import pack
from typing import Any, TypeVar

from gallia.log import get_logger
from gallia.services.uds.core.constants import (
    DTCFormatIdentifier,
    InputOutputControlParameter,
    RCSubFuncs,
    RDTCISubFuncs,
    UDSErrorCodes,
    UDSIsoServices,
    UDSIsoServicesEchoLength,
)
from gallia.services.uds.core.utils import (
    address_and_size_length,
    any_repr,
    bytes_repr,
    check_data_identifier,
    check_length,
    check_range,
    check_sub_function,
    from_bytes,
    int_repr,
    service_repr,
    sub_function_split,
    to_bytes,
    uds_memory_parameters,
)

logger = get_logger("uds")

# ****************
# * Base classes *
# ****************


T_UDSRequest = TypeVar("T_UDSRequest", bound="UDSRequest")


class UDSRequest(ABC):
    SERVICE_ID: int | None
    RESPONSE_TYPE: type[PositiveResponse]
    _MINIMAL_LENGTH: int
    _MAXIMAL_LENGTH: int | None

    def __init_subclass__(
        cls,
        /,
        service_id: int | None,
        response_type: type[PositiveResponse],
        minimal_length: int,
        maximal_length: int | None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls.SERVICE_ID = service_id
        cls.RESPONSE_TYPE = response_type
        cls._MINIMAL_LENGTH = minimal_length
        cls._MAXIMAL_LENGTH = maximal_length

    @property
    @abstractmethod
    def pdu(self) -> bytes:
        pass

    @classmethod
    def from_pdu(cls: type[T_UDSRequest], pdu: bytes) -> T_UDSRequest:
        cls._check_pdu(pdu)
        result = cls._from_pdu(pdu)

        assert result.pdu == pdu

        return result

    @classmethod
    @abstractmethod
    def _from_pdu(cls: type[T_UDSRequest], pdu: bytes) -> T_UDSRequest:
        pass

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        check_length(pdu, cls._MINIMAL_LENGTH, cls._MAXIMAL_LENGTH)

        if cls.SERVICE_ID is not None and pdu[0] != cls.SERVICE_ID:
            raise ValueError(
                f"Service ID mismatch: {hex(pdu[0])} != {hex(cls.SERVICE_ID)}"
            )

    @property
    def service_id(self) -> int:
        return self.pdu[0]

    @property
    def data(self) -> bytes:
        return self.pdu[1:]

    def __repr__(self) -> str:
        title = self.__class__.__name__
        relevant_attributes = {}

        for attr, value in self.__dict__.items():
            if not attr.startswith("_"):
                relevant_attributes[attr] = any_repr(value)

        attributes = ", ".join(
            f"{attr}={value}" for attr, value in relevant_attributes.items()
        )
        return f"{title}({attributes})"

    @staticmethod
    def parse_dynamic(pdu: bytes) -> UDSRequest:
        try:
            logger.trace("Dynamically parsing request")
            logger.trace(f" - Got PDU {pdu.hex()}")
            # pylint: disable=protected-access
            request_service = UDSService._SERVICES[UDSIsoServices(pdu[0])]

            logger.trace(f" - Inferred service {request_service.__name__}")

            if (request_type := request_service.Request) is not None:
                logger.trace(f" - Trying {request_type.__name__}")
                return request_type.from_pdu(pdu)
            if issubclass(request_service, SpecializedSubFunctionService):
                logger.trace(" - Trying to infer subFunction")
                # pylint: disable=protected-access
                request_sub_function = request_service._sub_function_type(pdu)
                logger.trace(f" - Inferred subFunction {request_sub_function.__name__}")
                assert (request_type := request_sub_function.Request) is not None
                logger.trace(f" - Trying {request_type.__name__}")
                return request_type.from_pdu(pdu)

            raise ValueError("Request cannot be parsed")
        except Exception as e:
            logger.trace(
                f" - Falling back to RawRequest because of the following problem: {repr(e)}"
            )
            return RawRequest(pdu)


T_UDSResponse = TypeVar("T_UDSResponse", bound="UDSResponse")


class UDSResponse(ABC):
    SERVICE_ID: int | None
    RESPONSE_SERVICE_ID: int | None
    _MINIMAL_LENGTH: int
    _MAXIMAL_LENGTH: int | None

    def __init_subclass__(
        cls,
        /,
        service_id: int | None,
        minimal_length: int,
        maximal_length: int | None,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls.SERVICE_ID = service_id
        cls.RESPONSE_SERVICE_ID = None if service_id is None else service_id + 0x40
        cls._MINIMAL_LENGTH = minimal_length
        cls._MAXIMAL_LENGTH = maximal_length

    def __init__(self) -> None:
        self.trigger_request: UDSRequest | None = None

    @property
    @abstractmethod
    def pdu(self) -> bytes:
        pass

    @classmethod
    def from_pdu(cls: type[T_UDSResponse], pdu: bytes) -> T_UDSResponse:
        cls._check_pdu(pdu)
        return cls._from_pdu(pdu)

    @classmethod
    @abstractmethod
    def _from_pdu(cls: type[T_UDSResponse], pdu: bytes) -> T_UDSResponse:
        pass

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        check_length(pdu, cls._MINIMAL_LENGTH, cls._MAXIMAL_LENGTH)

        if (
            cls.RESPONSE_SERVICE_ID is not None
            and cls.SERVICE_ID is not None
            and pdu[0] != cls.RESPONSE_SERVICE_ID
        ):
            raise ValueError(
                f"Service ID mismatch: {hex(pdu[0])} != {hex(cls.RESPONSE_SERVICE_ID)}"
                f" ({hex(cls.SERVICE_ID)} + 0x40)"
            )

    @property
    def service_id(self) -> int:
        assert self.SERVICE_ID is not None

        return self.SERVICE_ID

    @abstractmethod
    def matches(self, request: UDSRequest) -> bool:
        pass

    @staticmethod
    def parse_dynamic(pdu: bytes) -> UDSResponse:
        if pdu[0] == UDSIsoServices.NegativeResponse:
            return NegativeResponse.from_pdu(pdu)

        response_type: type[PositiveResponse]

        logger.trace("Dynamically parsing response")
        logger.trace(f" - Got PDU {pdu.hex()}")

        try:
            # pylint: disable=protected-access
            response_service = UDSService._SERVICES[UDSIsoServices(pdu[0] - 0x40)]
        except Exception:
            logger.trace(
                " - Falling back to raw response because the service is unknown"
            )
            return RawPositiveResponse(pdu)

        logger.trace(f" - Inferred service {response_service.__name__}")

        if response_service.Response is not None:
            response_type = response_service.Response
        elif issubclass(response_service, SpecializedSubFunctionService):
            if len(pdu) < 2:
                raise ValueError(
                    "Message of subfunction service contains no subfunction"
                )

            logger.trace(" - Trying to infer subfunction")
            try:
                # pylint: disable=protected-access
                response_sub_function = response_service._sub_function_type(pdu)
            except ValueError as e:
                logger.trace(f" - Falling back to raw response because {str(e)}")
                return RawPositiveResponse(pdu)

            logger.trace(f" - Inferred subFunction {response_sub_function.__name__}")
            assert (response_type_ := response_sub_function.Response) is not None
            response_type = response_type_
        else:
            logger.trace(
                " - Falling back to raw response because the response cannot be parsed"
            )
            return RawPositiveResponse(pdu)

        logger.trace(f" - Trying {response_type.__name__}")
        return response_type.from_pdu(pdu)


T_RawResponse = TypeVar("T_RawResponse", bound="RawResponse")


class RawResponse(
    UDSResponse, ABC, service_id=None, minimal_length=1, maximal_length=None
):
    def __init__(self, pdu: bytes) -> None:
        super().__init__()

        self._pdu = pdu

    @classmethod
    def _from_pdu(cls: type[T_RawResponse], pdu: bytes) -> T_RawResponse:
        return cls(pdu)

    @property
    def pdu(self) -> bytes:
        return self._pdu

    @pdu.setter
    def pdu(self, pdu: bytes) -> None:
        self._pdu = pdu

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pdu={bytes_repr(self.pdu)})"


class NegativeResponseBase(
    UDSResponse,
    ABC,
    service_id=UDSIsoServices.NegativeResponse,
    minimal_length=1,
    maximal_length=None,
):
    pass


class RawNegativeResponse(
    NegativeResponseBase,
    RawResponse,
    service_id=UDSIsoServices.NegativeResponse,
    minimal_length=1,
    maximal_length=None,
):
    def matches(self, request: UDSRequest) -> bool:
        return len(self.pdu) > 1 and self.pdu[1] == request.service_id


class NegativeResponse(
    NegativeResponseBase,
    service_id=UDSIsoServices.NegativeResponse,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, request_service_id: int, response_code: UDSErrorCodes) -> None:
        super().__init__()

        self.request_service_id = request_service_id
        self.response_code = response_code

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BBB", self.SERVICE_ID, self.request_service_id, self.response_code
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> NegativeResponse:
        return NegativeResponse(pdu[1], UDSErrorCodes(pdu[2]))

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        check_length(pdu, cls._MINIMAL_LENGTH, cls._MAXIMAL_LENGTH)

        if pdu[0] != UDSIsoServices.NegativeResponse:
            raise ValueError(
                f"Not a negative response: {hex(pdu[0])} != "
                f"{hex(UDSIsoServices.NegativeResponse)}"
            )

    def matches(self, request: UDSRequest) -> bool:
        return self.request_service_id == request.service_id

    def __str__(self) -> str:
        return str(self.response_code.name)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(response_code={self.response_code.name}, "
            f"request_service={service_repr(self.request_service_id)})"
        )


T_PositiveResponse = TypeVar("T_PositiveResponse", bound="PositiveResponse")


class PositiveResponse(
    UDSResponse, ABC, service_id=None, minimal_length=0, maximal_length=None
):
    @property
    def data(self) -> bytes:
        return self.pdu[1:]

    def __repr__(self) -> str:
        title = self.__class__.__name__
        relevant_attributes = {}

        for attr, value in self.__dict__.items():
            if not attr.startswith("_") and attr not in ["trigger_request"]:
                relevant_attributes[attr] = any_repr(value)

        attributes = ", ".join(
            f"{attr}={value}" for attr, value in relevant_attributes.items()
        )
        return f"{title}({attributes})"

    @classmethod
    def parse_static(
        cls: type[T_PositiveResponse], response_pdu: bytes
    ) -> NegativeResponse | T_PositiveResponse:
        if response_pdu[0] == 0x7F:
            negative_response = NegativeResponse.from_pdu(response_pdu)
            return negative_response

        response = cls.from_pdu(response_pdu)
        return response


class UDSService(ABC):
    SERVICE_ID: UDSIsoServices | None
    _SERVICES: dict[UDSIsoServices | None, type[UDSService]] = {}
    Response: type[PositiveResponse] | None = None
    Request: type[UDSRequest] | None = None

    @classmethod
    def _response_type(cls, pdu: bytes) -> type[PositiveResponse] | None:
        return cls.Response

    @classmethod
    def _request_type(cls, pdu: bytes) -> type[UDSRequest] | None:
        return cls.Request

    def __init_subclass__(
        cls, /, service_id: UDSIsoServices | None, **kwargs: Any
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls.SERVICE_ID = service_id
        UDSService._SERVICES[service_id] = cls


class SubFunction(ABC):
    SUB_FUNCTION_ID: int | None
    Response: type[PositiveResponse] | None
    Request: type[UDSRequest] | None

    def __init_subclass__(cls, /, sub_function_id: int | None, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)

        cls.SUB_FUNCTION_ID = sub_function_id


class SpecializedSubFunctionService(UDSService, ABC, service_id=None):
    @classmethod
    def _sub_function_type(cls, pdu: bytes) -> type[SubFunction]:
        sub_function_id = pdu[1] % 0x80

        sub_functions = [
            x
            for x in cls.__dict__.values()
            if inspect.isclass(x) and issubclass(x, SubFunction)
        ]

        for sub_function in sub_functions:
            if sub_function.SUB_FUNCTION_ID == sub_function_id:
                return sub_function

        raise ValueError(f"SubFunction not supported: {int_repr(sub_function_id)}")

    @classmethod
    def _response_type(cls, pdu: bytes) -> type[PositiveResponse] | None:
        return cls._sub_function_type(pdu).Response

    @classmethod
    def _request_type(cls, pdu: bytes) -> type[UDSRequest] | None:
        return cls._sub_function_type(pdu).Request


class SubFunctionResponse(
    PositiveResponse, ABC, service_id=None, minimal_length=2, maximal_length=None
):
    def __init__(self) -> None:
        super().__init__()

        check_sub_function(self.sub_function)

    @property
    @abstractmethod
    def sub_function(self) -> int:
        pass

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        super()._check_pdu(pdu)

        check_sub_function(pdu[1])


class SubFunctionRequest(
    UDSRequest,
    ABC,
    service_id=None,
    response_type=SubFunctionResponse,  # type: ignore
    minimal_length=2,
    maximal_length=None,
):
    def __init__(self, suppress_response: bool) -> None:
        check_sub_function(self.sub_function)

        self.suppress_response = suppress_response

    @property
    @abstractmethod
    def sub_function(self) -> int:
        pass

    @property
    def sub_function_with_suppress_response_bit(self) -> int:
        return int(self.suppress_response) * 0x80 + self.sub_function

    @staticmethod
    def suppress_response_set(pdu: bytes) -> bool:
        return pdu[1] >= 0x80


class SpecializedSubFunctionResponse(
    SubFunctionResponse, ABC, service_id=None, minimal_length=2, maximal_length=None
):
    SUB_FUNCTION_ID: int

    def __init_subclass__(
        cls, /, sub_function_id: int, **kwargs: Any  # pylint: disable=arguments-differ
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls.SUB_FUNCTION_ID = sub_function_id

    def __init__(self) -> None:
        super().__init__()

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        super()._check_pdu(pdu)

        if pdu[1] != cls.SUB_FUNCTION_ID:
            raise ValueError(
                f"Sub-function ID mismatch: {hex(pdu[1])} != "
                f"{hex(cls.SUB_FUNCTION_ID)}"
            )

    @property
    def sub_function(self) -> int:
        return self.SUB_FUNCTION_ID


class SpecializedSubFunctionRequest(
    SubFunctionRequest,
    ABC,
    service_id=None,
    response_type=SpecializedSubFunctionResponse,  # type: ignore
    minimal_length=2,
    maximal_length=None,
):
    SUB_FUNCTION_ID: int

    def __init_subclass__(
        cls, /, sub_function_id: int, **kwargs: Any  # pylint: disable=arguments-differ
    ) -> None:
        super().__init_subclass__(**kwargs)

        cls.SUB_FUNCTION_ID = sub_function_id

    def __init__(self, suppress_response: bool) -> None:
        super().__init__(suppress_response)

    @classmethod
    def _check_pdu(cls, pdu: bytes) -> None:
        super()._check_pdu(pdu)

        if pdu[1] % 0x80 != cls.SUB_FUNCTION_ID:
            raise ValueError(
                f"Sub-function ID mismatch: {hex(pdu[1])} != "
                f"{hex(cls.SUB_FUNCTION_ID)}"
            )

    @property
    def sub_function(self) -> int:
        return self.SUB_FUNCTION_ID


# ******************************
# * Raw requests and responses *
# ******************************


class RawPositiveResponse(
    RawResponse,
    PositiveResponse,
    service_id=None,
    minimal_length=1,
    maximal_length=None,
):
    @property
    def service_id(self) -> int:
        return self.pdu[0] - 0x40

    def matches(self, request: UDSRequest) -> bool:
        if self.service_id != request.service_id:
            return False

        # Use the old heuristic approach to detect as many mismatches as possible on responses which could not be parsed
        try:
            echo_length = UDSIsoServicesEchoLength[UDSIsoServices(self.service_id)]
            return request.pdu[1 : echo_length + 1] == self.pdu[1 : echo_length + 1]
        except Exception:
            pass

        return True


class RawRequest(
    UDSRequest,
    service_id=None,
    response_type=RawPositiveResponse,
    minimal_length=1,
    maximal_length=None,
):
    def __init__(self, pdu: bytes) -> None:
        """Raw request, which does not need to be compliant with the standard.
        It can be used to send arbitrary data packets.

        :param pdu: The data.
        """
        self._pdu = pdu

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> RawRequest:
        return RawRequest(pdu)

    @property
    def service_id(self) -> int:
        return self.pdu[0]

    @property
    def pdu(self) -> bytes:
        return self._pdu

    @pdu.setter
    def pdu(self, pdu: bytes) -> None:
        self._pdu = pdu

    def __repr__(self) -> str:
        return f"{type(self).__name__}(pdu={bytes_repr(self.pdu)})"


class Raw(UDSService, service_id=None):
    Response = RawPositiveResponse
    Request = RawRequest


# ******************************
# * Diagnostic session control *
# ******************************


class DiagnosticSessionControlResponse(
    SubFunctionResponse,
    service_id=UDSIsoServices.DiagnosticSessionControl,
    minimal_length=2,
    maximal_length=None,
):
    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.RESPONSE_SERVICE_ID, self.diagnostic_session_type)
            + self.session_parameter_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> DiagnosticSessionControlResponse:
        diagnostic_session_type = from_bytes(pdu[1:2])
        session_parameter_record = pdu[2:]
        return DiagnosticSessionControlResponse(
            diagnostic_session_type, session_parameter_record
        )

    def __init__(
        self, diagnostic_session_type: int, session_parameter_record: bytes = b""
    ) -> None:
        self.diagnostic_session_type = diagnostic_session_type
        self.session_parameter_record = session_parameter_record

        super().__init__()

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, DiagnosticSessionControlRequest)
            and request.diagnostic_session_type == self.diagnostic_session_type
        )

    @property
    def sub_function(self) -> int:
        return self.diagnostic_session_type


class DiagnosticSessionControlRequest(
    SubFunctionRequest,
    service_id=UDSIsoServices.DiagnosticSessionControl,
    response_type=DiagnosticSessionControlResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(
        self, diagnostic_session_type: int, suppress_response: bool = False
    ) -> None:
        """Sets the diagnostic session which is specified by a specific diagnosticSessionType
        sub-function.
        This is an implementation of the UDS request for service DiagnosticSessionControl (0x10).

        :param diagnostic_session_type: The session sub-function.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        self.diagnostic_session_type = diagnostic_session_type

        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> DiagnosticSessionControlRequest:
        return DiagnosticSessionControlRequest(*sub_function_split(pdu[1]))

    @property
    def sub_function(self) -> int:
        return self.diagnostic_session_type


class DiagnosticSessionControl(
    UDSService, service_id=UDSIsoServices.DiagnosticSessionControl
):
    Response = DiagnosticSessionControlResponse
    Request = DiagnosticSessionControlRequest


# *************
# * ECU reset *
# *************


class ECUResetResponse(
    SubFunctionResponse,
    service_id=UDSIsoServices.EcuReset,
    minimal_length=2,
    maximal_length=3,
):
    def __init__(self, reset_type: int, power_down_time: int | None = None) -> None:
        if power_down_time is not None:
            check_range(power_down_time, "powerDownTime", 0, 0xFF)

        self.reset_type = reset_type
        self.power_down_time = power_down_time

        super().__init__()

    @property
    def pdu(self) -> bytes:
        if self.power_down_time is None:
            return pack("!BB", self.RESPONSE_SERVICE_ID, self.reset_type)

        return pack(
            "!BBB", self.RESPONSE_SERVICE_ID, self.reset_type, self.power_down_time
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ECUResetResponse:
        reset_type = pdu[1]
        power_down_time = pdu[2] if len(pdu) > 2 else None

        return ECUResetResponse(reset_type, power_down_time)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, ECUResetRequest)
            and request.reset_type == self.reset_type
        )

    @property
    def sub_function(self) -> int:
        return self.reset_type


class ECUResetRequest(
    SubFunctionRequest,
    service_id=UDSIsoServices.EcuReset,
    response_type=ECUResetResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, reset_type: int, suppress_response: bool = False) -> None:
        """Resets the ECU using the specified reset type sub-function.
        This is an implementation of the UDS request for service ECUReset (0x11).

        :param reset_type: The reset type sub-function.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        self.reset_type = reset_type

        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ECUResetRequest:
        return ECUResetRequest(*sub_function_split(pdu[1]))

    @property
    def sub_function(self) -> int:
        return self.reset_type


class ECUReset(UDSService, service_id=UDSIsoServices.EcuReset):
    Response = ECUResetResponse
    Request = ECUResetRequest


# *******************
# * Security access *
# *******************


class SecurityAccessResponse(
    SubFunctionResponse,
    service_id=UDSIsoServices.SecurityAccess,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(self, security_access_type: int, security_seed: bytes = b"") -> None:
        self.security_access_type = security_access_type
        self.security_seed = security_seed

        super().__init__()

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.RESPONSE_SERVICE_ID, self.security_access_type)
            + self.security_seed
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> SecurityAccessResponse:
        security_access_type = from_bytes(pdu[1:2])
        security_seed = pdu[2:]
        return SecurityAccessResponse(security_access_type, security_seed)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, _SecurityAccessRequest)
            and request.security_access_type == self.security_access_type
        )

    @property
    def sub_function(self) -> int:
        return self.security_access_type


class _SecurityAccessRequest(
    SubFunctionRequest,
    ABC,
    service_id=UDSIsoServices.SecurityAccess,
    response_type=SecurityAccessResponse,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(
        self, security_access_type: int, suppress_response: bool = False
    ) -> None:
        self.security_access_type = security_access_type

        super().__init__(suppress_response)

    @property
    def sub_function(self) -> int:
        return self.security_access_type


class RequestSeedRequest(
    _SecurityAccessRequest,
    service_id=UDSIsoServices.SecurityAccess,
    response_type=SecurityAccessResponse,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(
        self,
        security_access_type: int,
        security_access_data_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        """Requests a seed for a security access level.
        This is an implementation of the UDS request for the requestSeed sub-function group
        of the service SecurityAccess (0x27).

        :param security_access_type: The securityAccess type sub-function.
        :param security_access_data_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(security_access_type, suppress_response)

        if security_access_type % 2 == 0:
            raise ValueError(
                f"RequestSeed requests must have an odd securityAccessType: "
                f"{hex(security_access_type)}"
            )

        self.security_access_data_record = security_access_data_record

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit)
            + self.security_access_data_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> RequestSeedRequest:
        security_access_type, suppress_response = sub_function_split(pdu[1])
        security_access_data_record = pdu[2:]
        return RequestSeedRequest(
            security_access_type, security_access_data_record, suppress_response
        )


class SendKeyRequest(
    _SecurityAccessRequest,
    service_id=UDSIsoServices.SecurityAccess,
    response_type=SecurityAccessResponse,
    minimal_length=3,
    maximal_length=None,
):
    def __init__(
        self,
        security_access_type: int,
        security_key: bytes,
        suppress_response: bool = False,
    ) -> None:
        """Sends the key for a security access level.
        This is an implementation of the UDS request for the sendKey sub-function group
        of the service SecurityAccess (0x27).

        :param security_access_type: The securityAccess type sub-function.
        :param security_key: The response to the seed challenge.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(security_access_type, suppress_response)

        if security_access_type % 2 == 1:
            raise ValueError(
                f"SendKey requests must have an even securityAccessType: "
                f"{hex(security_access_type)}"
            )

        self.security_key = security_key

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit)
            + self.security_key
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> SendKeyRequest:
        security_access_type, suppress_response = sub_function_split(pdu[1])
        security_key = pdu[2:]
        return SendKeyRequest(security_access_type, security_key, suppress_response)


class SecurityAccess(
    SpecializedSubFunctionService, service_id=UDSIsoServices.SecurityAccess
):
    class RequestSeed(SubFunction, sub_function_id=None):
        Response = SecurityAccessResponse
        Request = RequestSeedRequest

    class SendKey(SubFunction, sub_function_id=None):
        Response = SecurityAccessResponse
        Request = SendKeyRequest

    @classmethod
    def _sub_function_type(cls, pdu: bytes) -> type[SubFunction]:
        sub_function_id = pdu[1]
        return (
            SecurityAccess.RequestSeed
            if sub_function_id % 2 == 1
            else SecurityAccess.SendKey
        )


# *************************
# * Communication control *
# *************************


class CommunicationControlResponse(
    SubFunctionResponse,
    service_id=UDSIsoServices.CommunicationControl,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, control_type: int) -> None:
        self.control_type = control_type

        super().__init__()

    @property
    def pdu(self) -> bytes:
        return pack("!BB", self.RESPONSE_SERVICE_ID, self.control_type)

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> CommunicationControlResponse:
        control_type = pdu[1]
        return CommunicationControlResponse(control_type)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, CommunicationControlRequest)
            and request.control_type == self.control_type
        )

    @property
    def sub_function(self) -> int:
        return self.control_type


class CommunicationControlRequest(
    SubFunctionRequest,
    service_id=UDSIsoServices.CommunicationControl,
    response_type=CommunicationControlResponse,
    minimal_length=3,
    maximal_length=3,
):
    """Controls communication of the ECU.
    This is an implementation of the UDS request for service CommunicationControl (0x28).

    :param control_type: The control type sub-function.
    :param communication_type: The communication type.
    :param suppress_response: If set to True, the server is advised to not send back a positive
                              response.
    """

    def __init__(
        self,
        control_type: int,
        communication_type: int,
        suppress_response: bool = False,
    ) -> None:
        self.control_type = control_type
        self.communication_type = communication_type

        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BBB",
            self.SERVICE_ID,
            self.sub_function_with_suppress_response_bit,
            self.communication_type,
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> CommunicationControlRequest:
        control_type, suppress_response = sub_function_split(pdu[1])
        communication_type = pdu[2]

        return CommunicationControlRequest(
            control_type, communication_type, suppress_response
        )

    @property
    def sub_function(self) -> int:
        return self.control_type


class CommunicationControl(UDSService, service_id=UDSIsoServices.CommunicationControl):
    Response = CommunicationControlResponse
    Request = CommunicationControlRequest


# ******************
# * Tester present *
# ******************


class TesterPresentResponse(
    SpecializedSubFunctionResponse,
    service_id=UDSIsoServices.TesterPresent,
    sub_function_id=0,
    minimal_length=2,
    maximal_length=2,
):
    @property
    def pdu(self) -> bytes:
        return pack("!BB", self.RESPONSE_SERVICE_ID, self.SUB_FUNCTION_ID)

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> TesterPresentResponse:
        return TesterPresentResponse()

    def matches(self, request: UDSRequest) -> bool:
        return isinstance(request, TesterPresentRequest)


class TesterPresentRequest(
    SpecializedSubFunctionRequest,
    service_id=UDSIsoServices.TesterPresent,
    sub_function_id=0,
    response_type=TesterPresentResponse,
    minimal_length=2,
    maximal_length=2,
):
    """Signals to the ECU, that the tester is still present.
    This is an implementation of the UDS request for service TesterPresent (0x3E).

    :param suppress_response: If set to True, the server is advised to not send back a positive
                              response.
    """

    def __init__(self, suppress_response: bool = False) -> None:
        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> TesterPresentRequest:
        return TesterPresentRequest(cls.suppress_response_set(pdu))


class TesterPresent(UDSService, service_id=UDSIsoServices.TesterPresent):
    Response = TesterPresentResponse
    Request = TesterPresentRequest


# ******************
# * Authentication *
# ******************


# ***************************
# * Access timing parameter *
# ***************************


# *****************************
# * Secured data transmission *
# *****************************


# ***********************
# * Control DTC setting *
# ***********************


class ControlDTCSettingResponse(
    SubFunctionResponse,
    service_id=UDSIsoServices.ControlDTCSetting,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_setting_type: int) -> None:
        self.dtc_setting_type = dtc_setting_type

        super().__init__()

    @property
    def pdu(self) -> bytes:
        return pack("!BB", self.RESPONSE_SERVICE_ID, self.dtc_setting_type)

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ControlDTCSettingResponse:
        dtc_setting_type = pdu[1]
        return ControlDTCSettingResponse(dtc_setting_type)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, ControlDTCSettingRequest)
            and request.dtc_setting_type == self.dtc_setting_type
        )

    @property
    def sub_function(self) -> int:
        return self.dtc_setting_type


class ControlDTCSettingRequest(
    SubFunctionRequest,
    service_id=UDSIsoServices.ControlDTCSetting,
    response_type=ControlDTCSettingResponse,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(
        self,
        dtc_setting_type: int,
        dtc_setting_control_option_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        """Control the setting of DTCs.
        This is an implementation of the UDS request for service ControlDTCSetting (0x85).


        :param dtc_setting_type: The setting type.
        :param dtc_setting_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        self.dtc_setting_type = dtc_setting_type
        self.dtc_setting_control_option_record = dtc_setting_control_option_record

        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.SERVICE_ID, self.dtc_setting_type)
            + self.dtc_setting_control_option_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ControlDTCSettingRequest:
        dtc_setting_type, suppress_response = sub_function_split(pdu[1])
        dtc_setting_control_option_record = pdu[2:]

        return ControlDTCSettingRequest(
            dtc_setting_type, dtc_setting_control_option_record, suppress_response
        )

    @property
    def sub_function(self) -> int:
        return self.dtc_setting_type


class ControlDTCSetting(UDSService, service_id=UDSIsoServices.ControlDTCSetting):
    Response = ControlDTCSettingResponse
    Request = ControlDTCSettingRequest


# *********************
# * Response on event *
# *********************


# ****************
# * Link control *
# ****************


# ***************************
# * Read data by identifier *
# ***************************


class ReadDataByIdentifierResponse(
    PositiveResponse,
    service_id=UDSIsoServices.ReadDataByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        data_identifiers: int | Sequence[int],
        data_records: bytes | Sequence[bytes],
    ) -> None:
        super().__init__()

        if not isinstance(data_identifiers, int):
            self.data_identifiers = list(data_identifiers)
        else:
            self.data_identifiers = [data_identifiers]

        if not isinstance(data_records, bytes):
            self.data_records = list(data_records)
        else:
            self.data_records = [data_records]

        if len(self.data_identifiers) != len(self.data_records):
            raise ValueError(
                f"The number of data identifiers does not match the number of "
                f"data_records: "
                f"{len(self.data_identifiers)} != {len(self.data_records)}"
            )

        for identifier in self.data_identifiers:
            check_data_identifier(identifier)

    @property
    def data_record(self) -> bytes:
        return self.data_records[0]

    @data_record.setter
    def data_record(self, data_record: bytes) -> None:
        self.data_records[0] = data_record

    @property
    def data_identifier(self) -> int:
        return self.data_identifiers[0]

    @data_identifier.setter
    def data_identifier(self, data_identifier: int) -> None:
        self.data_identifiers[0] = data_identifier

    @property
    def pdu(self) -> bytes:
        pdu = pack("!B", self.RESPONSE_SERVICE_ID)

        for data_identifier, data_record in zip(
            self.data_identifiers, self.data_records
        ):
            pdu = pdu + to_bytes(data_identifier, 2) + data_record

        return pdu

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ReadDataByIdentifierResponse:
        # Without knowing the lengths of the dataRecords in a response with multiple dataIdentifiers
        # and dataRecords it's not possible to recover all ids.
        # Therefore, only the first identifier is used and the rest is simply attributed to the
        # first dataRecord
        data_identifier = from_bytes(pdu[1:3])
        data_record = pdu[3:]

        return ReadDataByIdentifierResponse(data_identifier, data_record)

    def matches(self, request: UDSRequest) -> bool:
        if not isinstance(request, ReadDataByIdentifierRequest):
            return False

        # Without knowing the lengths of the dataRecords in a response with multiple dataIdentifiers
        # and dataRecords it's not possible to recover all ids. This is respected here, where only
        # if this was possible,a complete check is done, while otherwise only the first id of the
        # request is taken into account.
        if len(self.data_identifiers) > 1:
            if len(request.data_identifiers) != len(self.data_identifiers):
                return False

            return all(
                req_id == resp_id
                for req_id, resp_id in zip(
                    request.data_identifiers, self.data_identifiers
                )
            )

        return request.data_identifiers[0] == self.data_identifiers[0]

    @property
    def _minimal_length(self) -> int:
        return 4


class ReadDataByIdentifierRequest(
    UDSRequest,
    service_id=UDSIsoServices.ReadDataByIdentifier,
    response_type=ReadDataByIdentifierResponse,
    minimal_length=3,
    maximal_length=None,
):
    def __init__(self, data_identifiers: int | Sequence[int]) -> None:
        """Reads data which is identified by a specific dataIdentifier.
        This is an implementation of the UDS request for service ReadDataByIdentifier (0x22).
        While this implementation supports requesting multiple dataIdentifiers at once, as is
        permitted in the standard, it is recommended to request them separately, because the support
        is optional on the server side.
        Additionally, it is not possible to reliably determine each single dataRecord from a
        corresponding response.

        :param data_identifiers: One or multiple dataIdentifiers. A dataIdentifier is a max two
                                 bytes integer.
        """

        if isinstance(data_identifiers, Sequence):
            self.data_identifiers = list(data_identifiers)
        else:
            self.data_identifiers = [data_identifiers]

        for identifier in self.data_identifiers:
            check_data_identifier(identifier)

    @property
    def data_identifier(self) -> int:
        return self.data_identifiers[0]

    @data_identifier.setter
    def data_identifier(self, data_identifier: int) -> None:
        self.data_identifiers[0] = data_identifier

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ReadDataByIdentifierRequest:
        identifiers: list[int] = []

        for i in range(1, len(pdu), 2):
            identifiers.append(from_bytes(pdu[i : i + 2]))

        return ReadDataByIdentifierRequest(identifiers)

    @property
    def pdu(self) -> bytes:
        return pack(
            f"!B{len(self.data_identifiers)}H",
            UDSIsoServices.ReadDataByIdentifier,
            *self.data_identifiers,
        )


class ReadDataByIdentifier(UDSService, service_id=UDSIsoServices.ReadDataByIdentifier):
    Response = ReadDataByIdentifierResponse
    Request = ReadDataByIdentifierRequest


# **************************
# * Read memory by address *
# **************************


class ReadMemoryByAddressResponse(
    PositiveResponse,
    service_id=UDSIsoServices.ReadMemoryByAddress,
    minimal_length=2,
    maximal_length=None,
):
    @property
    def pdu(self) -> bytes:
        return pack("!B", self.RESPONSE_SERVICE_ID) + self.data_record

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ReadMemoryByAddressResponse:
        data_record = pdu[1:]

        return ReadMemoryByAddressResponse(data_record)

    def __init__(self, data_record: bytes) -> None:
        super().__init__()

        self.data_record = data_record

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, ReadMemoryByAddressRequest)
            and len(self.data_record) == request.memory_size
        )


class ReadMemoryByAddressRequest(
    UDSRequest,
    service_id=UDSIsoServices.ReadMemoryByAddress,
    response_type=ReadMemoryByAddressResponse,
    minimal_length=4,
    maximal_length=32,
):
    def __init__(
        self,
        memory_address: int,
        memory_size: int,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        """Reads data from a specific memory address on the UDS server.
        This is an implementation of the UDS request for service ReadMemoryByAddress (0x3d).
        While it exposes each parameter of the corresponding specification,
        some parameters can be computed from the remaining ones and can therefore be omitted.

        :param memory_address: The start address.
        :param memory_size: The number of bytes to read.
        :param address_and_length_format_identifier: The byte lengths of the memory address and size.
                                                     If omitted, this parameter is computed based on
                                                     the memory_address and memory_size parameters.
        """

        self.memory_address = memory_address
        self.memory_size = memory_size

        if address_and_length_format_identifier is None:
            address_and_length_format_identifier, _, _ = uds_memory_parameters(
                memory_address, memory_size, address_and_length_format_identifier
            )

        self.address_and_length_format_identifier = address_and_length_format_identifier

    @property
    def pdu(self) -> bytes:
        _, address_bytes, size_bytes = uds_memory_parameters(
            self.memory_address,
            self.memory_size,
            self.address_and_length_format_identifier,
        )

        pdu = pack("!BB", self.SERVICE_ID, self.address_and_length_format_identifier)
        pdu += address_bytes + size_bytes
        return pdu

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ReadMemoryByAddressRequest:
        address_and_length_format_identifier = pdu[1]
        address_length, size_length = address_and_size_length(
            address_and_length_format_identifier
        )

        if len(pdu) != 2 + address_length + size_length:
            raise ValueError(
                "The addressAndLengthIdentifier is incompatible with the PDU size"
            )

        return ReadMemoryByAddressRequest(
            from_bytes(pdu[2 : 2 + address_length]),
            from_bytes(pdu[2 + address_length : 2 + address_length + size_length]),
            address_and_length_format_identifier,
        )


class ReadMemoryByAddress(UDSService, service_id=UDSIsoServices.ReadMemoryByAddress):
    Request = ReadMemoryByAddressRequest
    Response = ReadMemoryByAddressResponse


# ***********************************
# * Read scaling data by identifier *
# ***********************************


# ************************************
# * Read data by periodic identifier *
# ************************************


# **************************************
# * Dynamically define data identifier *
# **************************************


# ******************************
# * Write memory by identifier *
# ******************************


class WriteDataByIdentifierResponse(
    PositiveResponse,
    minimal_length=3,
    maximal_length=3,
    service_id=UDSIsoServices.WriteDataByIdentifier,
):
    def __init__(self, data_identifier: int) -> None:
        super().__init__()

        check_data_identifier(data_identifier)

        self.data_identifier = data_identifier

    @property
    def pdu(self) -> bytes:
        return pack("!BH", self.RESPONSE_SERVICE_ID, self.data_identifier)

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> WriteDataByIdentifierResponse:
        data_identifier = from_bytes(pdu[1:3])
        return WriteDataByIdentifierResponse(data_identifier)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, WriteDataByIdentifierRequest)
            and request.data_identifier == self.data_identifier
        )


class WriteDataByIdentifierRequest(
    UDSRequest,
    service_id=UDSIsoServices.WriteDataByIdentifier,
    response_type=WriteDataByIdentifierResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, data_record: bytes) -> None:
        """Writes data which is identified by a specific dataIdentifier.
        This is an implementation of the UDS request for service WriteDataByIdentifier (0x2E).

        :param data_identifier: The identifier. A dataIdentifier is a max two bytes integer.
        :param data_record: The data to be written.
        """
        check_data_identifier(data_identifier)

        if len(data_record) < 1:
            raise ValueError("The dataRecord must not be empty")

        self.data_identifier = data_identifier
        self.data_record = data_record

    @property
    def pdu(self) -> bytes:
        return pack("!BH", self.SERVICE_ID, self.data_identifier) + self.data_record

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> WriteDataByIdentifierRequest:
        data_identifier = from_bytes(pdu[1:3])
        data_record = pdu[3:]
        return WriteDataByIdentifierRequest(data_identifier, data_record)


class WriteDataByIdentifier(
    UDSService, service_id=UDSIsoServices.WriteDataByIdentifier
):
    Response = WriteDataByIdentifierResponse
    Request = WriteDataByIdentifierRequest


# ***************************
# * Write memory by address *
# ***************************


class WriteMemoryByAddressResponse(
    PositiveResponse,
    service_id=UDSIsoServices.WriteMemoryByAddress,
    minimal_length=4,
    maximal_length=32,
):
    @property
    def pdu(self) -> bytes:
        _, address_bytes, size_bytes = uds_memory_parameters(
            self.memory_address,
            self.memory_size,
            self.address_and_length_format_identifier,
        )

        pdu = pack(
            "!BB", self.RESPONSE_SERVICE_ID, self.address_and_length_format_identifier
        )
        pdu += address_bytes + size_bytes
        return pdu

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> WriteMemoryByAddressResponse:
        address_and_length_format_identifier = pdu[1]
        addr_len, size_len = address_and_size_length(
            address_and_length_format_identifier
        )

        if len(pdu) < 2 + addr_len + size_len:
            raise ValueError(
                "The PDU is smaller as specified by the addressAndLengthFormatIdentifier"
            )

        memory_address = from_bytes(pdu[2 : 2 + addr_len])
        memory_size = from_bytes(pdu[2 + addr_len : 2 + addr_len + size_len])

        return WriteMemoryByAddressResponse(
            memory_address, memory_size, address_and_length_format_identifier
        )

    def __init__(
        self,
        memory_address: int,
        memory_size: int,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        super().__init__()

        self.memory_address = memory_address
        self.memory_size = memory_size

        if address_and_length_format_identifier is None:
            address_and_length_format_identifier, _, _ = uds_memory_parameters(
                memory_address, memory_size, address_and_length_format_identifier
            )

        self.address_and_length_format_identifier = address_and_length_format_identifier

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, WriteMemoryByAddressRequest)
            and self.address_and_length_format_identifier
            == request.address_and_length_format_identifier
            and self.memory_address == request.memory_address
            and self.memory_size == request.memory_size
        )


class WriteMemoryByAddressRequest(
    UDSRequest,
    service_id=UDSIsoServices.WriteMemoryByAddress,
    response_type=WriteMemoryByAddressResponse,
    minimal_length=5,
    maximal_length=None,
):
    def __init__(
        self,
        memory_address: int,
        data_record: bytes,
        memory_size: int | None = None,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        """Writes data to a specific memory on the UDS server.
        This is an implementation of the UDS request for service writeMemoryByAddress (0x3d).
        While it exposes each parameter of the corresponding specification,
        some parameters can be computed from the remaining ones and can therefore be omitted.

        :param memory_address: The start address.
        :param data_record: The data to be written.
        :param memory_size: The number of bytes to write.
                            If omitted, the byte length of the data is used.
        :param address_and_length_format_identifier: The byte lengths of the memory address and
                                                     size. If omitted, this parameter is computed
                                                     based on the memory_address and memory_size
                                                     or data_record parameters.
        """

        self.memory_address = memory_address
        self.data_record = data_record

        # If the size is given explicitly, use it as is, otherwise take the size of the data
        if memory_size is None:
            memory_size = len(data_record)

        self.memory_size = memory_size

        if address_and_length_format_identifier is None:
            address_and_length_format_identifier, _, _ = uds_memory_parameters(
                memory_address, memory_size, address_and_length_format_identifier
            )

        self.address_and_length_format_identifier = address_and_length_format_identifier

    @property
    def pdu(self) -> bytes:
        _, address_bytes, size_bytes = uds_memory_parameters(
            self.memory_address,
            self.memory_size,
            self.address_and_length_format_identifier,
        )

        pdu = pack("!BB", self.SERVICE_ID, self.address_and_length_format_identifier)
        pdu += address_bytes + size_bytes + self.data_record
        return pdu

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> WriteMemoryByAddressRequest:
        address_and_length_format_identifier = pdu[1]
        address_length, size_length = address_and_size_length(
            address_and_length_format_identifier
        )

        if len(pdu) < 2 + address_length + size_length:
            raise ValueError(
                "The addressAndLengthIdentifier is incompatible with the PDU size"
            )

        return WriteMemoryByAddressRequest(
            from_bytes(pdu[2 : 2 + address_length]),
            pdu[2 + address_length + size_length :],
            from_bytes(pdu[2 + address_length : 2 + address_length + size_length]),
            address_and_length_format_identifier,
        )


class WriteMemoryByAddress(UDSService, service_id=UDSIsoServices.WriteMemoryByAddress):
    Request = WriteMemoryByAddressRequest
    Response = WriteMemoryByAddressResponse


# ********************************
# * Clear diagnostic information *
# ********************************


class ClearDiagnosticInformationResponse(
    PositiveResponse,
    minimal_length=1,
    maximal_length=1,
    service_id=UDSIsoServices.ClearDiagnosticInformation,
):
    @property
    def pdu(self) -> bytes:
        assert self.RESPONSE_SERVICE_ID is not None
        return bytes([self.RESPONSE_SERVICE_ID])

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ClearDiagnosticInformationResponse:
        return ClearDiagnosticInformationResponse()

    def matches(self, request: UDSRequest) -> bool:
        return isinstance(request, ClearDiagnosticInformationRequest)


class ClearDiagnosticInformationRequest(
    UDSRequest,
    minimal_length=4,
    maximal_length=4,
    service_id=UDSIsoServices.ClearDiagnosticInformation,
    response_type=ClearDiagnosticInformationResponse,
):
    def __init__(self, group_of_dtc: int) -> None:
        """Clears diagnostic trouble codes according to a given mask.
        This is an implementation of the UDS request for service clearDiagnosticInformation (0x14).

        :param group_of_dtc: The three byte mask, which determines the DTCs to be cleared.
        """
        check_range(group_of_dtc, "groupOfDTC", 0, 0xFFFFFF)

        self.group_of_dtc = group_of_dtc

    @property
    def pdu(self) -> bytes:
        assert self.SERVICE_ID is not None
        return bytes([self.SERVICE_ID]) + to_bytes(self.group_of_dtc, 3)

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ClearDiagnosticInformationRequest:
        group_of_dtc = from_bytes(pdu[1:])
        return ClearDiagnosticInformationRequest(group_of_dtc)


class ClearDiagnosticInformation(
    UDSService, service_id=UDSIsoServices.ClearDiagnosticInformation
):
    Response = ClearDiagnosticInformationResponse
    Request = ClearDiagnosticInformationRequest


# ************************
# * Read DTC information *
# ************************


class _ReadDTCResponse(
    SpecializedSubFunctionResponse,
    ABC,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=None,
    maximal_length=None,
):
    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, _ReadDTCRequest)
            and self.sub_function == request.sub_function
        )


class _ReadDTCRequest(
    SpecializedSubFunctionRequest,
    ABC,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=None,
    maximal_length=None,
    response_type=_ReadDTCResponse,
):
    pass


T_ReadDTCType0Response = TypeVar(
    "T_ReadDTCType0Response", bound="_ReadDTCType0Response"
)


class _ReadDTCType0Response(
    _ReadDTCResponse,
    ABC,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=6,
    maximal_length=6,
):
    def __init__(
        self,
        dtc_status_availability_mask: int,
        dtc_format_identifier: DTCFormatIdentifier,
        dtc_count: int,
    ) -> None:
        super().__init__()

        check_range(dtc_status_availability_mask, "DTCStatusAvailabilityMask", 0, 0xFF)
        check_range(dtc_count, "DTCCount", 0, 0xFFFF)

        self.dtc_status_availability_mask = dtc_status_availability_mask
        self.dtc_format_identifier = dtc_format_identifier
        self.dtc_count = dtc_count

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BBBBH",
            self.RESPONSE_SERVICE_ID,
            self.sub_function,
            self.dtc_status_availability_mask,
            self.dtc_format_identifier,
            self.dtc_count,
        )

    @classmethod
    def _from_pdu(
        cls: type[T_ReadDTCType0Response], pdu: bytes
    ) -> T_ReadDTCType0Response:
        dtc_status_availability_mask = pdu[2]
        dtc_format_identifier = DTCFormatIdentifier(pdu[3])
        dtc_count = from_bytes(pdu[4:])
        return cls(dtc_status_availability_mask, dtc_format_identifier, dtc_count)


T_ReadDTCType1Response = TypeVar(
    "T_ReadDTCType1Response", bound="_ReadDTCType1Response"
)


class _ReadDTCType1Response(
    _ReadDTCResponse,
    ABC,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=3,
    maximal_length=None,
):
    def __init__(
        self,
        dtc_status_availability_mask: int,
        dtc_and_status_record: bytes | dict[int, int],
    ) -> None:
        super().__init__()

        check_range(dtc_status_availability_mask, "DTCStatusAvailabilityMask", 0, 0xFF)

        if isinstance(dtc_and_status_record, bytes):
            if len(dtc_and_status_record) % 4 != 0:
                raise ValueError("Not a valid dtc_and_status_record")

            self.dtc_and_status_record = {
                from_bytes(dtc_and_status_record[i : i + 3]): dtc_and_status_record[
                    i + 3
                ]
                for i in range(0, len(dtc_and_status_record), 4)
            }
        else:
            for dtc, status in dtc_and_status_record.items():
                check_range(dtc, "DTC", 0, 0xFFFFFF)
                check_range(status, "DTC Status", 0, 0xFF)

            self.dtc_and_status_record = dtc_and_status_record

        self.dtc_status_availability_mask = dtc_status_availability_mask

    def dtc_and_status_record_bytes(self) -> bytes:
        return bytes(
            bytearray().join(
                bytearray(to_bytes(dtc, 3)) + to_bytes(status, 1)
                for dtc, status in self.dtc_and_status_record.items()
            )
        )

    @property
    def pdu(self) -> bytes:
        return (
            pack(
                "!BBB",
                self.RESPONSE_SERVICE_ID,
                self.sub_function,
                self.dtc_status_availability_mask,
            )
            + self.dtc_and_status_record_bytes()
        )

    @classmethod
    def _from_pdu(
        cls: type[T_ReadDTCType1Response], pdu: bytes
    ) -> T_ReadDTCType1Response:
        dtc_status_availability_mask = pdu[2]
        dtc_and_status_record = pdu[3:]
        return cls(dtc_status_availability_mask, dtc_and_status_record)


T_ReadDTCType0Request = TypeVar("T_ReadDTCType0Request", bound="_ReadDTCType0Request")


class _ReadDTCType0Request(
    _ReadDTCRequest,
    ABC,
    response_type=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        super().__init__(suppress_response)

        check_range(dtc_status_mask, "DTCStatusMask", 0, 0xFF)

        self.dtc_status_mask = dtc_status_mask

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BBB",
            self.SERVICE_ID,
            self.sub_function_with_suppress_response_bit,
            self.dtc_status_mask,
        )

    @classmethod
    def _from_pdu(
        cls: type[T_ReadDTCType0Request], pdu: bytes
    ) -> T_ReadDTCType0Request:
        dtc_status_mask = pdu[2]
        return cls(dtc_status_mask, cls.suppress_response_set(pdu))


T_ReadDTCType6Request = TypeVar("T_ReadDTCType6Request", bound="_ReadDTCType6Request")


class _ReadDTCType6Request(
    _ReadDTCRequest,
    ABC,
    response_type=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=0,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, suppress_response: bool = False) -> None:
        super().__init__(suppress_response)

    @property
    def pdu(self) -> bytes:
        return pack(
            "!BBB", self.SERVICE_ID, self.sub_function_with_suppress_response_bit
        )

    @classmethod
    def _from_pdu(
        cls: type[T_ReadDTCType6Request], pdu: bytes
    ) -> T_ReadDTCType6Request:
        return cls(cls.suppress_response_set(pdu))


class ReportNumberOfDTCByStatusMaskResponse(
    _ReadDTCType0Response,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNODTCBSM,
    minimal_length=6,
    maximal_length=6,
):
    pass


class ReportNumberOfDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    minimal_length=3,
    maximal_length=3,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNODTCBSM,
    response_type=ReportNumberOfDTCByStatusMaskResponse,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the number of DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the reportNumberOfDTCByStatusMask
        sub-function of the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportDTCByStatusMaskResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RDTCBSM,
):
    pass


class ReportDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    minimal_length=3,
    maximal_length=3,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RDTCBSM,
    response_type=ReportDTCByStatusMaskResponse,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read DTCs and their state from the UDS server.
        This is an implementation of the UDS request for the reportDTCByStatusMask sub-function of
        the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportMirrorMemoryDTCByStatusMaskResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMMDTCBSM,
):
    pass


class ReportMirrorMemoryDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMMDTCBSM,
    response_type=ReportMirrorMemoryDTCByStatusMaskResponse,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read DTCs and their state from the UDS server's mirror memory.
        This is an implementation of the UDS request for the reportMirrorMemoryDTCByStatusMask
        sub-function of the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportNumberOfMirrorMemoryDTCByStatusMaskResponse(
    _ReadDTCType0Response,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNOMMDTCBSM,
    minimal_length=6,
    maximal_length=6,
):
    pass


class ReportNumberOfMirrorMemoryDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNOMMDTCBSM,
    response_type=ReportNumberOfMirrorMemoryDTCByStatusMaskResponse,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the number of DTCs with the specified state from the UDS server's mirror memory.
        This is an implementation of the UDS request for the
        reportNumberOfMirrorMemoryDTCByStatusMask sub-function of the service ReadDTCInformation
        (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskResponse(
    _ReadDTCType0Response,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNOOBDDTCBSM,
    minimal_length=6,
    maximal_length=6,
):
    pass


class ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RNOOBDDTCBSM,
    response_type=ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskResponse,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the number of emission related DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the
        reportNumberOfEmissionsRelatedOBDDTCByStatusMask sub-function of the service
        ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportEmissionsRelatedOBDDTCByStatusMaskResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.ROBDDTCBSM,
):
    pass


class ReportEmissionsRelatedOBDDTCByStatusMaskRequest(
    _ReadDTCType0Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.ROBDDTCBSM,
    response_type=ReportEmissionsRelatedOBDDTCByStatusMaskResponse,
    minimal_length=3,
    maximal_length=3,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the number of emission related DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the
        reportEmissionsRelatedOBDDTCByStatusMask sub-function of the service ReadDTCInformation
        (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(dtc_status_mask, suppress_response)


class ReportSupportedDTCResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RSUPDTC,
):
    pass


class ReportSupportedDTCRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RSUPDTC,
    response_type=ReportSupportedDTCResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the supported DTCs from the UDS server.
        This is an implementation of the UDS request for the
        reportSupportedDTC sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReportFirstTestFailedDTCResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=7,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RFTFDTC,
):
    pass


class ReportFirstTestFailedDTCRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RFTFDTC,
    response_type=ReportFirstTestFailedDTCResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the first failed DTC since last clearance from the UDS server.
        This is an implementation of the UDS request for the
        reportFirstTestFailedDTC sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReportFirstConfirmedDTCResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=7,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RFCDTC,
):
    pass


class ReportFirstConfirmedDTCRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RFCDTC,
    response_type=ReportFirstConfirmedDTCResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the first confirmed DTC since last clearance from the UDS server.
        This is an implementation of the UDS request for the
        reportFirstConfirmedDTC sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReportMostRecentTestFailedDTCResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=7,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMRTFDTC,
):
    pass


class ReportMostRecentFirstTestFailedDTCRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMRTFDTC,
    response_type=ReportMostRecentTestFailedDTCResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the most recent failed DTC since last clearance from the UDS server.
        This is an implementation of the UDS request for the
        reportMostRecentTestFailedDTC sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReportMostrecentConfirmedDTCResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=7,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMRCDTC,
):
    pass


class ReportMostRecentConfirmedDTCRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RMRCDTC,
    response_type=ReportMostrecentConfirmedDTCResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the most recent confirmed DTC since last clearance from the UDS server.
        This is an implementation of the UDS request for the
        reportMostRecentConfirmedDTC sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReportDTCWithPermanentStatusResponse(
    _ReadDTCType1Response,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RDTCWPS,
):
    pass


class ReportDTCWithPermanentStatusRequest(
    _ReadDTCType6Request,
    service_id=UDSIsoServices.ReadDTCInformation,
    sub_function_id=RDTCISubFuncs.RDTCWPS,
    response_type=ReportDTCWithPermanentStatusResponse,
    minimal_length=2,
    maximal_length=2,
):
    def __init__(self, dtc_status_mask: int, suppress_response: bool = False) -> None:
        """Read the DTCs with permanent status from the UDS server.
        This is an implementation of the UDS request for the
        reportDTCWithPermanentStatus sub-function of the service ReadDTCInformation (0x19).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(suppress_response)


class ReadDTCInformation(
    SpecializedSubFunctionService, service_id=UDSIsoServices.ReadDTCInformation
):
    class ReportNumberOfDTCByStatusMask(
        SubFunction, sub_function_id=RDTCISubFuncs.RNODTCBSM
    ):
        Response = ReportNumberOfDTCByStatusMaskResponse
        Request = ReportNumberOfDTCByStatusMaskRequest

    class ReportDTCByStatusMask(SubFunction, sub_function_id=RDTCISubFuncs.RDTCBSM):
        Response = ReportDTCByStatusMaskResponse
        Request = ReportDTCByStatusMaskRequest

    class ReportMirrorMemoryDTCByStatusMask(
        SubFunction, sub_function_id=RDTCISubFuncs.RMMDTCBSM
    ):
        Response = ReportMirrorMemoryDTCByStatusMaskResponse
        Request = ReportMirrorMemoryDTCByStatusMaskRequest

    class ReportNumberOfMirrorMemoryDTCByStatusMask(
        SubFunction, sub_function_id=RDTCISubFuncs.RNOMMDTCBSM
    ):
        Response = ReportNumberOfMirrorMemoryDTCByStatusMaskResponse
        Request = ReportNumberOfMirrorMemoryDTCByStatusMaskRequest

    class ReportNumberOfEmissionsRelatedOBDDTCByStatusMask(
        SubFunction, sub_function_id=RDTCISubFuncs.RNOOBDDTCBSM
    ):
        Response = ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskResponse
        Request = ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskRequest

    class ReportEmissionsRelatedOBDDTCByStatusMask(
        SubFunction, sub_function_id=RDTCISubFuncs.ROBDDTCBSM
    ):
        Response = ReportEmissionsRelatedOBDDTCByStatusMaskResponse
        Request = ReportEmissionsRelatedOBDDTCByStatusMaskRequest

    class ReportSupportedDTC(SubFunction, sub_function_id=RDTCISubFuncs.RSUPDTC):
        Response = ReportSupportedDTCResponse
        Request = ReportSupportedDTCRequest

    class ReportFirstTestFailedDTC(SubFunction, sub_function_id=RDTCISubFuncs.RFTFDTC):
        Response = ReportFirstTestFailedDTCResponse
        Request = ReportFirstTestFailedDTCRequest

    class ReportFirstConfirmedDTC(SubFunction, sub_function_id=RDTCISubFuncs.RFCDTC):
        Response = ReportFirstConfirmedDTCResponse
        Request = ReportFirstConfirmedDTCRequest

    class ReportMostRecentTestFailedDTC(
        SubFunction, sub_function_id=RDTCISubFuncs.RMRTFDTC
    ):
        Response = ReportMostRecentTestFailedDTCResponse
        Request = ReportMostRecentFirstTestFailedDTCRequest

    class ReportMostRecentConfirmedDTC(
        SubFunction, sub_function_id=RDTCISubFuncs.RMRCDTC
    ):
        Response = ReportMostrecentConfirmedDTCResponse
        Request = ReportMostRecentConfirmedDTCRequest

    class ReportDTCWithPermanentStatus(
        SubFunction, sub_function_id=RDTCISubFuncs.RDTCWPS
    ):
        Response = ReportDTCWithPermanentStatusResponse
        Request = ReportDTCWithPermanentStatusRequest


# **************************************
# * Input output control by identifier *
# **************************************


class InputOutputControlByIdentifierResponse(
    PositiveResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, control_status_record: bytes) -> None:
        super().__init__()

        check_data_identifier(data_identifier)

        if len(control_status_record) < 1:
            raise ValueError("The controlStatusRecord must not be empty")

        self.data_identifier = data_identifier
        self.control_status_record = control_status_record

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BH", self.RESPONSE_SERVICE_ID, self.data_identifier)
            + self.control_status_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> InputOutputControlByIdentifierResponse:
        data_identifier = from_bytes(pdu[1:3])
        control_status_record = pdu[3:]
        return InputOutputControlByIdentifierResponse(
            data_identifier, control_status_record
        )

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, InputOutputControlByIdentifierRequest)
            and self.data_identifier == request.data_identifier
        )


class InputOutputControlByIdentifierRequest(
    UDSRequest,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    response_type=InputOutputControlByIdentifierResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        data_identifier: int,
        control_option_record: bytes,
        control_enable_mask_record: bytes = b"",
    ) -> None:
        """Controls input or output values on the server.
        This is an implementation of the UDS request for the service
        InputOutputControlByIdentifier (0x2F).
        This function exposes the parameters as in the corresponding specification,
        hence is suitable for all variants of this service.
        For the variants which use an inputOutputControlParameter as the first byte of the
        controlOptionRecord, using the corresponding wrappers is recommended.

        :param data_identifier: The data identifier of the value(s) to be controlled.
        :param control_option_record: The controlStates, which specify the intended values of the
                                      input / output parameters, optionally prefixed with an
                                      inputOutputControlParameter or only an
                                      inputOutputControlParameter.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        """
        check_data_identifier(data_identifier)

        if len(control_option_record) < 1:
            raise ValueError("The controlOptionRecord must not be empty")

        self.data_identifier = data_identifier
        self.control_option_record = control_option_record
        self.control_enable_mask_record = control_enable_mask_record

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BH", self.SERVICE_ID, self.data_identifier)
            + self.control_option_record
            + self.control_enable_mask_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> InputOutputControlByIdentifierRequest:
        # Because both the controlOptionRecord as well as the controlEnableMaskRecord are of
        # variable size, and there is no field which describes those parameters,
        # it is impossible for the server to determine those fields reliably without vendor or ECU
        # specific knowledge.
        # Therefore, similar to the implementation for ReadDataByIdentifier,
        # the first variable parameter consumes all remaining data.
        data_identifier = from_bytes(pdu[1:3])
        control_option_record = pdu[3:]
        control_enable_mask_record = b""
        return InputOutputControlByIdentifierRequest(
            data_identifier, control_option_record, control_enable_mask_record
        )


class ReturnControlToECUResponse(
    InputOutputControlByIdentifierResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, control_states: bytes = b"") -> None:
        super().__init__(
            data_identifier,
            bytes([InputOutputControlParameter.RCTECU]) + control_states,
        )

    def matches(self, request: UDSRequest) -> bool:
        return super().matches(request) and isinstance(
            request, ReturnControlToECURequest
        )


class ReturnControlToECURequest(
    InputOutputControlByIdentifierRequest,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    response_type=ReturnControlToECUResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self, data_identifier: int, control_enable_mask_record: bytes = b""
    ) -> None:
        """Gives the control over input / output parameters back to the ECU.
        This is a convenience wrapper of the generic request for the case where an
        inputOutputControlParameter is used and is set to returnControlToECU. In that case no
        further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) for which control should be
                                returned to the ECU.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        """
        super().__init__(
            data_identifier,
            bytes([InputOutputControlParameter.RCTECU]),
            control_enable_mask_record,
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ReturnControlToECURequest:
        data_identifier = from_bytes(pdu[1:3])
        control_enable_mask_record = pdu[4:]
        return ReturnControlToECURequest(data_identifier, control_enable_mask_record)


class ResetToDefaultResponse(
    InputOutputControlByIdentifierResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, control_states: bytes = b"") -> None:
        super().__init__(
            data_identifier, bytes([InputOutputControlParameter.RTD]) + control_states
        )

    def matches(self, request: UDSRequest) -> bool:
        return super().matches(request) and isinstance(request, ResetToDefaultRequest)


class ResetToDefaultRequest(
    InputOutputControlByIdentifierRequest,
    response_type=ResetToDefaultResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self, data_identifier: int, control_enable_mask_record: bytes = b""
    ) -> None:
        """Sets the input / output parameters to the default value(s).
        This is a convenience wrapper of the generic request for the case where an
        inputOutputControlParameter is used and is set to resetToDefault.
        In that case no further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) for which the values should be
                                reset.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        """
        super().__init__(
            data_identifier,
            bytes([InputOutputControlParameter.RTD]),
            control_enable_mask_record,
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> ResetToDefaultRequest:
        data_identifier = from_bytes(pdu[1:3])
        control_enable_mask_record = pdu[4:]
        return ResetToDefaultRequest(data_identifier, control_enable_mask_record)


class FreezeCurrentStateResponse(
    InputOutputControlByIdentifierResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, control_states: bytes = b"") -> None:
        super().__init__(
            data_identifier, bytes([InputOutputControlParameter.FCS]) + control_states
        )

    def matches(self, request: UDSRequest) -> bool:
        return super().matches(request) and isinstance(
            request, FreezeCurrentStateResponse
        )


class FreezeCurrentStateRequest(
    InputOutputControlByIdentifierRequest,
    response_type=FreezeCurrentStateResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self, data_identifier: int, control_enable_mask_record: bytes = b""
    ) -> None:
        """Freezes the input / output parameters at their current state.
        This is a convenience wrapper of the generic request for the case where an
        inputOutputControlParameter is used and is set to freezeCurrentState.
        In that case no further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) to be frozen.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        """
        super().__init__(
            data_identifier,
            bytes([InputOutputControlParameter.FCS]),
            control_enable_mask_record,
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> FreezeCurrentStateRequest:
        data_identifier = from_bytes(pdu[1:3])
        control_enable_mask_record = pdu[4:]
        return FreezeCurrentStateRequest(data_identifier, control_enable_mask_record)


class ShortTermAdjustmentResponse(
    InputOutputControlByIdentifierResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(self, data_identifier: int, control_states: bytes = b"") -> None:
        super().__init__(
            data_identifier, bytes([InputOutputControlParameter.STA]) + control_states
        )


class ShortTermAdjustmentRequest(
    InputOutputControlByIdentifierRequest,
    response_type=ShortTermAdjustmentResponse,
    service_id=UDSIsoServices.InputOutputControlByIdentifier,
    minimal_length=5,
    maximal_length=None,
):
    def __init__(
        self,
        data_identifier: int,
        control_states: bytes,
        control_enable_mask_record: bytes = b"",
    ) -> None:
        """Sets the input / output parameters as specified in the controlOptionRecord.
        This is a convenience wrapper of the generic request for the case
        where an inputOutputControlParameter is used and is set to freezeCurrentState.
        In that case controlState parameters are required.

        :param data_identifier: The data identifier of the value(s) to be adjusted.
        :param control_states: The controlStates, which specify the intended values of the input /
                               output parameters.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        """
        control_option_record = (
            bytes([InputOutputControlParameter.STA]) + control_states
        )
        super().__init__(
            data_identifier, control_option_record, control_enable_mask_record
        )


class InputOutputControlByIdentifier(
    UDSService, service_id=UDSIsoServices.InputOutputControlByIdentifier
):
    Response = InputOutputControlByIdentifierResponse
    Request = InputOutputControlByIdentifierRequest

    class ReturnControlToECU:
        Response = ReturnControlToECUResponse
        Request = ReturnControlToECURequest

    class ResetToDefault:
        Response = ResetToDefaultResponse
        Request = ResetToDefaultRequest

    class FreezeCurrentState:
        Response = FreezeCurrentStateResponse
        Request = FreezeCurrentStateRequest

    class ShortTermAdjustment:
        Response = ShortTermAdjustmentResponse
        Request = ShortTermAdjustmentRequest


# *******************
# * Routine control *
# *******************


T_RoutineControlResponse = TypeVar(
    "T_RoutineControlResponse", bound="RoutineControlResponse"
)


class RoutineControlResponse(
    SpecializedSubFunctionResponse,
    ABC,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=0,
    minimal_length=4,
    maximal_length=None,
):
    @property
    def pdu(self) -> bytes:
        return (
            pack(
                "!BBH",
                self.RESPONSE_SERVICE_ID,
                self.sub_function,
                self.routine_identifier,
            )
            + self.routine_status_record
        )

    @classmethod
    def _from_pdu(
        cls: type[T_RoutineControlResponse], pdu: bytes
    ) -> T_RoutineControlResponse:
        routine_identifier = from_bytes(pdu[2:4])
        routine_status_record = pdu[4:]

        return cls(routine_identifier, routine_status_record)

    def __init__(
        self, routine_identifier: int, routine_status_record: bytes = b""
    ) -> None:
        super().__init__()

        self.routine_control_type = self.sub_function
        self.routine_identifier = routine_identifier
        self.routine_status_record = routine_status_record

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, RoutineControlRequest)
            and self.routine_control_type == request.routine_control_type
            and self.routine_identifier == request.routine_identifier
        )


T_RoutineControlRequest = TypeVar(
    "T_RoutineControlRequest", bound="RoutineControlRequest"
)


class RoutineControlRequest(
    SpecializedSubFunctionRequest,
    ABC,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=0,
    response_type=RoutineControlResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        super().__init__(suppress_response)

        check_range(routine_identifier, "routineIdentifier", 0, 0xFFFF)
        self.routine_control_type = self.sub_function
        self.routine_identifier = routine_identifier
        self.routine_control_option_record = routine_control_option_record

    @property
    def pdu(self) -> bytes:
        return (
            pack(
                "!BBH",
                self.SERVICE_ID,
                self.sub_function_with_suppress_response_bit,
                self.routine_identifier,
            )
            + self.routine_control_option_record
        )

    @classmethod
    def _from_pdu(
        cls: type[T_RoutineControlRequest], pdu: bytes
    ) -> T_RoutineControlRequest:
        routine_identifier = from_bytes(pdu[2:4])
        routine_control_option_record = pdu[4:]

        return cls(
            routine_identifier,
            routine_control_option_record,
            cls.suppress_response_set(pdu),
        )


class StartRoutineResponse(
    RoutineControlResponse,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.STR,
    minimal_length=4,
    maximal_length=None,
):
    pass


class StartRoutineRequest(
    RoutineControlRequest,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.STR,
    response_type=StartRoutineResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        """Starts a specific routine on the server.
        This is an implementation of the UDS request for the startRoutine sub-function of the
        service routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(
            routine_identifier, routine_control_option_record, suppress_response
        )


class StopRoutineResponse(
    RoutineControlResponse,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.STPR,
    minimal_length=4,
    maximal_length=None,
):
    pass


class StopRoutineRequest(
    RoutineControlRequest,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.STPR,
    response_type=StopRoutineResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        """Stops a specific routine on the server.
        This is an implementation of the UDS request for the stopRoutine sub-function of the service
        routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(
            routine_identifier, routine_control_option_record, suppress_response
        )


class RequestRoutineResultsResponse(
    RoutineControlResponse,
    minimal_length=4,
    maximal_length=None,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.RRR,
):
    pass


class RequestRoutineResultsRequest(
    RoutineControlRequest,
    service_id=UDSIsoServices.RoutineControl,
    sub_function_id=RCSubFuncs.RRR,
    response_type=RequestRoutineResultsResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
    ) -> None:
        """Requests the results of a specific routine on the server.
        This is an implementation of the UDS request for the requestRoutineResults sub-function of
        the service routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        """
        super().__init__(
            routine_identifier, routine_control_option_record, suppress_response
        )


class RoutineControl(
    SpecializedSubFunctionService, service_id=UDSIsoServices.RoutineControl
):
    class StartRoutine(SubFunction, sub_function_id=RCSubFuncs.STR):
        Request = StartRoutineRequest
        Response = StartRoutineResponse

    class StopRoutine(SubFunction, sub_function_id=RCSubFuncs.STPR):
        Request = StopRoutineRequest
        Response = StopRoutineResponse

    class RequestRoutineResults(SubFunction, sub_function_id=RCSubFuncs.RRR):
        Request = RequestRoutineResultsRequest
        Response = RequestRoutineResultsResponse


# ********************
# * Request download *
# ********************


T_RequestUpOrDownloadResponse = TypeVar(
    "T_RequestUpOrDownloadResponse", bound="_RequestUpOrDownloadResponse"
)


class _RequestUpOrDownloadResponse(
    PositiveResponse, service_id=None, minimal_length=3, maximal_length=None
):
    def __init__(
        self,
        max_number_of_block_length: int,
        length_format_identifier: int | None = None,
    ) -> None:
        super().__init__()

        if length_format_identifier is not None:
            if (
                not 0 <= length_format_identifier <= 0xF0
                or length_format_identifier % 2**4 > 0
            ):
                raise ValueError(
                    f"Invalid value for lengthFormatIdentifier: "
                    f"{length_format_identifier}"
                )

            uds_memory_parameters(
                0, max_number_of_block_length, length_format_identifier + 1
            )
        else:
            length_format_identifier, _, _ = uds_memory_parameters(
                0, max_number_of_block_length
            )

        self.max_number_of_block_length = max_number_of_block_length
        self.length_format_identifier = length_format_identifier - (
            length_format_identifier % 2**4
        )

    @property
    def pdu(self) -> bytes:
        max_number_of_block_length = to_bytes(
            self.max_number_of_block_length, self.length_format_identifier // 2**4
        )
        return (
            pack("BB", self.RESPONSE_SERVICE_ID, self.length_format_identifier)
            + max_number_of_block_length
        )

    @classmethod
    def _from_pdu(
        cls: type[T_RequestUpOrDownloadResponse], pdu: bytes
    ) -> T_RequestUpOrDownloadResponse:
        length_format_identifier = pdu[1]
        max_number_of_block_length = from_bytes(pdu[2:])
        return cls(max_number_of_block_length, length_format_identifier)

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, _RequestUpOrDownloadRequest)
            and request.SERVICE_ID == self.SERVICE_ID
        )


T_RequestUpOrDownloadRequest = TypeVar(
    "T_RequestUpOrDownloadRequest", bound="_RequestUpOrDownloadRequest"
)


class _RequestUpOrDownloadRequest(
    UDSRequest,
    service_id=None,
    response_type=_RequestUpOrDownloadResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        memory_address: int,
        memory_size: int,
        compression_method: int = 0x0,
        encryption_method: int = 0x0,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        check_range(compression_method, "compressionMethod", 0, 0xF)
        check_range(encryption_method, "encryptionMethod", 0, 0xF)

        if address_and_length_format_identifier is not None:
            check_range(
                address_and_length_format_identifier,
                "addressAndLengthFormatIdentifier",
                0,
                0xFF,
            )

        self.memory_address = memory_address
        self.memory_size = memory_size
        self.compression_method = compression_method
        self.encryption_method = encryption_method
        self.address_and_length_format_identifier, _, _ = uds_memory_parameters(
            memory_address, memory_size, address_and_length_format_identifier
        )

    @property
    def pdu(self) -> bytes:
        data_format_identifier = (self.compression_method << 4) | self.encryption_method

        addr_and_len_format_id, address_bytes, size_bytes = uds_memory_parameters(
            self.memory_address,
            self.memory_size,
            self.address_and_length_format_identifier,
        )

        pdu = struct.pack(
            "!BBB", self.SERVICE_ID, data_format_identifier, addr_and_len_format_id
        )
        pdu += address_bytes + size_bytes
        return pdu

    @classmethod
    def _from_pdu(
        cls: type[T_RequestUpOrDownloadRequest], pdu: bytes
    ) -> T_RequestUpOrDownloadRequest:
        data_format_identifier = pdu[1]
        address_and_length_format_identifier = pdu[2]
        address_length, size_length = address_and_size_length(
            address_and_length_format_identifier
        )

        if len(pdu) != 3 + address_length + size_length:
            raise ValueError(
                "The addressAndLengthIdentifier is incompatible with the PDU size"
            )

        return cls(
            from_bytes(pdu[3 : 3 + address_length]),
            from_bytes(pdu[3 + address_length : 3 + address_length + size_length]),
            data_format_identifier // 2**4,
            data_format_identifier % 2**4,
            address_and_length_format_identifier,
        )


class RequestDownloadResponse(
    _RequestUpOrDownloadResponse,
    minimal_length=3,
    maximal_length=None,
    service_id=UDSIsoServices.RequestDownload,
):
    pass


class RequestDownloadRequest(
    _RequestUpOrDownloadRequest,
    service_id=UDSIsoServices.RequestDownload,
    response_type=RequestDownloadResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        memory_address: int,
        memory_size: int,
        compression_method: int = 0x0,
        encryption_method: int = 0x0,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        """Requests the download of data, i.e. the possibility to send data from the client to the
        server.
        This is an implementation of the UDS request for requestDownload (0x34).

        :param memory_address: The address at which data should be downloaded.
        :param memory_size: The number of bytes to be downloaded.
        :param compression_method: Encodes the utilized compressionFormat (0x0 for none)
        :param encryption_method: Encodes the utilized encryptionFormat (0x0 for none)
        :param address_and_length_format_identifier: The byte lengths of the memory address and
                                                     size. If omitted, this parameter is computed
                                                     based on the memory_address and
                                                     memory_size parameters.
        """
        super().__init__(
            memory_address,
            memory_size,
            compression_method,
            encryption_method,
            address_and_length_format_identifier,
        )


class RequestDownload(UDSService, service_id=UDSIsoServices.RequestDownload):
    Response = RequestDownloadResponse
    Request = RequestDownloadRequest


# ******************
# * Request Upload *
# ******************


class RequestUploadResponse(
    _RequestUpOrDownloadResponse,
    service_id=UDSIsoServices.RequestUpload,
    minimal_length=3,
    maximal_length=None,
):
    pass


class RequestUploadRequest(
    _RequestUpOrDownloadRequest,
    service_id=UDSIsoServices.RequestUpload,
    response_type=RequestUploadResponse,
    minimal_length=4,
    maximal_length=None,
):
    def __init__(
        self,
        memory_address: int,
        memory_size: int,
        compression_method: int = 0x0,
        encryption_method: int = 0x0,
        address_and_length_format_identifier: int | None = None,
    ) -> None:
        """Requests the upload of data, i.e. the possibility to receive data from the server.
        This is an implementation of the UDS request for requestUpload (0x35).

        :param memory_address: The address at which data should be uploaded.
        :param memory_size: The number of bytes to be uploaded.
        :param compression_method: Encodes the utilized compressionFormat (0x0 for none)
        :param encryption_method: Encodes the utilized encryptionFormat (0x0 for none)
        :param address_and_length_format_identifier: The byte lengths of the memory address and
                                                     size. If omitted, this parameter is computed
                                                     based on the memory_address and memory_size
                                                     parameters.
        """
        super().__init__(
            memory_address,
            memory_size,
            compression_method,
            encryption_method,
            address_and_length_format_identifier,
        )


class RequestUpload(UDSService, service_id=UDSIsoServices.RequestUpload):
    Response = RequestUploadResponse
    Request = RequestUploadRequest


# *****************
# * Transfer data *
# *****************


class TransferDataResponse(
    PositiveResponse,
    service_id=UDSIsoServices.TransferData,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(
        self,
        block_sequence_counter: int,
        transfer_response_parameter_record: bytes = b"",
    ) -> None:
        super().__init__()

        check_range(block_sequence_counter, "blockSequenceCounter", 0, 0xFF)

        self.block_sequence_counter = block_sequence_counter
        self.transfer_response_parameter_record = transfer_response_parameter_record

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> TransferDataResponse:
        block_sequence_counter = pdu[1]
        transfer_response_parameter_record = pdu[2:]
        return TransferDataResponse(
            block_sequence_counter, transfer_response_parameter_record
        )

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.RESPONSE_SERVICE_ID, self.block_sequence_counter)
            + self.transfer_response_parameter_record
        )

    def matches(self, request: UDSRequest) -> bool:
        return (
            isinstance(request, TransferDataRequest)
            and self.block_sequence_counter == request.block_sequence_counter
        )


class TransferDataRequest(
    UDSRequest,
    service_id=UDSIsoServices.TransferData,
    response_type=TransferDataResponse,
    minimal_length=2,
    maximal_length=None,
):
    def __init__(
        self,
        block_sequence_counter: int,
        transfer_request_parameter_record: bytes = b"",
    ) -> None:
        """Transfers data to the server or requests the next data from the server.
        This is an implementation of the UDS request for transferData (0x36).

        :param block_sequence_counter: The current block sequence counter.
                                       Initialized with one and incremented for each new data.
                                       After 0xff, the counter is resumed at 0
        :param transfer_request_parameter_record: Contains the data to be transferred if downloading
                                                  to the server.
        """
        check_range(block_sequence_counter, "blockSequenceCounter", 0, 0xFF)

        self.block_sequence_counter = block_sequence_counter
        self.transfer_request_parameter_record = transfer_request_parameter_record

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> TransferDataRequest:
        block_sequence_counter = pdu[1]
        transfer_request_parameter_record = pdu[2:]
        return TransferDataRequest(
            block_sequence_counter, transfer_request_parameter_record
        )

    @property
    def pdu(self) -> bytes:
        return (
            pack("!BB", self.SERVICE_ID, self.block_sequence_counter)
            + self.transfer_request_parameter_record
        )


class TransferData(UDSService, service_id=UDSIsoServices.TransferData):
    Response = TransferDataResponse
    Request = TransferDataRequest


# *************************
# * Request transfer exit *
# *************************


class RequestTransferExitResponse(
    PositiveResponse,
    service_id=UDSIsoServices.RequestTransferExit,
    minimal_length=1,
    maximal_length=None,
):
    def __init__(self, transfer_response_parameter_record: bytes = b"") -> None:
        super().__init__()

        self.transfer_response_parameter_record = transfer_response_parameter_record

    @property
    def pdu(self) -> bytes:
        assert self.RESPONSE_SERVICE_ID is not None
        return (
            bytes([self.RESPONSE_SERVICE_ID]) + self.transfer_response_parameter_record
        )

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> RequestTransferExitResponse:
        transfer_response_parameter_record = pdu[1:]
        return RequestTransferExitResponse(transfer_response_parameter_record)

    def matches(self, request: UDSRequest) -> bool:
        return isinstance(request, RequestTransferExitRequest)


class RequestTransferExitRequest(
    UDSRequest,
    service_id=UDSIsoServices.RequestTransferExit,
    response_type=RequestTransferExitResponse,
    minimal_length=1,
    maximal_length=None,
):
    def __init__(self, transfer_request_parameter_record: bytes = b"") -> None:
        """Ends the transfer of data.
        This is an implementation of the UDS request for requestTransferExit (0x77).

        :param transfer_request_parameter_record: Optional data.
        """
        self.transfer_request_parameter_record = transfer_request_parameter_record

    @property
    def pdu(self) -> bytes:
        assert self.SERVICE_ID is not None
        return bytes([self.SERVICE_ID]) + self.transfer_request_parameter_record

    @classmethod
    def _from_pdu(cls, pdu: bytes) -> RequestTransferExitRequest:
        transfer_request_parameter_record = pdu[1:]
        return RequestTransferExitRequest(transfer_request_parameter_record)


class RequestTransferExit(UDSService, service_id=UDSIsoServices.RequestTransferExit):
    Response = RequestTransferExitResponse
    Request = RequestTransferExitRequest


# *************************
# * Request file transfer *
# *************************
