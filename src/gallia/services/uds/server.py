# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import json
import random
import traceback
from abc import ABC, abstractmethod
from binascii import hexlify, unhexlify
from copy import copy
from pathlib import Path
from time import time
from typing import Any

import aiosqlite

from gallia.log import get_logger
from gallia.services.uds.core import service
from gallia.services.uds.core.constants import (
    DataIdentifier,
    ERSubFuncs,
    RCSubFuncs,
    RDTCISubFuncs,
    UDSErrorCodes,
    UDSIsoServices,
)
from gallia.services.uds.core.utils import bytes_repr, int_repr, service_repr, to_bytes
from gallia.services.uds.ecu import ECUState
from gallia.transports import ISOTPTransport, TargetURI


class UDSServer(ABC):
    def __init__(self) -> None:
        self.state = ECUState()
        self.logger = get_logger("v-ecu")

        self.use_default_response_if_service_not_supported = True
        self.use_default_response_if_missing_sub_function = True
        self.use_default_response_if_sub_function_not_supported = True
        self.use_default_response_if_incorrect_format = True
        self.use_default_response_if_session_change = True
        self.use_default_response_if_session_read = True
        self.use_default_response_if_tester_present = True
        self.use_default_response_if_none = True
        self.use_default_response_if_suppress = True

    @property
    @abstractmethod
    def supported_services(
        self,
    ) -> dict[int, dict[UDSIsoServices, list[int] | None]]:
        ...

    def default_response_if_service_not_supported(
        self, request: service.UDSRequest
    ) -> service.NegativeResponse | None:
        assert (
            self.state.session in self.supported_services
        ), "Virtual ECU in unsupported session"

        if request.service_id not in self.supported_services[self.state.session]:
            if any(request.service_id in s for s in self.supported_services.values()):
                nrc = UDSErrorCodes.serviceNotSupportedInActiveSession
            else:
                nrc = UDSErrorCodes.serviceNotSupported

            return service.NegativeResponse(request.service_id, nrc)

        return None

    def _is_sub_function_service(self, service_id: int) -> bool:
        try:
            service_class = (
                service.UDSService._SERVICES[  # pylint: disable=protected-access
                    UDSIsoServices(service_id)
                ]
            )

            return (
                issubclass(service_class, service.SpecializedSubFunctionService)
                or service_class.Request is not None
                and issubclass(service_class.Request, service.SubFunctionRequest)
            )
        except Exception:
            return False

    def _is_sub_function_request(self, request: service.UDSRequest) -> bool:
        return self._is_sub_function_service(request.service_id)

    def default_response_if_missing_sub_function(
        self, request: service.UDSRequest
    ) -> service.NegativeResponse | None:
        try:
            if self._is_sub_function_request(request) and len(request.pdu) < 2:
                return service.NegativeResponse(
                    request.service_id,
                    UDSErrorCodes.incorrectMessageLengthOrInvalidFormat,
                )
        except Exception:
            pass

        return None

    def default_response_if_sub_function_not_supported(
        self, request: service.UDSRequest
    ) -> service.NegativeResponse | None:
        assert (
            self.state.session in self.supported_services
        ), "Virtual ECU in unsupported session"

        # The standards explicitly excludes RoutineControl for this check because the availability of a sub function
        # depends on the routineIdentifier
        if (
            self._is_sub_function_request(request)
            and request.service_id != UDSIsoServices.RoutineControl
        ):
            supported_in_active_session = False
            supported_in_other_session = False

            for session in self.supported_services:
                if (
                    UDSIsoServices(request.service_id)
                    not in self.supported_services[session]
                ):
                    continue

                supported_sub_functions = self.supported_services[session][
                    UDSIsoServices(request.service_id)
                ]

                assert (
                    supported_sub_functions is not None
                ), "Sub function services must have a (potentially empty) list of supported sub functions"

                sub_function = request.pdu[1] % 0x80

                if sub_function in supported_sub_functions:
                    if session == self.state.session:
                        supported_in_active_session = True
                        break
                    supported_in_other_session = True

            if not supported_in_active_session:
                if supported_in_other_session:
                    nrc = UDSErrorCodes.subFunctionNotSupportedInActiveSession

                else:
                    nrc = UDSErrorCodes.subFunctionNotSupported

                return service.NegativeResponse(request.service_id, nrc)

        return None

    def default_response_if_incorrect_format(
        self, request: service.UDSRequest
    ) -> service.NegativeResponse | None:
        if isinstance(request, service.RawRequest):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
            )

        return None

    def default_response_if_session_change(
        self, request: service.UDSRequest
    ) -> None | (service.NegativeResponse | service.DiagnosticSessionControlResponse):
        if isinstance(request, service.DiagnosticSessionControlRequest):
            return service.DiagnosticSessionControlResponse(
                request.diagnostic_session_type
            )

        return None

    def default_response_if_session_read(
        self, request: service.UDSRequest
    ) -> service.ReadDataByIdentifierResponse | None:
        if isinstance(request, service.ReadDataByIdentifierRequest):
            if (
                request.data_identifier
                == DataIdentifier.ActiveDiagnosticSessionDataIdentifier
            ):
                return service.ReadDataByIdentifierResponse(
                    request.data_identifier, to_bytes(self.state.session, 1)
                )

        return None

    def default_response_if_tester_present(
        self, request: service.UDSRequest
    ) -> service.TesterPresentResponse | None:
        if isinstance(request, service.TesterPresentRequest):
            return service.TesterPresentResponse()

        return None

    def default_response_if_none(
        self, request: service.UDSRequest
    ) -> service.NegativeResponse:
        return service.NegativeResponse(request.service_id, UDSErrorCodes.generalReject)

    def default_response_if_suppress(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> service.UDSResponse | None:
        if (
            isinstance(response, service.NegativeResponse)
            or not isinstance(request, service.SubFunctionRequest)
            or not request.suppress_response
        ):
            return response

        return None

    async def update_state(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> None:
        if isinstance(response, service.DiagnosticSessionControlResponse):
            self.state.reset()
            self.state.session = response.diagnostic_session_type

        if (
            isinstance(response, service.SecurityAccessResponse)
            and response.security_access_type % 2 == 0
        ):
            self.state.security_access_level = response.security_access_type - 1

        if isinstance(response, service.ECUResetResponse):
            self.state.reset()

    async def setup(self) -> None:
        pass

    async def teardown(self) -> None:
        pass

    # pylint: disable=too-many-return-statements
    async def respond_without_state_change(
        self, request: service.UDSRequest
    ) -> service.UDSResponse | None:
        response: service.UDSResponse | None

        if (
            self.use_default_response_if_service_not_supported
            and (response := self.default_response_if_service_not_supported(request))
            is not None
        ):
            return response

        if (
            self.use_default_response_if_missing_sub_function
            and (response := self.default_response_if_missing_sub_function(request))
            is not None
        ):
            return response

        if (
            self.use_default_response_if_sub_function_not_supported
            and (
                response := self.default_response_if_sub_function_not_supported(request)
            )
            is not None
        ):
            return response

        if (
            self.use_default_response_if_incorrect_format
            and (response := self.default_response_if_incorrect_format(request))
            is not None
        ):
            return response

        if (
            self.use_default_response_if_session_change
            and (response := self.default_response_if_session_change(request))
            is not None
        ):
            return response

        if (
            self.use_default_response_if_session_read
            and (response := self.default_response_if_session_read(request)) is not None
        ):
            return response

        if (
            self.use_default_response_if_tester_present
            and (response := self.default_response_if_tester_present(request))
            is not None
        ):
            return response

        if (response := await self.respond_after_default(request)) is not None:
            return response

        if self.use_default_response_if_none:
            return self.default_response_if_none(request)

        return None

    async def respond(self, request: service.UDSRequest) -> service.UDSResponse | None:
        response = await self.respond_without_state_change(request)

        if response is not None:
            old_state = copy(self.state)

            await self.update_state(request, response)

            if self.state.__dict__ != old_state.__dict__:
                self.logger.debug(f"Changed state to {self.state}")

            if self.use_default_response_if_suppress:
                return self.default_response_if_suppress(request, response)

        return response

    @abstractmethod
    async def respond_after_default(
        self, request: service.UDSRequest
    ) -> service.UDSResponse | None:
        ...


class RNG(random.Random):
    def __init__(self, *args: Any):
        super().__init__()

        self.seeds: list[Any] = []
        self.set_seeds(*args)

    def set_seeds(self, *args: Any) -> None:
        self.seeds = list(args)

        if len(self.seeds) == 0:
            self.seed()
        else:
            self.seed("|".join(str(seed) for seed in self.seeds))

    def add_seeds(self, *args: Any) -> None:
        self.set_seeds(*self.seeds, *args)

    def random_bool(self, p_true: float) -> bool:
        return self.random() <= p_true

    def random_payload(self, min_len: int = 0, max_len: int | None = None) -> bytes:
        # Mean length should be a few bytes (here 8)
        byte_length = max(min_len, int(self.expovariate(1 / 8) + 0.5))

        if max_len is not None:
            byte_length = min(max_len, byte_length)

        return bytes(self.randint(0, 255) for _ in range(byte_length))


class RNGEcuState(ECUState):
    def __init__(self) -> None:
        super().__init__()

        self.last_sa_response: service.SecurityAccessResponse | None = None

    def reset(self) -> None:
        super().reset()
        self.last_sa_response = None


class RandomUDSServer(UDSServer):
    def __init__(self, seed: int):
        super().__init__()

        self.state: RNGEcuState = RNGEcuState()

        self.seed = seed

        self.mandatory_sessions = [1]
        self.optional_sessions = [2, 3, 4] + list(range(0x40, 0x7F))
        self.p_session = 0.05

        self.services: dict[int, dict[UDSIsoServices, list[int] | None]] = {}
        self.mandatory_services = [UDSIsoServices.DiagnosticSessionControl]
        self.optional_services = list(
            set(UDSIsoServices)
            - set(self.mandatory_services + [UDSIsoServices.NegativeResponse])
        )
        self.p_service = 0.2

        self.p_sub_function = 0.05
        self.p_identifier = 0.005
        self.p_correct_payload_format = 0.1
        self.p_dtc_status_mask = 0.9

    async def setup(self) -> None:
        self.randomize()

        self.logger.notice(f"Initialized random UDS server with seed {self.seed}")
        self.logger.info(
            json.dumps(
                {
                    int_repr(session): {
                        f"{int_repr(s.value)} ({service_repr(s)})": str(
                            list(int_repr(sf) for sf in sfs)
                        )
                        if sfs is not None
                        else None
                        for s, sfs in services.items()
                    }
                    for session, services in self.services.items()
                },
                indent=4,
                sort_keys=True,
            )
        )

    def randomize(self) -> None:
        rng = RNG(self.seed)

        level = 0
        default_session = 1
        level_sessions = {default_session}
        session_transitions: list[set[int]] = list(set() for _ in range(0x7F))
        session_transitions[default_session] = {default_session}
        combined_sessions = self.mandatory_sessions + self.optional_sessions

        while len(level_sessions) > 0:
            p_transition = self.p_session / len(level_sessions) / 2 ** (level + 0.5)
            next_level_sessions = set()
            available_sessions = list(
                i for i, l in enumerate(session_transitions) if len(l) > 0
            )

            for session in level_sessions:
                transitions = list(
                    session
                    for session in combined_sessions
                    if rng.random() < p_transition
                )
                session_transitions[session].update(transitions)
                next_level_sessions.update(transitions)

            for session in next_level_sessions:
                session_transitions[session].add(default_session)

            level_sessions = next_level_sessions - set(available_sessions)
            level += 1

        for session in self.mandatory_sessions:
            if len(session_transitions[session]) == 0:
                available_sessions = list(
                    i for i, l in enumerate(session_transitions) if len(l) > 0
                )
                session_transitions[rng.choice(available_sessions)].add(session)
                session_transitions[session] = {default_session}

        self.services = {}

        for session, session_specific_transitions in enumerate(session_transitions):
            if len(session_specific_transitions) == 0:
                continue

            self.services[session] = {}

            for supported_service in self.mandatory_services + list(
                s for s in self.optional_services if rng.random() < self.p_service
            ):
                supported_sub_functions: list[int] | None = None

                if self._is_sub_function_service(supported_service):
                    # For SecurityAccess there are always two consecutive sub functions, the uneven one for RequestSeed,
                    # the even one (+1) for SendKey
                    if supported_service == UDSIsoServices.TesterPresent:
                        supported_sub_functions = [0]
                    elif supported_service == UDSIsoServices.DiagnosticSessionControl:
                        supported_sub_functions = sorted(session_specific_transitions)
                    elif supported_service == UDSIsoServices.SecurityAccess:
                        supported_sub_functions_tmp = list(
                            sf
                            for sf in range(1, 0x7E, 2)
                            if rng.random() < self.p_sub_function / 2
                        )
                        supported_sub_functions = []

                        for sf in supported_sub_functions_tmp:
                            supported_sub_functions.append(sf)
                            supported_sub_functions.append(sf + 1)
                    elif supported_service == UDSIsoServices.RoutineControl:
                        supported_sub_functions = list(sf.value for sf in RCSubFuncs)
                    # Currently only this sub function is supported so it doesn't make sense to gamble a lot here
                    elif supported_service == UDSIsoServices.ReadDTCInformation:
                        supported_sub_functions = [RDTCISubFuncs.RDTCBSM]
                    else:
                        supported_sub_functions = list(
                            sf
                            for sf in range(1, 0x80, 1)
                            if rng.random() < self.p_sub_function
                        )

                self.services[session][supported_service] = supported_sub_functions

    @property
    def supported_services(
        self,
    ) -> dict[int, dict[UDSIsoServices, list[int] | None]]:
        return self.services

    def stateful_rng(self, *args: Any) -> RNG:
        return RNG(
            str(self.seed)
            + "|"
            + str(self.state.session)
            + "|".join(str(arg) for arg in args)
        )

    # pylint: disable=too-many-return-statements
    async def respond_after_default(
        self, request: service.UDSRequest
    ) -> service.UDSResponse | None:
        # Service specific handling starts here
        # It is assumed, that the service and sub-function, if any, are both supported
        # Furthermore, it is assumed that the request is a valid request for that particular service and sub-function
        if isinstance(request, service.ECUResetRequest):
            return self.ecu_reset(request)
        if isinstance(
            request, service._SecurityAccessRequest  # pylint: disable=protected-access
        ):
            return self.security_access(request)
        if isinstance(request, service.RoutineControlRequest):
            return self.routine_control(request)
        if isinstance(request, service.ReadDataByIdentifierRequest):
            return self.read_data_by_identifier(request)
        if isinstance(request, service.WriteDataByIdentifierRequest):
            return self.write_data_by_identifier(request)
        if isinstance(request, service.InputOutputControlByIdentifierRequest):
            return self.input_output_control_by_identifier(request)
        if isinstance(request, service.ClearDiagnosticInformationRequest):
            return self.clear_diagnostic_information(request)
        if request.service_id == UDSIsoServices.ReadDTCInformation:
            return self.read_dtc_information(request)

        return None

    async def update_state(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> None:
        await super().update_state(request, response)

        if not isinstance(response, service.TesterPresentResponse):
            self.state.last_sa_response = (
                response
                if isinstance(response, service.SecurityAccessResponse)
                else None
            )

    def ecu_reset(self, request: service.ECUResetRequest) -> service.UDSResponse:
        rng = self.stateful_rng(request.pdu)

        if request.reset_type == ERSubFuncs.ERPSD:
            return service.ECUResetResponse(request.reset_type, rng.randint(0, 255))

        return service.ECUResetResponse(request.reset_type)

    def security_access(
        self, request: service._SecurityAccessRequest
    ) -> service.UDSResponse:
        if isinstance(request, service.RequestSeedRequest):
            return service.SecurityAccessResponse(
                request.security_access_type, RNG().random_payload()
            )

        if isinstance(request, service.SendKeyRequest):
            if (
                self.state.last_sa_response is None
                or request.security_access_type
                != self.state.last_sa_response.security_access_type + 1
            ):
                return service.NegativeResponse(
                    request.service_id, UDSErrorCodes.requestSequenceError
                )

            # Let's use the identity as a valid key
            expected_key = self.state.last_sa_response.security_seed
            self.state.last_sa_response = None

            if request.security_key == expected_key:
                return service.SecurityAccessResponse(request.security_access_type)

            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.invalidKey
            )

        assert False

    def routine_control(
        self, request: service.RoutineControlRequest
    ) -> service.UDSResponse:
        rng = self.stateful_rng(request.service_id, request.routine_identifier)

        if not rng.random_bool(self.p_identifier):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.requestOutOfRange
            )

        rng.add_seeds(request.sub_function)

        if not rng.random_bool(2 / 3):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.subFunctionNotSupported
            )

        rng = self.stateful_rng(request.pdu)

        if not rng.random_bool(self.p_correct_payload_format):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
            )

        return request.RESPONSE_TYPE(request.routine_identifier, rng.random_payload())  # type: ignore

    def read_data_by_identifier(
        self, request: service.ReadDataByIdentifierRequest
    ) -> service.UDSResponse:
        rng = self.stateful_rng(request.pdu)

        if not rng.random_bool(self.p_identifier):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.requestOutOfRange
            )

        return service.ReadDataByIdentifierResponse(
            request.data_identifier, rng.random_payload(min_len=1)
        )

    def write_data_by_identifier(
        self, request: service.WriteDataByIdentifierRequest
    ) -> service.UDSResponse:
        rng = self.stateful_rng(request.service_id, request.data_identifier)

        if not rng.random_bool(self.p_identifier):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.requestOutOfRange
            )

        rng = self.stateful_rng(request.pdu)

        if not rng.random_bool(self.p_correct_payload_format):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
            )

        return service.WriteDataByIdentifierResponse(request.data_identifier)

    def input_output_control_by_identifier(
        self, request: service.InputOutputControlByIdentifierRequest
    ) -> service.UDSResponse:
        rng = self.stateful_rng(request.service_id, request.data_identifier)

        if not rng.random_bool(self.p_identifier):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.requestOutOfRange
            )

        rng = self.stateful_rng(request.pdu)

        if not rng.random_bool(self.p_correct_payload_format):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
            )

        return request.RESPONSE_TYPE(request.data_identifier, rng.random_payload(min_len=1))  # type: ignore

    def clear_diagnostic_information(
        self, request: service.ClearDiagnosticInformationRequest
    ) -> service.UDSResponse:
        rng = self.stateful_rng(request.service_id, request.group_of_dtc)

        if not rng.random_bool(self.p_dtc_status_mask):
            return service.NegativeResponse(
                request.service_id, UDSErrorCodes.requestOutOfRange
            )

        return service.ClearDiagnosticInformationResponse()

    def read_dtc_information(self, request: service.UDSRequest) -> service.UDSResponse:
        assert request.service_id == UDSIsoServices.ReadDTCInformation

        # Currently only this sub function is supported
        if isinstance(request, service.ReportDTCByStatusMaskRequest):
            # The supported dtc status bits should be equal for all requests
            # and only differ among different ECUs and states
            dtc_status_availability_mask = self.stateful_rng().randint(0, 255)

            rng = self.stateful_rng(request.service_id, request.dtc_status_mask)
            dtc_and_status_record = {}

            # On average around 50 dtcs should be fine
            for _ in range(int(rng.expovariate(1 / 50) + 0.5)):
                dtc_and_status_record[rng.randint(0, 256**3 - 1)] = (
                    rng.randint(0, 255) & dtc_status_availability_mask
                )

            return service.ReportDTCByStatusMaskResponse(
                dtc_status_availability_mask, dtc_and_status_record
            )

        return service.NegativeResponse(
            request.service_id, UDSErrorCodes.subFunctionNotSupported
        )


class DBUDSServer(UDSServer):
    def __init__(
        self, db_path: Path, ecu: str | None, properties: dict[str, Any] | None
    ):
        super().__init__()

        self.db_path = db_path
        self.ecu = ecu
        self.properties = properties
        self.connection: aiosqlite.Connection | None = None
        self.last_response = -1

        # Override defaults
        self.use_default_response_if_service_not_supported = False
        self.use_default_response_if_missing_sub_function = False
        self.use_default_response_if_sub_function_not_supported = False
        self.use_default_response_if_incorrect_format = False
        self.use_default_response_if_session_change = False
        self.use_default_response_if_session_read = False
        self.use_default_response_if_tester_present = False
        self.use_default_response_if_none = False
        self.use_default_response_if_suppress = False

    async def setup(self) -> None:
        self.connection = await aiosqlite.connect(self.db_path)

    async def teardown(self) -> None:
        if self.connection is not None:
            await self.connection.close()

    @property
    def supported_services(
        self,
    ) -> dict[int, dict[UDSIsoServices, list[int] | None]]:
        return {}

    async def respond_after_default(
        self, request: service.UDSRequest
    ) -> service.UDSResponse | None:
        assert self.connection is not None

        query = "SELECT r.id, r.response_pdu FROM scan_result r WHERE "
        parameters: list[Any] = []

        if self.properties is not None and self.ecu is None:
            query = (
                "SELECT r.id, r.response_pdu "
                "FROM scan_result r, scan_run s WHERE r.run = s.id AND "
            )

        if self.ecu is not None:
            query = (
                "SELECT r.id, r.response_pdu "
                "FROM scan_run s, scan_result r, address a, ecu e "
                "WHERE r.run = s.id AND s.address = a.id AND a.ecu = e.id "
                "AND e.name = ? AND "
            )

            parameters = [self.ecu]

        for key, value in self.state.__dict__.items():
            if value is None:
                query += f"json_extract(r.state, '$.{key}') IS NULL AND "
            else:
                query += f"json_extract(r.state, '$.{key}') = ? AND "
                parameters.append(
                    value if isinstance(value, (int, float)) else json.dumps(value)
                )

        if self.properties is not None:
            for key, value in self.properties.items():
                if value is None:
                    query += f"json_extract(s.properties_pre, '$.{key}') IS NULL AND "
                else:
                    query += f"json_extract(s.properties_pre, '$.{key}') = ? AND "
                    parameters.append(
                        value if isinstance(value, (int, float)) else json.dumps(value)
                    )

        query += "r.request_pdu = ? "

        final_query = f"{query} AND r.id > ? ORDER BY r.id LIMIT 1 "

        parameters += [bytes_repr(request.pdu, False, None), self.last_response]
        cursor: aiosqlite.Cursor = await self.connection.execute(
            final_query, parameters
        )
        result = await cursor.fetchone()

        if result is None:
            final_query = f"{query} AND r.id <= ? ORDER BY r.id LIMIT 1 "
            cursor = await self.connection.execute(final_query, parameters)
            result = await cursor.fetchone()

        if result is not None:
            self.last_response = result[0]
            response_pdu: bytes | None = result[1]

            if response_pdu is not None:
                response = service.UDSResponse.parse_dynamic(unhexlify(response_pdu))
                return response

            self.logger.info("Reset ECU due to missing response")
            self.state.reset()

        return None


class UDSServerTransport:
    def __init__(self, server: UDSServer, target: TargetURI):
        self.server = server
        self.target = target
        self.logger = get_logger("v-ecu")
        self.last_time_active = time()

    async def run(self) -> None:
        ...

    async def handle_request(self, request_pdu: bytes) -> tuple[bytes | None, float]:
        start = time()

        if start - self.last_time_active > 10:
            self.logger.info("Server state reset due to inactivity")
            self.server.state.reset()

        request = service.UDSRequest.parse_dynamic(request_pdu)
        self.logger.debug(f"---> {request}")
        response = await self.server.respond(request)
        end = time()
        self.last_time_active = end

        if response is not None:
            self.logger.debug(f"  <--- {response} after {(end - start) * 1000:.2f} ms")
            return response.pdu, end - start

        self.logger.debug(f"  x--- NO RESPONSE after {(end - start) * 1000:.2f} ms")
        return None, end - start


class TCPUDSServerTransport(UDSServerTransport):
    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        self.logger.info("New connection")
        response_times = []

        while True:
            try:
                line = await reader.readline()

                if not line:
                    break

                tcp_request = line.decode("ascii").strip()
                uds_request_raw = unhexlify(tcp_request)
                uds_response_raw, response_time = await self.handle_request(
                    uds_request_raw
                )
                response_times.append(response_time)

                if uds_response_raw is not None:
                    writer.write(hexlify(uds_response_raw) + b"\n")
                    await writer.drain()
            except Exception:
                traceback.print_exc()

        self.logger.info("Connection closed")
        self.logger.info(
            f"Average response time: {sum(response_times) / len(response_times) * 1000:.2f}ms"
        )

    async def run(self) -> None:
        server = await asyncio.start_server(
            self.handle_client, self.target.hostname, self.target.port
        )

        async with server:
            await server.serve_forever()


class ISOTPUDSServerTransport(UDSServerTransport):
    async def run(self) -> None:
        transport = await ISOTPTransport.connect(self.target)

        while True:
            try:
                uds_request_raw = await transport.read()
                uds_response_raw, _ = await self.handle_request(uds_request_raw)

                if uds_response_raw is not None:
                    await transport.write(uds_response_raw)
            except Exception:
                traceback.print_exc()
