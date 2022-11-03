# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import overload

from gallia.log import get_logger
from gallia.services.uds.core import service
from gallia.services.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import MissingResponse
from gallia.services.uds.helpers import parse_pdu
from gallia.transports import BaseTransport


@dataclass
class UDSRequestConfig:
    # timeout for this request in sec
    timeout: float | None = None
    # maximum number of attempts in case of network errors
    max_retry: int | None = None
    # Skip the hooks which apply to session changes.
    skip_hooks: bool = False
    # tags to be applied to the logged output
    tags: list[str] | None = None


class UDSClient:
    def __init__(
        self,
        transport: BaseTransport,
        timeout: float,
        max_retry: int = 1,
    ):
        self.transport = transport
        self.timeout = timeout
        self.max_retry = max_retry
        self.retry_wait = 0.2
        self.pending_timeout = 5
        self.mutex = asyncio.Lock()
        self.logger = get_logger("uds")

    async def reconnect(self, timeout: int | None = None) -> None:
        """Calls the underlying transport to trigger a reconnect"""
        async with self.mutex:
            self.transport = await self.transport.reconnect(timeout)

    async def _read(
        self, timeout: float | None = None, tags: list[str] | None = None
    ) -> bytes:
        if timeout is None and self.timeout:
            timeout = self.timeout
        return await self.transport.read(timeout, tags)

    async def request_unsafe(
        self, request: service.UDSRequest, config: UDSRequestConfig | None = None
    ) -> service.UDSResponse:
        """This method is the same as request() with the difference
        that it does not hold the mutex in the underlying transport.
        """
        config = config if config is not None else UDSRequestConfig()
        tags: list[str] = [] if config.tags is None else config.tags

        last_exception: Exception = MissingResponse(request)
        max_retry = config.max_retry if config.max_retry else self.max_retry
        timeout = config.timeout if config.timeout else self.timeout
        for i in range(0, max_retry):
            # Exponential backoff
            wait_time = self.retry_wait * 2**i

            # Avoid pasting this very line in every error branch.
            if i > 0:
                self.logger.debug(f"retrying {i} from {max_retry}…")
            try:
                self.logger.debug(
                    request.pdu.hex(), extra={"tags": ["write", "uds"] + tags}
                )
                raw_resp = await self.transport.request_unsafe(
                    request.pdu, timeout, config.tags
                )
                if raw_resp == b"":
                    raise BrokenPipeError("connection to target lost")
            except asyncio.TimeoutError as e:
                self.logger.debug(f"{request} failed with: {repr(e)}")
                last_exception = MissingResponse(request, str(e))
                await asyncio.sleep(wait_time)
                continue

            self.logger.debug(raw_resp.hex(), extra={"tags": ["read", "uds"] + tags})
            resp = parse_pdu(raw_resp, request)

            if isinstance(resp, service.NegativeResponse):
                if resp.response_code == UDSErrorCodes.busyRepeatRequest:
                    if i >= max_retry - 1:
                        return resp
                    await asyncio.sleep(wait_time)
                    continue
            # We already had ECUs which thought an infinite
            # response_pending loop is a good idea…
            # Let's limit this.
            n_pending = 0
            n_timeout = 0
            waiting_time = 0.5
            max_n_timeout = max(timeout if timeout else 0, 10) / waiting_time
            while (
                isinstance(resp, service.NegativeResponse)
                and resp.response_code
                == UDSErrorCodes.requestCorrectlyReceivedResponsePending
            ):
                try:
                    raw_resp = await self._read(timeout=waiting_time, tags=config.tags)
                    if raw_resp == b"":
                        raise BrokenPipeError("connection to target lost")
                    self.logger.debug(
                        raw_resp.hex(), extra={"tags": ["read", "uds"] + tags}
                    )
                except asyncio.TimeoutError as e:
                    # Send a tester present to indicate that
                    # we are still there.
                    await self._tester_present(supress_resp=True)
                    n_timeout += 1
                    if n_timeout >= max_n_timeout:
                        last_exception = MissingResponse(request, str(e))
                        break
                    continue
                resp = parse_pdu(raw_resp, request)
                n_timeout = 0  # Only raise errors for consecutive timeouts
                n_pending += 1
                if n_pending >= 120:
                    raise RuntimeError(
                        "ECU appears to be stuck in ResponsePending loop"
                    )
            else:
                # We reach this code here once all response pending
                # and similar busy stuff is resolved.
                return resp

        self.logger.debug(f"{request} failed after retry loop")
        raise last_exception

    async def _tester_present(
        self, supress_resp: bool = False, config: UDSRequestConfig | None = None
    ) -> service.UDSResponse | None:
        config = config if config is not None else UDSRequestConfig()
        timeout = config.timeout if config.timeout else self.timeout
        if supress_resp:
            pdu = service.TesterPresentRequest(suppress_response=True).pdu
            await self.transport.write(pdu, timeout, config.tags)
            return None
        return await self.tester_present(False, config)

    async def send_raw(
        self, pdu: bytes, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.PositiveResponse:
        """Raw request, which does not need to be compliant with the standard.
        It can be used to send arbitrary data packets.

        :param pdu: The data.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(service.RawRequest(pdu), config)

    async def diagnostic_session_control(
        self,
        diagnostic_session_type: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.DiagnosticSessionControlResponse:
        """Sets the diagnostic session which is specified by a specific diagnosticSessionType
        sub-function.
        This is an implementation of the UDS request for service DiagnosticSessionControl (0x10).

        :param diagnostic_session_type: The session sub-function.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.DiagnosticSessionControlRequest(
                diagnostic_session_type, suppress_response
            ),
            config,
        )

    async def ecu_reset(
        self,
        reset_type: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ECUResetResponse:
        """Resets the ECU using the specified reset type sub-function.
        This is an implementation of the UDS request for service ECUReset (0x11).

        :param reset_type: The reset type sub-function.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ECUResetRequest(reset_type, suppress_response), config
        )

    async def security_access_request_seed(
        self,
        security_access_type: int,
        security_access_data_record: bytes = b"",
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.SecurityAccessResponse:
        """Requests a seed for a security access level.
        This is an implementation of the UDS request for the requestSeed sub-function group
        of the service SecurityAccess (0x27).

        :param security_access_type: The securityAccess type sub-function.
        :param security_access_data_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.RequestSeedRequest(
                security_access_type, security_access_data_record, suppress_response
            ),
            config,
        )

    async def security_access_send_key(
        self,
        security_access_type: int,
        security_key: bytes,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.SecurityAccessResponse:
        """Sends the key for a security access level.
        This is an implementation of the UDS request for the sendKey sub-function group
        of the service SecurityAccess (0x27).

        :param security_access_type: The securityAccess type sub-function.
        :param security_key: The response to the seed challenge.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.SendKeyRequest(
                security_access_type, security_key, suppress_response
            ),
            config,
        )

    async def communication_control(
        self,
        control_type: int,
        communication_type: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.CommunicationControlResponse:
        """Controls communication of the ECU.
        This is an implementation of the UDS request for service CommunicationControl (0x28).

        :param control_type: The control type sub-function.
        :param communication_type: The communication type.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.CommunicationControlRequest(
                control_type, communication_type, suppress_response
            ),
            config,
        )

    async def tester_present(
        self, suppress_response: bool = False, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.TesterPresentResponse:
        """Signals to the ECU, that the tester is still present.
        This is an implementation of the UDS request for service TesterPresent (0x3E).

        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.TesterPresentRequest(suppress_response), config
        )

    async def control_dtc_setting(
        self,
        dtc_setting_type: int,
        dtc_setting_control_option_record: bytes = b"",
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ControlDTCSettingResponse:
        """Control the setting of DTCs.
        This is an implementation of the UDS request for service ControlDTCSetting (0x85).


        :param dtc_setting_type: The setting type.
        :param dtc_setting_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ControlDTCSettingRequest(
                dtc_setting_type, dtc_setting_control_option_record, suppress_response
            ),
            config,
        )

    async def read_data_by_identifier(
        self,
        data_identifiers: int | Sequence[int],
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReadDataByIdentifierResponse:
        """Reads data which is identified by a specific dataIdentifier.
        This is an implementation of the UDS request for service ReadDataByIdentifier (0x22).
        While this implementation supports requesting multiple dataIdentifiers at once, as is
        permitted in the standard, it is recommended to request them separately,
        because the support is optional on the server side.
        Additionally, it is not possible to reliably determine each single dataRecord from a
        corresponding response.

        :param data_identifiers: One or multiple dataIdentifiers. A dataIdentifier is a max two
                                 bytes integer.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReadDataByIdentifierRequest(data_identifiers), config
        )

    async def read_memory_by_address(
        self,
        memory_address: int,
        memory_size: int,
        address_and_length_format_identifier: int | None = None,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReadMemoryByAddressResponse:
        """Reads data from a specific memory address on the UDS server.
        This is an implementation of the UDS request for service ReadMemoryByAddress (0x3d).
        While it exposes each parameter of the corresponding specification,
        some parameters can be computed from the remaining ones and can therefore be omitted.

        :param memory_address: The start address.
        :param memory_size: The number of bytes to read.
        :param address_and_length_format_identifier: The byte lengths of the memory address and
                                                     size. If omitted, this parameter is computed
                                                     based on the memory_address and memory_size
                                                     parameters.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReadMemoryByAddressRequest(
                memory_address, memory_size, address_and_length_format_identifier
            ),
            config,
        )

    async def write_data_by_identifier(
        self,
        data_identifier: int,
        data_record: bytes,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.WriteDataByIdentifierResponse:
        """Writes data which is identified by a specific dataIdentifier.
        This is an implementation of the UDS request for service WriteDataByIdentifier (0x2E).

        :param data_identifier: The identifier. A dataIdentifier is a max two bytes integer.
        :param data_record: The data to be written.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.WriteDataByIdentifierRequest(data_identifier, data_record), config
        )

    async def write_memory_by_address(
        self,
        memory_address: int,
        data_record: bytes,
        memory_size: int | None = None,
        address_and_length_format_identifier: int | None = None,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.WriteMemoryByAddressResponse:
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
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.WriteMemoryByAddressRequest(
                memory_address,
                data_record,
                memory_size,
                address_and_length_format_identifier,
            ),
            config,
        )

    async def clear_diagnostic_information(
        self, group_of_dtc: int, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.ClearDiagnosticInformationResponse:
        """Clears diagnostic trouble codes according to a given mask.
        This is an implementation of the UDS request for service clearDiagnosticInformation (0x14).

        :param group_of_dtc: The three byte mask, which determines the DTCs to be cleared.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ClearDiagnosticInformationRequest(group_of_dtc), config
        )

    async def read_dtc_information_report_number_of_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReportNumberOfDTCByStatusMaskResponse:
        """Read the number of DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the reportNumberOfDTCByStatusMask
        sub-function of the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportNumberOfDTCByStatusMaskRequest(
                dtc_status_mask, suppress_response
            ),
            config,
        )

    async def read_dtc_information_report_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReportDTCByStatusMaskResponse:
        """Read DTCs and their state from the UDS server.
        This is an implementation of the UDS request for the reportDTCByStatusMask sub-function of
        the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
         response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportDTCByStatusMaskRequest(dtc_status_mask, suppress_response),
            config,
        )

    async def read_dtc_information_report_mirror_memory_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.ReportMirrorMemoryDTCByStatusMaskResponse):
        """Read DTCs and their state from the UDS server's mirror memory.
        This is an implementation of the UDS request for the reportMirrorMemoryDTCByStatusMask
        sub-function of the
        service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportMirrorMemoryDTCByStatusMaskRequest(
                dtc_status_mask, suppress_response
            ),
            config,
        )

    async def read_dtc_information_report_number_of_mirror_memory_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportNumberOfMirrorMemoryDTCByStatusMaskResponse
    ):
        """Read the number of DTCs with the specified state from the UDS server's mirror memory.
        This is an implementation of the UDS request for the
        reportNumberOfMirrorMemoryDTCByStatusMask sub-function of
        the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportNumberOfMirrorMemoryDTCByStatusMaskRequest(
                dtc_status_mask, suppress_response
            ),
            config,
        )

    async def read_dtc_information_report_number_of_emissions_related_obd_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskResponse
    ):
        """Read the number of emission related DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the
        reportNumberOfEmissionsRelatedOBDDTCByStatusMask sub-function of the service
        ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskRequest(
                dtc_status_mask, suppress_response
            ),
            config,
        )

    async def read_dtc_information_report_emissions_related_obd_dtc_by_status_mask(
        self,
        dtc_status_mask: int,
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportEmissionsRelatedOBDDTCByStatusMaskResponse
    ):
        """Read the number of emission related DTCs with the specified state from the UDS server.
        This is an implementation of the UDS request for the
        reportNumberOfEmissionsRelatedOBDDTCByStatusMask
        sub-function of the service ReadDTCInformation (0x19).

        :param dtc_status_mask: Used to select a portion of the DTCs based on their state.
        :param suppress_response: If set to True, the server is advised to not send back a positive
         response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReportEmissionsRelatedOBDDTCByStatusMaskRequest(
                dtc_status_mask, suppress_response
            ),
            config,
        )

    async def input_output_control_by_identifier(
        self,
        data_identifier: int,
        control_option_record: bytes,
        control_enable_mask_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
        """Controls input or output values on the server.
        This is an implementation of the UDS request for the service InputOutputControlByIdentifier
        (0x2F).
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
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        pdu = struct.pack(
            "!BH", UDSIsoServices.InputOutputControlByIdentifier, data_identifier
        )
        pdu += control_option_record + control_enable_mask_record
        return await self.request(
            service.InputOutputControlByIdentifierRequest(
                data_identifier, control_option_record, control_enable_mask_record
            ),
            config,
        )

    async def input_output_control_by_identifier_return_control_to_ecu(
        self,
        data_identifier: int,
        control_enable_mask_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
        """Gives the control over input / output parameters back to the ECU.
        This is a convenience wrapper for the generic input_output_control_by_id() for the case
        where an inputOutputControlParameter is used and is set to returnControlToECU.
        In that case no further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) for which control should be
                                returned to the ECU.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ReturnControlToECURequest(
                data_identifier, control_enable_mask_record
            ),
            config,
        )

    async def input_output_control_by_identifier_reset_to_default(
        self,
        data_identifier: int,
        control_enable_mask_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
        """Sets the input / output parameters to the default value(s).
        This is a convenience wrapper of the generic request for the case where an
        inputOutputControlParameter is used and is set to resetToDefault.
        In that case no further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) for which the values should be
                                reset.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ResetToDefaultRequest(data_identifier, control_enable_mask_record),
            config,
        )

    async def input_output_control_by_identifier_freeze_current_state(
        self,
        data_identifier: int,
        control_enable_mask_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
        """Freezes the input / output parameters at their current state.
        This is a convenience wrapper of the generic request for the case where an
        inputOutputControlParameter is used and is set to  freezeCurrentState.
        In that case no further controlState parameters can be submitted.

        :param data_identifier: The data identifier of the value(s) to be frozen.
        :param control_enable_mask_record: In cases where the dataIdentifier corresponds to multiple
                                           input / output parameters, this mask specifies which ones
                                           should be affected by this request.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.FreezeCurrentStateRequest(
                data_identifier, control_enable_mask_record
            ),
            config,
        )

    async def input_output_control_by_identifier_short_term_adjustment(
        self,
        data_identifier: int,
        control_states: bytes,
        control_enable_mask_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
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
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.ShortTermAdjustmentRequest(
                data_identifier, control_enable_mask_record
            ),
            config,
        )

    async def routine_control_start_routine(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.StartRoutineResponse:
        """Starts a specific routine on the server.
        This is an implementation of the UDS request for the startRoutine sub-function of the
        service routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.StartRoutineRequest(
                routine_identifier, routine_control_option_record, suppress_response
            ),
            config,
        )

    async def routine_control_stop_routine(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.StopRoutineResponse:
        """Stops a specific routine on the server.
        This is an implementation of the UDS request for the stopRoutine sub-function of the service
        routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.StopRoutineRequest(
                routine_identifier, routine_control_option_record, suppress_response
            ),
            config,
        )

    async def routine_control_request_routine_results(
        self,
        routine_identifier: int,
        routine_control_option_record: bytes = b"",
        suppress_response: bool = False,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestRoutineResultsResponse:
        """Requests the results of a specific routine on the server.
        This is an implementation of the UDS request for the requestRoutineResults sub-function of
        the service routineControl (0x31).

        :param routine_identifier: The identifier of the routine.
        :param routine_control_option_record: Optional data.
        :param suppress_response: If set to True, the server is advised to not send back a positive
                                  response.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.RequestRoutineResultsRequest(
                routine_identifier, routine_control_option_record, suppress_response
            ),
            config,
        )

    async def request_download(
        self,
        memory_address: int,
        memory_size: int,
        compression_method: int = 0x0,
        encryption_method: int = 0x0,
        address_and_length_format_identifier: int | None = None,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestDownloadResponse:
        """Requests the download of data, i.e. the possibility to send data from the client to the
        server.
        This is an implementation of the UDS request for requestDownload (0x34).

        :param memory_address: The address at which data should be downloaded.
        :param memory_size: The number of bytes to be downloaded.
        :param compression_method: Encodes the utilized compressionFormat (0x0 for none)
        :param encryption_method: Encodes the utilized encryptionFormat (0x0 for none)
        :param address_and_length_format_identifier: The byte lengths of the memory address and
                                                     size. If omitted, this parameter is computed
                                                     based on the memory_address and memory_size
                                                     parameters.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.RequestDownloadRequest(
                memory_address,
                memory_size,
                compression_method,
                encryption_method,
                address_and_length_format_identifier,
            ),
            config,
        )

    async def request_upload(
        self,
        memory_address: int,
        memory_size: int,
        compression_method: int = 0x0,
        encryption_method: int = 0x0,
        address_and_length_format_identifier: int | None = None,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestUploadResponse:
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
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.RequestUploadRequest(
                memory_address,
                memory_size,
                compression_method,
                encryption_method,
                address_and_length_format_identifier,
            ),
            config,
        )

    async def transfer_data(
        self,
        block_sequence_counter: int,
        transfer_request_parameter_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.TransferDataResponse:
        """Transfers data to the server or requests the next data from the server.
        This is an implementation of the UDS request for transferData (0x36).

        :param block_sequence_counter: The current block sequence counter.
                                       Initialized with one and incremented for each new data.
                                       After 0xff, the counter is resumed at 0
        :param transfer_request_parameter_record: Contains the data to be transferred if downloading
                                                  to the server.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.TransferDataRequest(
                block_sequence_counter, transfer_request_parameter_record
            ),
            config,
        )

    async def request_transfer_exit(
        self,
        transfer_request_parameter_record: bytes = b"",
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestTransferExitResponse:
        """Ends the transfer of data.
        This is an implementation of the UDS request for requestTransferExit (0x77).

        :param transfer_request_parameter_record: Optional data.
        :param config: Passed on to request_pdu().
        :return: The response of the server.
        """
        return await self.request(
            service.RequestTransferExitRequest(transfer_request_parameter_record),
            config,
        )

    @overload
    async def request(
        self, request: service.RawRequest, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.PositiveResponse:
        ...

    @overload
    async def request(
        self,
        request: service.DiagnosticSessionControlRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.DiagnosticSessionControlResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ECUResetRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ECUResetResponse:
        ...

    @overload
    async def request(
        self,
        request: service.RequestSeedRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.SecurityAccessResponse:
        ...

    @overload
    async def request(
        self, request: service.SendKeyRequest, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.SecurityAccessResponse:
        ...

    @overload
    async def request(
        self,
        request: service.CommunicationControlRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.CommunicationControlResponse:
        ...

    @overload
    async def request(
        self,
        request: service.TesterPresentRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.TesterPresentResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ControlDTCSettingRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ControlDTCSettingResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ReadDataByIdentifierRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReadDataByIdentifierResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ReadMemoryByAddressRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReadMemoryByAddressResponse:
        ...

    @overload
    async def request(
        self,
        request: service.WriteDataByIdentifierRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.WriteDataByIdentifierResponse:
        ...

    @overload
    async def request(
        self,
        request: service.WriteMemoryByAddressRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.WriteMemoryByAddressResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ClearDiagnosticInformationRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ClearDiagnosticInformationResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ReportNumberOfDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReportNumberOfDTCByStatusMaskResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ReportDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.ReportDTCByStatusMaskResponse:
        ...

    @overload
    async def request(
        self,
        request: service.ReportMirrorMemoryDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.ReportMirrorMemoryDTCByStatusMaskResponse):
        ...

    @overload
    async def request(
        self,
        request: service.ReportNumberOfMirrorMemoryDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportNumberOfMirrorMemoryDTCByStatusMaskResponse
    ):
        ...

    @overload
    async def request(
        self,
        request: service.ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportNumberOfEmissionsRelatedOBDDTCByStatusMaskResponse
    ):
        ...

    @overload
    async def request(
        self,
        request: service.ReportEmissionsRelatedOBDDTCByStatusMaskRequest,
        config: UDSRequestConfig | None = None,
    ) -> (
        service.NegativeResponse
        | service.ReportEmissionsRelatedOBDDTCByStatusMaskResponse
    ):
        ...

    @overload
    async def request(
        self,
        request: service.InputOutputControlByIdentifierRequest,
        config: UDSRequestConfig | None = None,
    ) -> (service.NegativeResponse | service.InputOutputControlByIdentifierResponse):
        ...

    @overload
    async def request(
        self,
        request: service.StartRoutineRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.StartRoutineResponse:
        ...

    @overload
    async def request(
        self,
        request: service.StopRoutineRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.StopRoutineResponse:
        ...

    @overload
    async def request(
        self,
        request: service.RequestRoutineResultsRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestRoutineResultsResponse:
        ...

    @overload
    async def request(
        self,
        request: service.RequestDownloadRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestDownloadResponse:
        ...

    @overload
    async def request(
        self,
        request: service.RequestUploadRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestUploadResponse:
        ...

    @overload
    async def request(
        self,
        request: service.TransferDataRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.TransferDataResponse:
        ...

    @overload
    async def request(
        self,
        request: service.RequestTransferExitRequest,
        config: UDSRequestConfig | None = None,
    ) -> service.NegativeResponse | service.RequestTransferExitResponse:
        ...

    async def request(
        self, request: service.UDSRequest, config: UDSRequestConfig | None = None
    ) -> service.UDSResponse:
        """Sends a raw UDS request and returns the response.
        Network errors are handled via exponential backoff.
        Pending errors, triggered by the ECU are resolved as well.

        :param request: request to send
        :param config: The request config parameters
        :return: The response.
        """
        return await self._request(request, config)

    async def _request(
        self, request: service.UDSRequest, config: UDSRequestConfig | None = None
    ) -> service.UDSResponse:
        async with self.mutex:
            return await self.request_unsafe(request, config)
