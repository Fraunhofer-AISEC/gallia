# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional, Union

from gallia.db.db_handler import DBHandler, LogMode
from gallia.penlab import PowerSupply
from gallia.penlog import Logger
from gallia.transports.base import BaseTransport
from gallia.uds.core import service
from gallia.uds.core.client import UDSClient, UDSRequestConfig
from gallia.uds.core.constants import DataIdentifier
from gallia.uds.core.exception import ResponseException, UnexpectedNegativeResponse
from gallia.uds.core.utils import from_bytes
from gallia.uds.helpers import (
    as_exception,
    raise_for_error,
    suggests_identifier_not_supported,
)
from gallia.utils import g_repr


class ECUState:
    def __init__(self) -> None:
        self.session = 1
        self.security_access_level: Optional[int] = None

    def reset(self) -> None:
        self.session = 1
        self.security_access_level = None

    def __repr__(self) -> str:
        return f'{self.__class__.__name__}({", ".join(f"{key}={repr(value)}" for key, value in self.__dict__.items())})'


class ECU(UDSClient):
    """ECU is a high level interface wrapping a UDSClient class. It provides
    semantically correct higher level interfaces such as read_session()
    or ping(). Vendor specific implementations can be derived from this
    class. For the arguments of the constructor, please check uds.uds.UDS.
    """

    def __init__(
        self,
        transport: BaseTransport,
        timeout: Optional[float] = None,
        max_retry: int = 1,
        power_supply: Optional[PowerSupply] = None,
    ) -> None:

        super().__init__(transport, timeout, max_retry)
        self.logger = Logger(component="ecu", flush=True)
        self.power_supply = power_supply
        self.state = ECUState()
        self.db_handler: Optional[DBHandler] = None

    async def connect(self) -> None:
        ...

    async def properties(
        self, fresh: bool = False, config: Optional[UDSRequestConfig] = None
    ) -> dict:
        return {}

    async def ping(
        self, config: Optional[UDSRequestConfig] = None
    ) -> Union[service.NegativeResponse, service.TesterPresentResponse]:
        """Send an UDS TesterPresent message.

        Returns:
            UDS response.
        """
        return await self.tester_present(suppress_response=False, config=config)

    async def read_session(self, config: Optional[UDSRequestConfig] = None) -> int:
        """Read out current session.

        Returns:
            The current session as int.
        """
        resp = await self.read_data_by_identifier(
            DataIdentifier.ActiveDiagnosticSessionDataIdentifier, config=config
        )
        if isinstance(resp, service.NegativeResponse):
            raise as_exception(resp)
        return from_bytes(resp.data_record)

    async def set_session_pre(
        self, level: int, config: Optional[UDSRequestConfig] = None
    ) -> bool:
        """set_session_pre() is called before the diagnostic session control
        pdu is written on the wire. Implement this if there are special
        preconditions for a particular session, such as disabling error
        logging.

        Args:
            uds: The UDSClient class where this hook is embedded. The caller typically
                 calls this function with `self` as the first argument.
            session: The desired session identifier.
        Returns:
            True on success, False on error.
        """

    async def set_session_post(
        self, level: int, config: Optional[UDSRequestConfig] = None
    ) -> bool:
        """set_session_post() is called after the diagnostic session control
        pdu was written on the wire. Implement this if there are special
        cleanup routines or sleeping until a certain moment is required.

        Args:
            uds: The UDSClient class where this hook is embedded. The caller typically
                 calls this function with `self` as the first argument.
            session: The desired session identifier.
        Returns:
            True on success, False on error.
        """

    async def check_and_set_session(
        self,
        expected_session: int,
        retries: int = 3,
    ) -> bool:
        """check_and_set_session() reads the current session and (re)tries to set
        the session to the expected session if they do not match.

        Returns True if the current session matches the expected session,
        or if read_session is not supported by the ECU or in the current session."""

        self.logger.log_debug(
            f"Checking current session, expecting {g_repr(expected_session)}"
        )

        try:
            current_session = await self.read_session(
                config=UDSRequestConfig(max_retry=retries)
            )
        except UnexpectedNegativeResponse as e:
            if suggests_identifier_not_supported(e.RESPONSE_CODE):
                self.logger.log_info(
                    f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                )
                return True
            raise e
        except asyncio.TimeoutError:
            self.logger.log_warning(
                "Reading current session timed out, skipping check_session"
            )
            return True

        self.logger.log_debug(f"Current session is {g_repr(current_session)}")
        if current_session == expected_session:
            return True

        for i in range(retries):
            self.logger.log_warning(
                f"Not in session {g_repr(expected_session)}, ECU replied with {g_repr(current_session)}"
            )

            self.logger.log_info(
                f"Switching to session {g_repr(expected_session)}; attempt {i + 1} of {retries}"
            )
            resp = await self.set_session(expected_session)

            if isinstance(resp, service.NegativeResponse):
                self.logger.log_warning(
                    f"Switching to session {g_repr(expected_session)} failed: {resp}"
                )

            try:
                current_session = await self.read_session(
                    config=UDSRequestConfig(max_retry=retries)
                )
                self.logger.log_debug(f"Current session is {g_repr(current_session)}")
                if current_session == expected_session:
                    return True
            except UnexpectedNegativeResponse as e:
                if suggests_identifier_not_supported(e.RESPONSE_CODE):
                    self.logger.log_info(
                        f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                    )
                    return True
                raise e
            except asyncio.TimeoutError:
                self.logger.log_warning(
                    "Reading current session timed out, skipping check_session"
                )
                return True

        self.logger.log_warning(
            f"Failed to switch to session {g_repr(expected_session)} after {retries} attempts"
        )
        return False

    async def power_cycle(self, sleep: int = 5) -> bool:
        if self.power_supply is None:
            self.logger.log_warning("no power_supply available")
            return False

        await self.power_supply.power_cycle(sleep, self.wait_for_ecu)
        return True

    async def leave_session(
        self, level: int, config: Optional[UDSRequestConfig] = None
    ) -> bool:
        """leave_session() is a hook which can be called explicitly by a
        scanner when a session is to be disabled. Use this hook if resetting
        the ECU is required, e.g. when disabling the programming session.

        Args:
            uds: The UDSClient class where this hook is embedded. The caller typically
                 calls this function with `self` as the first argument.
            session: The desired session identifier.
        Returns:
            True on success, False on error.
        """
        resp = await self.ecu_reset(0x01)
        if isinstance(resp, service.NegativeResponse):
            await self.power_cycle()
        else:
            await self.wait_for_ecu()

        resp = await self.set_session(0x01, config=config)
        if isinstance(resp, service.NegativeResponse):
            return await self.power_cycle()
        return True

    async def find_sessions(self, search: list, max_retry: int = 4) -> list[int]:
        sessions = []
        for sid in search:
            try:
                resp = await self.set_session(
                    sid, config=UDSRequestConfig(max_retry=max_retry)
                )
                if isinstance(resp, service.NegativeResponse):
                    continue
            except Exception:
                continue
            sessions.append(sid)
            await self.leave_session(sid)
        return sessions

    async def set_session(
        self, level: int, config: Optional[UDSRequestConfig] = None
    ) -> Union[service.NegativeResponse, service.DiagnosticSessionControlResponse]:
        config = config if config is not None else UDSRequestConfig()

        if not config.skip_hooks:
            await self.set_session_pre(level, config=config)

        resp = await self.diagnostic_session_control(level, config=config)

        if not isinstance(resp, service.NegativeResponse) and not config.skip_hooks:
            await self.set_session_post(level, config=config)

        return resp

    async def read_dtc(
        self, config: Optional[UDSRequestConfig] = None
    ) -> Union[service.NegativeResponse, service.ReportDTCByStatusMaskResponse]:
        """Read all dtc records from the ecu."""
        return await self.read_dtc_information_report_dtc_by_status_mask(
            0xFF, config=config
        )

    async def clear_dtc(
        self, config: Optional[UDSRequestConfig] = None
    ) -> Union[service.NegativeResponse, service.ClearDiagnosticInformationResponse]:
        """Clear all dtc records on the ecu."""
        return await self.clear_diagnostic_information(0xFFFFFF, config=config)

    async def read_vin(
        self, config: Optional[UDSRequestConfig] = None
    ) -> Union[service.NegativeResponse, service.ReadDataByIdentifierResponse]:
        """Read the VIN of the vehicle"""
        return await self.read_data_by_identifier(0xF190, config=config)

    async def transmit_data(
        self,
        data: bytes,
        block_length: int,
        max_block_length: int = 0xFFF,
        config: Optional[UDSRequestConfig] = None,
    ) -> None:
        """transmit_data splits the data to be sent in several blocks of size block_length,
        transfers all of them and concludes the transmission with RequestTransferExit"""
        if block_length > max_block_length:
            self.logger.log_warning(
                f"Limiting block size to {g_repr(max_block_length)}"
            )
            block_length = max_block_length
        # block_length includes the service identifier and block counter; payload must be smaller
        payload_size = block_length - 2
        counter = 0
        for i in range(0, len(data), payload_size):
            counter += 1
            payload = data[i : i + payload_size]
            self.logger.log_debug(
                f"Transferring block {g_repr(counter)} "
                f"with payload size {g_repr(len(payload))}"
            )
            resp: service.UDSResponse = await self.transfer_data(
                counter & 0xFF, payload, config=config
            )
            raise_for_error(resp, f"Transmitting data failed at index {g_repr(i)}")
        resp = await self.request_transfer_exit(config=config)
        raise_for_error(resp)

    async def wait_for_ecu(self, timeout: float = 60) -> bool:
        """wait for ecu to be alive again (eg. after reset)
        Wait at most timeout"""
        ret = False
        try:
            await asyncio.wait_for(self._wait_for_ecu(), timeout=timeout)
            ret = True
        except asyncio.TimeoutError:
            self.logger.log_critical("Timeout while waiting for ECU!")
        return ret

    async def _wait_for_ecu(self) -> None:
        """wait for ecu to be alive again (eg. after reset)
        Internal method without timeout"""
        self.logger.log_info("waiting for ECU…")
        while True:
            try:
                await asyncio.sleep(1)
                await self.reconnect()
                await self.ping()
                break
            # If the network is down or anything else is broken,
            # then an OSError is raised. Raise this kind of errors.
            except OSError:
                raise
            except Exception as e:
                self.logger.log_debug(f"ECU not ready: {g_repr(e)}")
        self.logger.log_info("ECU ready")

    async def update_state(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> None:
        if isinstance(response, service.DiagnosticSessionControlResponse):
            self.state.session = response.diagnostic_session_type

        if (
            isinstance(response, service.ReadDataByIdentifierResponse)
            and response.data_identifier
            == DataIdentifier.ActiveDiagnosticSessionDataIdentifier
        ):
            self.state.session = int.from_bytes(response.data_record, "big")

        if isinstance(response, service.SecurityAccessResponse):
            self.state.security_access_level = response.security_access_type - 1

        if isinstance(response, service.ECUResetResponse):
            self.state.reset()

    async def _request(
        self, request: service.UDSRequest, config: Optional[UDSRequestConfig] = None
    ) -> service.UDSResponse:
        """Sends a raw UDS request and returns the response.
        Network errors are handled via exponential backoff.
        Pending errors, triggered by the ECU are resolved as well.

        :param request: request to send
        :param config: The request config parameters
        :return: The response.
        """
        response = None
        exception: Optional[Exception] = None
        send_time = datetime.now(timezone.utc).astimezone()
        receive_time = None

        try:
            response = await super()._request(request, config)
            receive_time = datetime.now(timezone.utc).astimezone()
            return response
        except ResponseException as e:
            exception = e
            response = e.response
            raise
        except Exception as e:
            exception = e
            raise
        finally:
            try:
                if self.db_handler is not None:
                    log_mode = LogMode.implicit

                    if (
                        config is not None
                        and config.tags is not None
                        and "ANALYZE" in config.tags
                    ):
                        log_mode = LogMode.emphasized

                    await self.db_handler.insert_scan_result(
                        self.state.__dict__,
                        service.UDSRequest.parse_dynamic(request.pdu),
                        response,
                        exception,
                        send_time,
                        receive_time,
                        log_mode,
                    )
            except Exception as e:
                self.logger.log_warning(
                    f"Could not log messages to database: {g_repr(e)}"
                )

            if response is not None:
                await self.update_state(request, response)
