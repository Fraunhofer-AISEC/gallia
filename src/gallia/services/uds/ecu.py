# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from asyncio import Task
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gallia.db.log import LogMode
from gallia.log import get_logger
from gallia.powersupply import PowerSupply
from gallia.services.uds.core import service
from gallia.services.uds.core.client import UDSClient, UDSRequestConfig
from gallia.services.uds.core.constants import DataIdentifier
from gallia.services.uds.core.exception import (
    ResponseException,
    UDSException,
    UnexpectedNegativeResponse,
)
from gallia.services.uds.core.utils import from_bytes, g_repr
from gallia.services.uds.helpers import (
    as_exception,
    raise_for_error,
    suggests_identifier_not_supported,
)
from gallia.transports.base import BaseTransport

if TYPE_CHECKING:
    from gallia.db.handler import DBHandler


class ECUState:
    def __init__(self) -> None:
        self.session = 1
        self.security_access_level: int | None = None

    def reset(self) -> None:
        self.session = 1
        self.security_access_level = None

    def __repr__(self) -> str:
        return f'{type(self).__name__}({", ".join(f"{key}={g_repr(value)}" for key, value in self.__dict__.items())})'


class ECU(UDSClient):
    """ECU is a high level interface wrapping a UDSClient class. It provides
    semantically correct higher level interfaces such as read_session()
    or ping(). Vendor specific implementations can be derived from this
    class. For the arguments of the constructor, please check uds.uds.UDS.
    """

    OEM = "default"

    def __init__(
        self,
        transport: BaseTransport,
        timeout: float,
        max_retry: int = 1,
        power_supply: PowerSupply | None = None,
    ) -> None:

        super().__init__(transport, timeout, max_retry)
        self.logger = get_logger("ecu")
        self.tester_present_task: Task[None] | None = None
        self.tester_present_interval: float | None = None
        self.power_supply = power_supply
        self.state = ECUState()
        self.db_handler: DBHandler | None = None
        self.implicit_logging = True

    async def connect(self) -> None:
        ...

    async def properties(
        self, fresh: bool = False, config: UDSRequestConfig | None = None
    ) -> dict[str, Any]:
        return {}

    async def ping(
        self, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.TesterPresentResponse:
        """Send an UDS TesterPresent message.

        Returns:
            UDS response.
        """
        return await self.tester_present(suppress_response=False, config=config)

    async def read_session(self, config: UDSRequestConfig | None = None) -> int:
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
        self, level: int, config: UDSRequestConfig | None = None
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
        self, level: int, config: UDSRequestConfig | None = None
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

        self.logger.debug(
            f"Checking current session, expecting {g_repr(expected_session)}"
        )

        try:
            current_session = await self.read_session(
                config=UDSRequestConfig(max_retry=retries)
            )
        except UnexpectedNegativeResponse as e:
            if suggests_identifier_not_supported(e.RESPONSE_CODE):
                self.logger.info(
                    f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                )
                return True
            raise e
        except asyncio.TimeoutError:
            self.logger.warning(
                "Reading current session timed out, skipping check_session"
            )
            return True

        self.logger.debug(f"Current session is {g_repr(current_session)}")
        if current_session == expected_session:
            return True

        for i in range(retries):
            self.logger.warning(
                f"Not in session {g_repr(expected_session)}, ECU replied with {g_repr(current_session)}"
            )

            self.logger.info(
                f"Switching to session {g_repr(expected_session)}; attempt {i + 1} of {retries}"
            )
            resp = await self.set_session(expected_session)

            if isinstance(resp, service.NegativeResponse):
                self.logger.warning(
                    f"Switching to session {g_repr(expected_session)} failed: {resp}"
                )

            try:
                current_session = await self.read_session(
                    config=UDSRequestConfig(max_retry=retries)
                )
                self.logger.debug(f"Current session is {g_repr(current_session)}")
                if current_session == expected_session:
                    return True
            except UnexpectedNegativeResponse as e:
                if suggests_identifier_not_supported(e.RESPONSE_CODE):
                    self.logger.info(
                        f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                    )
                    return True
                raise e
            except asyncio.TimeoutError:
                self.logger.warning(
                    "Reading current session timed out, skipping check_session"
                )
                return True

        self.logger.warning(
            f"Failed to switch to session {g_repr(expected_session)} after {retries} attempts"
        )
        return False

    async def power_cycle(self, sleep: int = 5) -> bool:
        if self.power_supply is None:
            self.logger.debug("no power_supply available")
            return False

        async def callback() -> None:
            await self.wait_for_ecu()

        await self.power_supply.power_cycle(sleep, callback)
        return True

    async def leave_session(
        self, level: int, config: UDSRequestConfig | None = None
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
        resp: service.UDSResponse = await self.ecu_reset(0x01)
        if isinstance(resp, service.NegativeResponse):
            await self.power_cycle()
        else:
            await self.wait_for_ecu()

        resp = await self.set_session(0x01, config=config)
        if isinstance(resp, service.NegativeResponse):
            await self.power_cycle()
            await self.reconnect()
        return True

    async def find_sessions(self, search: list[int], max_retry: int = 4) -> list[int]:
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
        self,
        level: int,
        config: UDSRequestConfig | None = None,
        use_db: bool = True,
    ) -> service.NegativeResponse | service.DiagnosticSessionControlResponse:
        config = config if config is not None else UDSRequestConfig()

        if not config.skip_hooks:
            await self.set_session_pre(level, config=config)

        resp = await self.diagnostic_session_control(level, config=config)

        if (
            isinstance(resp, service.NegativeResponse)
            and self.db_handler is not None
            and use_db
        ):
            self.logger.debug(
                "Could not switch to session. Trying with database transitions ..."
            )

            if self.db_handler is not None:
                steps = await self.db_handler.get_session_transition(level)

                self.logger.debug(f"Found the following steps in database: {steps}")

                if steps is not None:
                    for step in steps:
                        await self.set_session(step, use_db=False)

                    resp = await self.diagnostic_session_control(level, config=config)

        if not isinstance(resp, service.NegativeResponse) and not config.skip_hooks:
            await self.set_session_post(level, config=config)

        return resp

    async def read_dtc(
        self, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.ReportDTCByStatusMaskResponse:
        """Read all dtc records from the ecu."""
        return await self.read_dtc_information_report_dtc_by_status_mask(
            0xFF, config=config
        )

    async def clear_dtc(
        self, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.ClearDiagnosticInformationResponse:
        """Clear all dtc records on the ecu."""
        return await self.clear_diagnostic_information(0xFFFFFF, config=config)

    async def read_vin(
        self, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.ReadDataByIdentifierResponse:
        """Read the VIN of the vehicle"""
        return await self.read_data_by_identifier(0xF190, config=config)

    async def transmit_data(
        self,
        data: bytes,
        block_length: int,
        max_block_length: int = 0xFFF,
        config: UDSRequestConfig | None = None,
    ) -> None:
        """transmit_data splits the data to be sent in several blocks of size block_length,
        transfers all of them and concludes the transmission with RequestTransferExit"""
        if block_length > max_block_length:
            self.logger.warning(f"Limiting block size to {g_repr(max_block_length)}")
            block_length = max_block_length
        # block_length includes the service identifier and block counter; payload must be smaller
        payload_size = block_length - 2
        counter = 0
        for i in range(0, len(data), payload_size):
            counter += 1
            payload = data[i : i + payload_size]
            self.logger.debug(
                f"Transferring block {g_repr(counter)} "
                f"with payload size {g_repr(len(payload))}"
            )
            resp: service.UDSResponse = await self.transfer_data(
                counter & 0xFF, payload, config=config
            )
            raise_for_error(resp, f"Transmitting data failed at index {g_repr(i)}")
        resp = await self.request_transfer_exit(config=config)
        raise_for_error(resp)

    async def _wait_for_ecu(self, sleep_time: float) -> None:
        """wait for ecu to be alive again (eg. after reset)
        Internal method without timeout"""
        self.logger.info("waiting for ECU…")
        while True:
            try:
                await asyncio.sleep(sleep_time)
                await self.ping()
                break
            except (ConnectionError, UDSException) as e:
                self.logger.debug(f"ECU not ready: {e!r}")
                await self.reconnect()
        self.logger.info("ECU ready")

    async def wait_for_ecu(
        self,
        timeout: float | None = None,
    ) -> bool:
        """wait for ecu to be alive again (eg. after reset)
        Wait at most timeout"""
        if self.tester_present_task and self.tester_present_interval:
            await self.stop_cyclic_tester_present()

        t = timeout if timeout is not None else self.timeout
        try:
            await asyncio.wait_for(self._wait_for_ecu(t * 0.8), timeout=t)
            return True
        except asyncio.TimeoutError:
            self.logger.critical("Timeout while waiting for ECU!")
            return False
        finally:
            if self.tester_present_task and self.tester_present_interval:
                await self.start_cyclic_tester_present(self.tester_present_interval)

    async def _tester_present_worker(self, interval: float) -> None:
        assert self.transport
        self.logger.debug("tester present worker started")
        while True:
            try:
                async with self.mutex:
                    payload = bytes([0x3E, 0x80])
                    await self.transport.write(payload)
                    self.logger.debug(payload.hex(), extra={"tags": ["write", "uds"]})

                    # Hold the mutex for 10 ms to synchronize this background
                    # worker with the main sender task.
                    await asyncio.sleep(0.01)

                    # The BCP might send us an error. Everything
                    # will break if we do not read it back. Since
                    # this read() call is only intended to flush
                    # errors caused by the previous write(), it is
                    # sane to ignore the error here.
                    try:
                        await self.transport.read(timeout=0.01)
                    except asyncio.TimeoutError:
                        pass
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                self.logger.debug("tester present worker terminated")
                break
            except ConnectionError:
                self.logger.info("connection lost; reconnecting")
                await self.reconnect()
            except Exception as e:
                self.logger.debug(f"tester present got {e!r}")

    async def start_cyclic_tester_present(self, interval: float) -> None:
        self.tester_present_interval = interval
        coroutine = self._tester_present_worker(interval)
        self.tester_present_task = asyncio.create_task(coroutine)

        # enforce context switch
        # this ensures, that the task is executed at least once
        # if the task is not executed, task.cancel will fail with CancelledError
        await asyncio.sleep(0)

    async def stop_cyclic_tester_present(self) -> None:
        if self.tester_present_task is None:
            self.logger.warning(
                "BUG: stop_cyclic_tester_present() called but no task running"
            )
            return

        self.tester_present_task.cancel()
        await self.tester_present_task

    async def update_state(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> None:
        if isinstance(response, service.DiagnosticSessionControlResponse):
            self.state.reset()
            self.state.session = response.diagnostic_session_type

        if (
            isinstance(response, service.ReadDataByIdentifierResponse)
            and response.data_identifier
            == DataIdentifier.ActiveDiagnosticSessionDataIdentifier
        ):
            new_session = int.from_bytes(response.data_record, "big")

            if self.state.session != new_session:
                self.state.reset()
                self.state.session = new_session

        if (
            isinstance(response, service.SecurityAccessResponse)
            and response.security_access_type % 2 == 0
        ):
            self.state.security_access_level = response.security_access_type - 1

        if isinstance(response, service.ECUResetResponse):
            self.state.reset()

    async def refresh_state(self, reset_state: bool = False) -> None:
        """
        Refresh the attributes of the ECU states, if possible.
        By, default, old values are only overwritten in case the corresponding
        information can be requested from the ECU and could be retrieved from a
        positive response from the ECU.

        :param reset_state: If True, the ECU state is reset before updating it.
        """
        if reset_state:
            self.state.reset()

        await self.read_session()

    async def _request(
        self, request: service.UDSRequest, config: UDSRequestConfig | None = None
    ) -> service.UDSResponse:
        """Sends a raw UDS request and returns the response.
        Network errors are handled via exponential backoff.
        Pending errors, triggered by the ECU are resolved as well.

        :param request: request to send
        :param config: The request config parameters
        :return: The response.
        """
        response = None
        exception: Exception | None = None
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
                if self.implicit_logging and self.db_handler is not None:
                    mode = LogMode.implicit

                    if (
                        config is not None
                        and config.tags is not None
                        and "ANALYZE" in config.tags
                    ):
                        mode = LogMode.emphasized

                    await self.db_handler.insert_scan_result(
                        self.state.__dict__,
                        service.UDSRequest.parse_dynamic(request.pdu),
                        response,
                        exception,
                        send_time,
                        receive_time,
                        mode,
                    )
            except Exception as e:
                self.logger.warning(f"Could not log messages to database: {g_repr(e)}")

            if response is not None:
                await self.update_state(request, response)
