# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from json import JSONEncoder, dumps
from typing import TYPE_CHECKING, Any

from gallia.db.log import LogMode
from gallia.log import get_logger
from gallia.power_supply import PowerSupply
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
from gallia.utils import handle_task_error, set_task_handler_ctx_variable

if TYPE_CHECKING:
    from gallia.db.handler import DBHandler

logger = get_logger(__name__)


@dataclass
class ECUState:
    session: int | None = None
    security_access_level: int | None = None

    def reset(self) -> None:
        self.session = None
        self.security_access_level = None

    def to_json(self, indent: int | str | None = None) -> str:
        return dumps(asdict(self), indent=indent, sort_keys=True, cls=self.json_encoder)

    @property
    def json_encoder(self) -> type[JSONEncoder]:
        return GalliaJSONEncoder

    def __repr__(self) -> str:
        return f"{type(self).__name__}({', '.join(f'{key}={g_repr(value)}' for key, value in self.__dict__.items())})"


@dataclass
class ECUProperties:
    def to_json(self, indent: int | str | None = None) -> str:
        # Make sure to keep 'sort_keys=True' when overriding this method!
        return dumps(asdict(self), indent=indent, sort_keys=True, cls=self.json_encoder)

    @property
    def json_encoder(self) -> type[JSONEncoder]:
        return GalliaJSONEncoder


class GalliaJSONEncoder(JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, bytes):
            return o.hex()
        elif isinstance(o, Enum):
            return o.value

        return super().default(o)


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
        max_retry: int = 0,
        power_supply: PowerSupply | None = None,
    ) -> None:
        super().__init__(transport, timeout, max_retry)
        self.tester_present_task: TesterPresentSender | None = None
        self.power_supply = power_supply
        self.state = ECUState()
        self.db_handler: DBHandler | None = None
        self.implicit_logging = True

    async def properties(
        self, fresh: bool = False, config: UDSRequestConfig | None = None
    ) -> ECUProperties:
        return ECUProperties()

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

    async def set_session_pre(self, session: int, config: UDSRequestConfig | None = None) -> bool:
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
        return True

    async def set_session_post(self, session: int, config: UDSRequestConfig | None = None) -> bool:
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
        return True

    async def check_and_set_session(
        self,
        expected_session: int,
        retries: int = 3,
    ) -> bool:
        """check_and_set_session() reads the current session and (re)tries to set
        the session to the expected session if they do not match.

        Returns True if the current session matches the expected session,
        or if read_session is not supported by the ECU or in the current session."""

        logger.debug(f"Checking current session, expecting {g_repr(expected_session)}")

        try:
            current_session = await self.read_session(config=UDSRequestConfig(max_retry=retries))
        except UnexpectedNegativeResponse as e:
            if suggests_identifier_not_supported(e.RESPONSE_CODE):
                logger.info(
                    f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                )
                return True
            raise e
        except TimeoutError:
            logger.warning("Reading current session timed out, skipping check_session")
            return True

        logger.debug(f"Current session is {g_repr(current_session)}")
        if current_session == expected_session:
            return True

        for i in range(retries + 1):
            logger.warning(
                f"Not in session {g_repr(expected_session)}, ECU replied with {g_repr(current_session)}"
            )

            logger.info(
                f"Switching to session {g_repr(expected_session)}; attempt {i + 1} of {retries}"
            )
            resp = await self.set_session(expected_session)

            if isinstance(resp, service.NegativeResponse):
                logger.warning(f"Switching to session {g_repr(expected_session)} failed: {resp}")

            try:
                current_session = await self.read_session(
                    config=UDSRequestConfig(max_retry=retries)
                )
                logger.debug(f"Current session is {g_repr(current_session)}")
                if current_session == expected_session:
                    return True
            except UnexpectedNegativeResponse as e:
                if suggests_identifier_not_supported(e.RESPONSE_CODE):
                    logger.info(
                        f"Read current session not supported: {e.RESPONSE_CODE.name}, skipping check_session"
                    )
                    return True
                raise e
            except TimeoutError:
                logger.warning("Reading current session timed out, skipping check_session")
                return True

        logger.warning(
            f"Failed to switch to session {g_repr(expected_session)} after {retries} attempts"
        )
        return False

    async def power_cycle(self, sleep: float = 5) -> bool:
        """
        Perform a power cycle and wait for the ECU to recover.

        Returns `False` on Error, and `True` if power cycle was successful or there is no power supply.
        """
        if self.power_supply is None:
            logger.debug("no power_supply available")
            return True

        # Hold mutex to prevent requests from being made during a power cycle
        async with self.mutex:
            await self.power_supply.power_cycle(sleep)
            self.state.reset()

        return await self.wait_for_ecu()

    async def leave_session(
        self,
        session: int,
        config: UDSRequestConfig | None = None,
        sleep: float | None = None,
    ) -> bool:
        """leave_session() is a hook which can be called explicitly by a
        scanner when a session is to be disabled. Use this hook if resetting
        the ECU is required, e.g. when disabling the programming session.
        """
        resp: service.UDSResponse = await self.ecu_reset(0x01)
        if isinstance(resp, service.NegativeResponse):
            if sleep is not None:
                await self.power_cycle(sleep=sleep)
            else:
                await self.power_cycle()
        await self.wait_for_ecu()

        resp = await self.set_session(0x01, config=config)
        if isinstance(resp, service.NegativeResponse):
            if sleep is not None:
                await self.power_cycle(sleep=sleep)
            else:
                await self.power_cycle()
        return True

    async def set_session(
        self,
        session: int,
        config: UDSRequestConfig | None = None,
        use_db: bool = True,
    ) -> service.NegativeResponse | service.DiagnosticSessionControlResponse:
        config = config if config is not None else UDSRequestConfig()

        if not config.skip_hooks:
            await self.set_session_pre(session, config=config)

        resp = await self.diagnostic_session_control(session, config=config)

        if isinstance(resp, service.NegativeResponse) and self.db_handler is not None and use_db:
            logger.debug("Could not switch to session. Trying with database transitions ...")

            if self.db_handler is not None:
                steps = await self.db_handler.get_session_transition(session)

                logger.debug(f"Found the following steps in database: {steps}")

                if steps is not None:
                    for step in steps:
                        await self.set_session(step, use_db=False)

                    resp = await self.diagnostic_session_control(session, config=config)

        if not isinstance(resp, service.NegativeResponse) and not config.skip_hooks:
            await self.set_session_post(session, config=config)

        return resp

    async def read_dtc(
        self, config: UDSRequestConfig | None = None
    ) -> service.NegativeResponse | service.ReportDTCByStatusMaskResponse:
        """Read all dtc records from the ecu."""
        return await self.read_dtc_information_report_dtc_by_status_mask(0xFF, config=config)

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
            logger.warning(f"Limiting block size to {g_repr(max_block_length)}")
            block_length = max_block_length
        # block_length includes the service identifier and block counter; payload must be smaller
        payload_size = block_length - 2
        counter = 0
        for i in range(0, len(data), payload_size):
            counter += 1
            payload = data[i : i + payload_size]
            logger.debug(
                f"Transferring block {g_repr(counter)} with payload size {g_repr(len(payload))}"
            )
            resp: service.UDSResponse = await self.transfer_data(
                counter & 0xFF, payload, config=config
            )
            raise_for_error(resp, f"Transmitting data failed at index {g_repr(i)}")
        resp = await self.request_transfer_exit(config=config)
        raise_for_error(resp)

    async def _wait_for_ecu_endless_loop(self, sleep_time: float) -> None:
        """Internal method with endless loop in case of no answer from ECU"""
        config = UDSRequestConfig(timeout=0.5, max_retry=0, skip_hooks=True)
        i = -1
        while True:
            i = (i + 1) % 4
            logger.info(f"Waiting for ECU{'.' * i}")
            try:
                await asyncio.sleep(sleep_time)
                await self.tester_present(suppress_response=False, config=config)
                break
            # When the ECU is not ready, we expect an UDSException, e.g. MissingResponse.
            # On ConnectionError, we additionally reconnect the transport to ensure connectivity.
            # Since Gallia converts a ConnectionError to a MissingResponse in `request_unsafe`, however,
            # there is a need to reconnect the transport also in case of high-level UDSExceptions
            # such as MissingResponses that are raised (__cause__) from ConnectionErrors.
            except (ConnectionError, UDSException) as e:
                logger.debug(f"ECU not ready: {e!r}")
                if isinstance(e, ConnectionError) or isinstance(e.__cause__, ConnectionError):
                    logger.debug("Reconnecting…")
                    await self.reconnect()
        logger.info("ECU ready")

    async def wait_for_ecu(
        self,
        timeout: float | None = 10,
    ) -> bool:
        """Wait for ecu to be alive again (e.g. after reset).
        Sends a ping every 0.5s and waits at most timeout.
        If timeout is None, wait endlessly"""
        logger.info(f"Waiting for {timeout}s for ECU to respond")
        if self.tester_present_task is not None:
            await self.tester_present_task.stop()

        try:
            await asyncio.wait_for(self._wait_for_ecu_endless_loop(0.5), timeout=timeout)
            return True
        except TimeoutError:
            logger.critical("Timeout while waiting for ECU!")
            return False
        finally:
            if self.tester_present_task is not None:
                await self.tester_present_task.start()

    async def _send_tester_present(self) -> None:
        try:
            await self.tester_present(config=UDSRequestConfig(max_retry=0, tags=["tp"]))
        except ConnectionError:
            logger.info("connection lost; tester present waiting…")
        except Exception as e:
            logger.warning(f"Tester present worker got {e!r}")

    async def attach_tester_present_sender(
        self,
        interval: float,
        ignore_activity: bool = False,
        task_timeout: float = 1,
    ) -> None:
        logger.debug("Attaching TesterPresentSender")

        if self.tester_present_task is None:
            self.tester_present_task = TesterPresentSender(
                interval,
                lambda: self._send_tester_present(timeout=task_timeout),
                oneshot=False,
                ignore_activity=ignore_activity,
            )

        await self.tester_present_task.start()

    async def detach_tester_present_sender(self) -> None:
        logger.debug("Detaching TesterPresentSender")

        if self.tester_present_task is None:
            logger.warning("Attempted to detach TesterPresentSender, but it is already gone!")
            return

        await self.tester_present_task.stop()
        self.tester_present_task = None

    async def update_state(
        self, request: service.UDSRequest, response: service.UDSResponse
    ) -> None:
        if isinstance(response, service.DiagnosticSessionControlResponse):
            self.state.reset()
            self.state.session = response.diagnostic_session_type

        if (
            isinstance(response, service.ReadDataByIdentifierResponse)
            and response.data_identifier == DataIdentifier.ActiveDiagnosticSessionDataIdentifier
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
        send_time = datetime.now(UTC).astimezone()
        receive_time = None

        if self.tester_present_task is not None:
            await self.tester_present_task.reset_timer()

        try:
            response = await super()._request(request, config)
            receive_time = datetime.now(UTC).astimezone()
            if self.tester_present_task is not None:
                await self.tester_present_task.reset_timer()
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

                    if config is not None and config.tags is not None and "ANALYZE" in config.tags:
                        mode = LogMode.emphasized

                    await self.db_handler.insert_scan_result(
                        self.state.to_json(),
                        service.UDSRequest.parse_dynamic(request.pdu),
                        response,
                        exception,
                        send_time,
                        receive_time,
                        mode,
                    )
            except Exception as e:
                logger.warning(f"Could not log messages to database: {g_repr(e)}")

            if response is not None:
                await self.update_state(request, response)


class TesterPresentSender:
    """Send TesterPresent after periods of inactivity"""

    def __init__(
        self,
        delay: float,
        send_tester_present: Callable[[], Awaitable[None]],
        oneshot: bool = False,
        ignore_activity: bool = False,
    ):
        """
        delay: idle time in seconds (e.g. 0.5)
        send_tester_present: async callable that sends the keepalive on your channel
        oneshot:  if True, send once, then wait for next real activity to re-arm;
                  if False, keep sending every 'delay' while idle.
        ignore_activity: ignore activity() calls such that keepalives are sent regardless of activity
        """
        self._delay = delay
        self._send = send_tester_present
        self._oneshot = oneshot
        self._ignore_activity = ignore_activity
        self._activity_event = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._cancelled: bool = False

    async def reset_timer(self) -> None:
        """Call this whenever you send or receive real traffic to reset the timer"""
        if self._ignore_activity is True:
            return
        self._activity_event.set()

    async def start(self) -> None:
        self._cancelled = False

        if self._task is not None:
            logger.warning("TesterPresentSender already running")
            return

        logger.info("Starting TesterPresentSender")
        self._task = asyncio.create_task(self._run())
        self._task.add_done_callback(
            handle_task_error,
            context=set_task_handler_ctx_variable(__name__, "TesterPresentSender"),
        )

    async def stop(self) -> None:
        self._cancelled = True

        if self._task is None:
            logger.warning("TesterPresentSender already stopped")
            return

        logger.info("Stopping TesterPresentSender")
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run(self) -> None:
        evt = self._activity_event
        while self._cancelled is False:
            evt.clear()
            try:
                # If activity happens before timeout, loop and wait again
                await asyncio.wait_for(evt.wait(), timeout=self._delay)
                continue
            except TimeoutError:
                # Idle period elapsed -> send keepalive
                await self._send()
                if self._oneshot:
                    # One-shot mode: re-arm only after next activity
                    await evt.wait()
