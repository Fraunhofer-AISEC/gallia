# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.service import RoutineControlResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class RTCLPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="The session in which the requests are made")
    routine_identifier: AutoInt = Field(description="The routine identifier", positional=True)
    start: bool = Field(
        False,
        description="Start the routine with a startRoutine request (this task is always executed first)",
    )
    stop: bool = Field(
        False,
        description="Stop the routine with a stopRoutine request (this task is executed after starting the routine if --start is given as well)",
    )
    results: bool = Field(
        False,
        description="Read the routine results with a requestRoutineResults request (this task is always executed last)",
    )
    start_parameters: HexBytes = Field(
        b"",
        description="The routineControlOptionRecord passed to the startRoutine request",
        metavar="HEXSTRING",
    )
    stop_parameters: HexBytes = Field(
        b"",
        description="The routineControlOptionRecord passed to the stopRoutine request",
        metavar="HEXSTRING",
    )
    results_parameters: HexBytes = Field(
        b"",
        description="The routineControlOptionRecord passed to the stopRoutine request",
        metavar="HEXSTRING",
    )
    stop_delay: float = Field(
        0.0,
        description="Delay the stopRoutine request by the given amount of seconds",
        metavar="SECONDS",
    )
    results_delay: float = Field(
        0.0,
        description="Delay the requestRoutineResults request by the given amount of seconds",
        metavar="SECONDS",
    )


class RTCLPrimitive(UDSScanner):
    """Start or stop a provided routine or request its results"""

    CONFIG_TYPE = RTCLPrimitiveConfig
    SHORT_HELP = "RoutineControl"

    def __init__(self, config: RTCLPrimitiveConfig):
        super().__init__(config)
        self.config: RTCLPrimitiveConfig = config

    async def main(self) -> None:
        try:
            await self.ecu.check_and_set_session(self.config.session)
        except Exception as e:
            logger.critical(f"Could not change to session: {g_repr(self.config.session)}: {e!r}")
            sys.exit(1)

        if (
            self.config.start is False
            and self.config.stop is False
            and (self.config.results is False)
        ):
            logger.warning("No instructions were given (start/stop/results)")

        if self.config.start:
            resp: (
                NegativeResponse | RoutineControlResponse
            ) = await self.ecu.routine_control_start_routine(
                self.config.routine_identifier, self.config.start_parameters
            )

            if isinstance(resp, NegativeResponse):
                logger.error(f"start_routine: {resp}")
            else:
                logger.result("[start] Positive response:")
                logger.result(f"hex: {resp.routine_status_record.hex()}")
                logger.result(f"raw: {resp.routine_status_record!r}")

        if self.config.stop:
            delay = self.config.stop_delay

            if delay > 0:
                logger.info(f"Delaying the request for stopping the routine by {delay} seconds")
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_stop_routine(
                self.config.routine_identifier, self.config.stop_parameters
            )

            if isinstance(resp, NegativeResponse):
                logger.error(f"stop routine: {resp}")
            else:
                logger.result("[stop] Positive response:")
                logger.result(f"hex: {resp.routine_status_record.hex()}")
                logger.result(f"raw: {resp.routine_status_record!r}")

        if self.config.results:
            delay = self.config.results_delay

            if delay > 0:
                logger.info(f"Delaying the request for the routine results by {delay} seconds")
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_request_routine_results(
                self.config.routine_identifier, self.config.results_parameters
            )

            if isinstance(resp, NegativeResponse):
                logger.error(f"request_routine_results: {resp}")
            else:
                logger.result("[results] Positive response:")
                logger.result(f"hex: {resp.routine_status_record.hex()}")
                logger.result(f"raw: {resp.routine_status_record!r}")
