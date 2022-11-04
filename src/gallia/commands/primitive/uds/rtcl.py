# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import sys
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.service import RoutineControlResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class RTCLPrimitive(UDSScanner):
    """Start or stop a provided routine or request its results"""

    GROUP = "primitive"
    COMMAND = "rtcl"
    SHORT_HELP = "RoutineControl"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "routine_identifier",
            type=auto_int,
            help="The routine identifier",
        )
        self.parser.add_argument(
            "--start",
            action="store_true",
            help="Start the routine with a startRoutine request (this task is always executed first)",
        )
        self.parser.add_argument(
            "--stop",
            action="store_true",
            help="Stop the routine with a stopRoutine request "
            "(this task is executed after starting the routine if --start is given as well)",
        )
        self.parser.add_argument(
            "--results",
            action="store_true",
            help="Read the routine results with a requestRoutineResults request (this task is always executed last)",
        )
        self.parser.add_argument(
            "--start-parameters",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="The routineControlOptionRecord passed to the startRoutine request",
        )
        self.parser.add_argument(
            "--stop-parameters",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="The routineControlOptionRecord passed to the stopRoutine request",
        )
        self.parser.add_argument(
            "--results-parameters",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="The routineControlOptionRecord passed to the stopRoutine request",
        )
        self.parser.add_argument(
            "--stop-delay",
            metavar="SECONDS",
            type=float,
            default=0.0,
            help="Delay the stopRoutine request by the given amount of seconds",
        )
        self.parser.add_argument(
            "--results-delay",
            metavar="SECONDS",
            type=float,
            default=0.0,
            help="Delay the requestRoutineResults request by the given amount of seconds",
        )

    async def main(self, args: Namespace) -> None:
        try:
            await self.ecu.check_and_set_session(args.session)
        except Exception as e:
            self.logger.critical(
                f"Could not change to session: {g_repr(args.session)}: {e!r}"
            )
            sys.exit(1)

        if args.start is False and args.stop is False and args.results is False:
            self.logger.warning("No instructions were given (start/stop/results)")

        if args.start:
            resp: (
                NegativeResponse | RoutineControlResponse
            ) = await self.ecu.routine_control_start_routine(
                args.routine_identifier, args.start_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.error(f"start_routine: {resp}")
            else:
                self.logger.result("[start] Positive response:")
                self.logger.result(f"hex: {resp.routine_status_record.hex()}")
                self.logger.result(f"raw: {resp.routine_status_record!r}")

        if args.stop:
            delay = args.stop_delay

            if delay > 0:
                self.logger.info(
                    f"Delaying the request for stopping the routine by {delay} seconds"
                )
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_stop_routine(
                args.routine_identifier, args.stop_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.error(f"stop routine: {resp}")
            else:
                self.logger.result("[stop] Positive response:")
                self.logger.result(f"hex: {resp.routine_status_record.hex()}")
                self.logger.result(f"raw: {resp.routine_status_record!r}")

        if args.results:
            delay = args.results_delay

            if delay > 0:
                self.logger.info(
                    f"Delaying the request for the routine results by {delay} seconds"
                )
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_request_routine_results(
                args.routine_identifier, args.results_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.error(f"request_routine_results: {resp}")
            else:
                self.logger.result("[get result] Positive response:")
                self.logger.result(f"hex: {resp.routine_status_record.hex()}")
                self.logger.result(f"raw: {resp.routine_status_record!r}")
