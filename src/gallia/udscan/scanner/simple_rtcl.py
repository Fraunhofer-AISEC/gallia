import asyncio
import binascii
import sys
from argparse import Namespace
from typing import Union

from gallia.uds.core.service import NegativeResponse, _RoutineControlResponse
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import auto_int, check_and_set_session


class RTCL(UDSScanner):
    """Start or stop a provided routine or request its results"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "routine_identifier", type=auto_int, help="The routine identifier"
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
            await check_and_set_session(self.ecu, args.session)
        except Exception as e:
            self.logger.log_critical(
                f"Could not change to session: 0x{args.session:02x}: {e.__class__.__name__} {e}"
            )
            sys.exit(1)

        if args.start is False and args.stop is False and args.results is False:
            self.logger.log_warning("No instructions were given (start/stop/results)")

        if args.start:
            resp: Union[
                NegativeResponse, _RoutineControlResponse
            ] = await self.ecu.routine_control_start_routine(
                args.routine_identifier, args.start_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.log_error(f"start_routine: {resp}")
            else:
                self.logger.log_summary("[start] Positive response:")
                self.logger.log_summary(f"hex: {resp.routine_status_record.hex()}")
                self.logger.log_summary(f"raw: {repr(resp.routine_status_record)}")

        if args.stop:
            delay = args.stop_delay

            if delay > 0:
                self.logger.log_info(
                    f"Delaying the request for stopping the routine by {delay} seconds"
                )
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_stop_routine(
                args.routine_identifier, args.stop_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.log_error(f"stop routine: {resp}")
            else:
                self.logger.log_summary("[stop] Positive response:")
                self.logger.log_summary(f"hex: {resp.routine_status_record.hex()}")
                self.logger.log_summary(f"raw: {repr(resp.routine_status_record)}")

        if args.results:
            delay = args.results_delay

            if delay > 0:
                self.logger.log_info(
                    f"Delaying the request for the routine results by {delay} seconds"
                )
                await asyncio.sleep(delay)

            resp = await self.ecu.routine_control_request_routine_results(
                args.routine_identifier, args.results_parameters
            )

            if isinstance(resp, NegativeResponse):
                self.logger.log_error(f"request_routine_results: {resp}")
            else:
                self.logger.log_summary("[get result] Positive response:")
                self.logger.log_summary(f"hex: {resp.routine_status_record.hex()}")
                self.logger.log_summary(f"raw: {repr(resp.routine_status_record)}")
