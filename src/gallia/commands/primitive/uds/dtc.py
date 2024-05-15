# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace
from functools import partial

from tabulate import tabulate

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds.core.constants import (
    CDTCSSubFuncs,
    DiagnosticSessionControlSubFuncs,
    UDSErrorCodes,
)
from gallia.services.uds.core.service import NegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger("gallia.primitive.dtc")


class DTCPrimitive(UDSScanner):
    """
    Read or manipulate Diagnostic Trouble Codes (DTCs)

    This class provides functionalities to interact with the ECU's Diagnostic Trouble Codes (DTCs) using the UDS protocol.
    It inherits from the UDSScanner class of the gallia.command module to establish communication with the ECU.
    """

    GROUP = "primitive"
    COMMAND = "dtc"
    SHORT_HELP = "DiagnosticTroubleCodes"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            default=DiagnosticSessionControlSubFuncs.defaultSession.value,
            type=auto_int,
            help="Diagnostic session to perform the test in (default: %(default)x)",
        )
        sub_parser = self.parser.add_subparsers(dest="cmd", required=True)
        read_parser = sub_parser.add_parser(
            "read", help="Read the DTCs using the ReadDTCInformation service"
        )
        read_parser.add_argument(
            "--mask",
            type=partial(int, base=16),
            default=0xFF,
            help="The bitmask which is sent to the ECU in order to select the relevant DTCs according to their "
            "error state. By default, all error codes are returned (c.f. ISO 14229-1,D.2). (default: 0x%(default)x)",
        )
        read_parser.add_argument(
            "--show-legend",
            action="store_true",
            help="Displays a legend explaining the bit interpretation of the error state according to ISO 14229-1,D.2",
        )
        read_parser.add_argument(
            "--show-failed",
            action="store_true",
            help="Show a summary of the codes which failed",
        )
        read_parser.add_argument(
            "--show-uncompleted",
            action="store_true",
            help="Show a summary of the codes which have not completed",
        )
        clear_parser = sub_parser.add_parser(
            "clear", help="Clear the DTCs using the ClearDiagnosticInformation service"
        )
        clear_parser.add_argument(
            "--group-of-dtc",
            type=int,
            default=0xFFFFFF,
            help="Only clear a particular DTC or the DTCs belonging to the given group. "
            "(default: 0x%(default)x - clears all)",
        )
        control_parser = sub_parser.add_parser(
            "control",
            help="Stop or resume setting of new DTCs using the " "ControlDTCSetting service",
        )
        control_group = control_parser.add_mutually_exclusive_group(required=True)
        control_group.add_argument(
            "--stop",
            action="store_true",
            help="Stops setting of new DTCs. If already disabled, this has no effect.",
        )
        control_group.add_argument(
            "--resume",
            action="store_true",
            help="Resumes setting of new DTCs. If already enabled, this has no effect.",
        )

    async def fetch_error_codes(self, mask: int, split: bool = True) -> dict[int, int]:
        """Fetches DTC information from the ECU using the ReadDTCInformation service.

    This method retrieves DTCs from the ECU based on the provided bitmask, which filters the results according to their error state.

    Args:
        mask (int): Bitmask to select DTCs based on error state.
        split (bool, optional): Attempts to fetch DTCs in chunks if the response is too large (default: True).

    Returns:
        dict[int, int]: Dictionary containing DTCs as keys and their corresponding error state as values.

    Raises:
        UDSErrorCodes: If a negative response is received from the ECU with a specific error code (e.g., response too long).
    """
        
        ecu_response = await self.ecu.read_dtc_information_report_dtc_by_status_mask(mask)
        dtcs = {}

        if isinstance(ecu_response, NegativeResponse):
            if ecu_response.response_code == UDSErrorCodes.responseTooLong:
                logger.error(
                    f"There are too many codes for (sub)mask {mask}. Consider setting --mask "
                    f"with a parameter that excludes one or more of the corresponding bits."
                )
                if split:
                    logger.warning("Trying to fetch the error codes iteratively.")

                    for i in range(8):
                        sub_mask = mask & 2**i

                        if sub_mask > 0:
                            logger.info(f"Trying to fetch with mask {g_repr(sub_mask)}")
                            dtcs.update(await self.fetch_error_codes(sub_mask, False))
            else:
                logger.critical(f"Could not fetch error codes: {ecu_response}; exiting…")
                sys.exit(1)
        else:
            dtcs = ecu_response.dtc_and_status_record

        return dtcs

    async def read(self, args: Namespace) -> None:
        """Reads DTCs and presents them along with summaries based on user options.

        This method retrieves DTCs using the `fetch_error_codes` method and categorizes them based on their error state.
        It then presents the DTC information and optional summaries according to user-specified flags.

        Args:
            args (Namespace): Namespace object containing parsed command-line arguments.
        """
        
        dtcs = await self.fetch_error_codes(args.mask)

        failed_dtcs: list[list[str]] = []
        uncompleted_dtcs: list[list[str]] = []

        for dtc, error_state in dtcs.items():
            raw_output = f"{dtc:06X} {error_state:02X}"
            bit_string = bin(error_state + 0x100)[
                3:
            ]  # Transform error_state into a bit-string with leading zeros
            table_output = [f"{dtc:06X}", f"{error_state:02X}"] + [
                "X" if b == "1" else "" for b in bit_string
            ]

            # if any kind of test failure
            if error_state & 0xAF:
                logger.warning(raw_output)
                failed_dtcs.append(table_output)
            # if not failed but also not completed yet (i.e. not yet in this cycle or since last clear)
            elif error_state & 0x50:
                logger.result(raw_output)
                uncompleted_dtcs.append(table_output)

        if args.show_legend:
            logger.result("")
            self.show_bit_legend()

        if args.show_failed:
            logger.result("")
            logger.result("Failed codes:")
            self.show_summary(failed_dtcs)

        if args.show_uncompleted:
            logger.result("")
            logger.result("Uncompleted codes:")
            self.show_summary(uncompleted_dtcs)

    def show_bit_legend(self) -> None:
        """
        Presents a legend explaining the bit interpretation of the DTC error state.

        This method iterates through a list of bit descriptions and logs them using the logger.result function.
        Each description corresponds to a specific bit in the error state value and explains its meaning.
        This legend helps users understand the detailed information provided in the DTC output.
        """

        bit_descriptions = [
            "0 = testFailed: most recent test failed",
            "1 = testFailedThisOperationCycle: failed in current cycle",
            "2 = pendingDTC: failed in current or last cycle",
            "3 = confirmedDTC: failed often enough to be stored in long term memory",
            "4 = testNotCompletedSinceLastClear: not completed since last clear",
            "5 = testFailedSinceLastClear: failed since last clear",
            "6 = testNotCompletedThisOperationCycle: not completed in current cycle",
            "7 = warningIndicatorRequested: existing warning indicators (e.g. lamp, display)",
        ]

        for line in (
            tabulate([[d] for d in bit_descriptions], headers=["bit descriptions"])
        ).splitlines():
            logger.result(line)

    def show_summary(self, dtcs: list[list[str]]) -> None:
        """
        Generates a summary table for the provided DTC information.

        This method sorts the DTC list and then creates a table with headers including "DTC", "error state", and individual bits (0 to 7).
        It uses the `tabulate` library to format the table in a user-friendly way and logs each line using the logger.result function.
        This summary provides a concise overview of the DTCs and their error states.
        """

        dtcs.sort()

        header = [
            "DTC",
            "error state",
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
        ]

        for line in tabulate(dtcs, headers=header, tablefmt="fancy_grid").splitlines():
            logger.result(line)

    async def clear(self, args: Namespace) -> None:
        """
        Clears DTCs from the ECU's memory based on the specified group or DTC.

        This method retrieves the group of DTCs or a specific DTC to clear from the command-line arguments.
        It then validates the provided value to ensure it falls within the acceptable range.
        Finally, it calls the `ecu.clear_diagnostic_information` method to send the clear request to the ECU.
        The method logs the response, indicating success or failure.

        Args:
            args (Namespace): Namespace object containing parsed command-line arguments.
        """

        group_of_dtc: int = args.group_of_dtc

        min_group_of_dtc = 0
        max_group_of_dtc = 0xFFFFFF

        if not min_group_of_dtc <= group_of_dtc <= max_group_of_dtc:
            logger.error(
                f"The parameter group_of_dtc must be in the range {g_repr(min_group_of_dtc)}-{g_repr(max_group_of_dtc)}"
            )

        resp = await self.ecu.clear_diagnostic_information(group_of_dtc)

        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Success")

    async def control(self, args: Namespace) -> None:
        """
        Enables or disables setting of new DTCs based on user selection.

        This method checks the `--stop` or `--resume` argument from the `args` object to determine whether to stop or resume setting new DTCs.
        It then calls the `ecu.control_dtc_setting` method with the corresponding sub-function (CDTCSSubFuncs.OFF or CDTCSSubFuncs.ON) to send the control request to the ECU.
        """

        if args.stop:
            await self.ecu.control_dtc_setting(CDTCSSubFuncs.OFF)
        else:
            await self.ecu.control_dtc_setting(CDTCSSubFuncs.ON)

    async def main(self, args: Namespace) -> None:
        await self.ecu.set_session(args.session)

        if args.cmd == "clear":
            await self.clear(args)
        elif args.cmd == "control":
            await self.control(args)
        elif args.cmd == "read":
            await self.read(args)
        else:
            logger.critical("Unhandled command")
            sys.exit(1)
