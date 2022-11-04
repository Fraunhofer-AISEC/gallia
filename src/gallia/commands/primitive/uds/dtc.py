# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace
from functools import partial

from tabulate import tabulate

from gallia.command import UDSScanner
from gallia.services.uds.core.constants import CDTCSSubFuncs, DSCSubFuncs, UDSErrorCodes
from gallia.services.uds.core.service import NegativeResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class DTCPrimitive(UDSScanner):
    """Read out the Diagnostic Troube Codes (DTC)"""

    GROUP = "primitive"
    COMMAND = "dtc"
    SHORT_HELP = "DiagnosticTroubleCodes"

    def configure_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            default=DSCSubFuncs.DS.value,
            type=auto_int,
            help="Session to perform test in",
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
            "error state. By default, all error codes are returned (c.f. ISO 14229-1,D.2).",
        )
        read_parser.add_argument(
            "--show-legend",
            action="store_true",
            help="Show the legend of the bit interpretation according to ISO 14229-1,D.2",
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
            "By default, all error codes are cleared.",
        )
        control_parser = sub_parser.add_parser(
            "control",
            help="Stop or resume the setting of DTCs using the "
            "ControlDTCSetting service",
        )
        control_group = control_parser.add_mutually_exclusive_group(required=True)
        control_group.add_argument(
            "--stop",
            action="store_true",
            help="Stop the setting of DTCs. If already disabled, this has no effect.",
        )
        control_group.add_argument(
            "--resume",
            action="store_true",
            help="Resume the setting of DTCs. If already enabled, this has no effect.",
        )

    async def fetch_error_codes(self, mask: int, split: bool = True) -> dict[int, int]:
        ecu_response = await self.ecu.read_dtc_information_report_dtc_by_status_mask(
            mask
        )
        dtcs = {}

        if isinstance(ecu_response, NegativeResponse):
            if ecu_response.response_code == UDSErrorCodes.responseTooLong:
                self.logger.error(
                    f"There are too many codes for (sub)mask {mask}. Consider setting --mask "
                    f"with a parameter that excludes one or more of the corresponding bits."
                )
                if split:
                    self.logger.warning("Trying to fetch the error codes iteratively.")

                    for i in range(8):
                        sub_mask = mask & 2**i

                        if sub_mask > 0:
                            self.logger.info(
                                f"Trying to fetch with mask {g_repr(sub_mask)}"
                            )
                            dtcs.update(await self.fetch_error_codes(sub_mask, False))
            else:
                self.logger.critical(
                    f"Could not fetch error codes: {ecu_response}; exiting…"
                )
                sys.exit(1)
        else:
            dtcs = ecu_response.dtc_and_status_record

        return dtcs

    async def read(self, args: Namespace) -> None:
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
                self.logger.warning(raw_output)
                failed_dtcs.append(table_output)
            # if not failed but also not completed yet (i.e. not yet in this cycle or since last clear)
            elif error_state & 0x50:
                self.logger.result(raw_output)
                uncompleted_dtcs.append(table_output)

        if args.show_legend:
            self.logger.result("")
            self.show_bit_legend()

        if args.show_failed:
            self.logger.result("")
            self.logger.result("Failed codes:")
            self.show_summary(failed_dtcs)

        if args.show_uncompleted:
            self.logger.result("")
            self.logger.result("Uncompleted codes:")
            self.show_summary(uncompleted_dtcs)

    def show_bit_legend(self) -> None:
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
            self.logger.result(line)

    def show_summary(self, dtcs: list[list[str]]) -> None:
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
            self.logger.result(line)

    async def clear(self, args: Namespace) -> None:
        group_of_dtc: int = args.group_of_dtc

        min_group_of_dtc = 0
        max_group_of_dtc = 0xFFFFFF

        if not min_group_of_dtc <= group_of_dtc <= max_group_of_dtc:
            self.logger.error(
                f"The parameter group_of_dtc must be in the range {g_repr(min_group_of_dtc)}-{g_repr(max_group_of_dtc)}"
            )

        resp = await self.ecu.clear_diagnostic_information(group_of_dtc)

        if isinstance(resp, NegativeResponse):
            self.logger.error(resp)
        else:
            self.logger.result("Success")

    async def control(self, args: Namespace) -> None:
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
            self.logger.critical("Unhandled command")
            sys.exit(1)
