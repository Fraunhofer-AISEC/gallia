# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from tabulate import tabulate

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexInt
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.constants import (
    CDTCSSubFuncs,
    DiagnosticSessionControlSubFuncs,
    UDSErrorCodes,
)
from gallia.services.uds.core.service import NegativeResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class DTCPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(
        DiagnosticSessionControlSubFuncs.defaultSession.value,
        description="Session to perform test in",
    )


class ReadDTCPrimitiveConfig(DTCPrimitiveConfig):
    mask: HexInt = Field(
        0xFF,
        description="The bitmask which is sent to the ECU in order to select the relevant DTCs according to their error state. By default, all error codes are returned (c.f. ISO 14229-1,D.2).",
    )
    show_legend: bool = Field(
        False, description="Show the legend of the bit interpretation according to ISO 14229-1,D.2"
    )
    show_failed: bool = Field(False, description="Show a summary of the codes which failed")
    show_uncompleted: bool = Field(
        False, description="Show a summary of the codes which have not completed"
    )


class ClearDTCPrimitiveConfig(DTCPrimitiveConfig):
    group_of_dtc: int = Field(
        0xFFFFFF,
        description="Only clear a particular DTC or the DTCs belonging to the given group. By default, all error codes are cleared.",
    )


class ControlDTCPrimitiveConfig(DTCPrimitiveConfig):
    stop: bool = Field(
        False, description="Stop the setting of DTCs. If already disabled, this has no effect."
    )
    resume: bool = Field(
        False, description="Resume the setting of DTCs. If already enabled, this has no effect."
    )


class ReadDTCPrimitive(UDSScanner):
    """Read out the Diagnostic Trouble Codes (DTC)"""

    CONFIG_TYPE = ReadDTCPrimitiveConfig
    SHORT_HELP = "Read the DTCs using the ReadDTCInformation service"

    def __init__(self, config: ReadDTCPrimitiveConfig):
        super().__init__(config)
        self.config: ReadDTCPrimitiveConfig = config

    async def fetch_error_codes(self, mask: int, split: bool = True) -> dict[int, int]:
        ecu_response = await self.ecu.read_dtc_information_report_dtc_by_status_mask(mask)
        dtcs = {}

        if isinstance(ecu_response, NegativeResponse):
            if ecu_response.response_code == UDSErrorCodes.responseTooLong:
                logger.error(
                    f"There are too many codes for (sub)mask {mask}. Consider setting --mask with a parameter that excludes one or more of the corresponding bits."
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

    async def main(self) -> None:
        dtcs = await self.fetch_error_codes(self.config.mask)

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

        if self.config.show_legend:
            logger.result("")
            self.show_bit_legend()

        if self.config.show_failed:
            logger.result("")
            logger.result("Failed codes:")
            self.show_summary(failed_dtcs)

        if self.config.show_uncompleted:
            logger.result("")
            logger.result("Uncompleted codes:")
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

        for line in tabulate(
            [[d] for d in bit_descriptions], headers=["bit descriptions"]
        ).splitlines():
            logger.result(line)

    def show_summary(self, dtcs: list[list[str]]) -> None:
        dtcs.sort()

        header = ["DTC", "error state", "0", "1", "2", "3", "4", "5", "6", "7"]

        for line in tabulate(dtcs, headers=header, tablefmt="fancy_grid").splitlines():
            logger.result(line)


class ClearDTCPrimitive(UDSScanner):
    CONFIG_TYPE = ClearDTCPrimitiveConfig
    SHORT_HELP = "Clear the DTCs using the ClearDiagnosticInformation service"

    def __init__(self, config: ClearDTCPrimitiveConfig):
        super().__init__(config)
        self.config: ClearDTCPrimitiveConfig = config

    async def main(self) -> None:
        group_of_dtc: int = self.config.group_of_dtc

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


class ControlDTCPrimitive(UDSScanner):
    CONFIG_TYPE = ControlDTCPrimitiveConfig
    SHORT_HELP = "Stop or resume the setting of DTCs using the ControlDTCSetting service"

    def __init__(self, config: ControlDTCPrimitiveConfig):
        super().__init__(config)
        self.config: ControlDTCPrimitiveConfig = config

    async def main(self) -> None:
        assert isinstance(self.config, ControlDTCPrimitiveConfig)

        if self.config.stop:
            await self.ecu.control_dtc_setting(CDTCSSubFuncs.OFF)
        else:
            await self.ecu.control_dtc_setting(CDTCSSubFuncs.ON)
