# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Literal

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class IOCBIPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="The session in which the requests are made")
    data_identifier: AutoInt = Field(description="The data identifier", positional=True)
    control_parameter: Literal[
        "return-control-to-ecu",
        "reset-to-default",
        "freeze-current-state",
        "short-term-adjustment",
        "without-control-parameter",
    ] = Field(
        description='Control parameter sent to the ECU. "short-term-adjustment" and "without-control-parameter" require passing a new state as well.',
        positional=True,
    )
    new_state: HexBytes = Field(
        b"",
        description='The new state required in use with the two control parameters "short-term-adjustment" and "without-control-parameter".',
        metavar="HEXSTRING",
    )
    control_enable_mask: HexBytes = Field(
        b"",
        description="This parameter is used if the data-identifier corresponds to multiple signals.In that case each bit enables or disables setting of each corresponding signal.Can only be used in combination with a control parameter.",
        metavar="HEXSTRING",
    )


class IOCBIPrimitive(UDSScanner):
    """Input output control"""

    CONFIG_TYPE = IOCBIPrimitiveConfig
    SHORT_HELP = "InputOutputControl"

    def __init__(self, config: IOCBIPrimitiveConfig):
        super().__init__(config)
        self.config: IOCBIPrimitiveConfig = config

    async def main(self) -> None:
        try:
            await self.ecu.check_and_set_session(self.config.session)
        except Exception as e:
            logger.critical(f"Could not change to session: {g_repr(self.config.session)}: {e!r}")
            sys.exit(1)

        did = self.config.data_identifier
        control_enable_mask_record = self.config.control_enable_mask
        uses_control_parameter = True

        if self.config.control_parameter == "return-control-to-ecu":
            resp = await self.ecu.input_output_control_by_identifier_return_control_to_ecu(
                did, control_enable_mask_record
            )
        elif self.config.control_parameter == "reset-to-default":
            resp = await self.ecu.input_output_control_by_identifier_reset_to_default(
                did, control_enable_mask_record
            )
        elif self.config.control_parameter == "freeze-current-state":
            resp = await self.ecu.input_output_control_by_identifier_freeze_current_state(
                did, control_enable_mask_record
            )
        elif self.config.control_parameter == "short-term-adjustment":
            resp = await self.ecu.input_output_control_by_identifier_short_term_adjustment(
                did, self.config.new_state, control_enable_mask_record
            )
        elif self.config.control_parameter == "without-control-parameter":
            resp = await self.ecu.input_output_control_by_identifier(
                did, self.config.new_state, control_enable_mask_record
            )
            uses_control_parameter = False

        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Positive response:")
            data = (
                resp.control_status_record[1:]
                if uses_control_parameter
                else resp.control_status_record
            )
            logger.result(f"hex: {data.hex()}")
            logger.result(f"raw: {repr(data)}")
