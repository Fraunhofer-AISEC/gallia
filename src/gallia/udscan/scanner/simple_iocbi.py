# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from argparse import Namespace

from gallia.uds.core.service import NegativeResponse
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class IOCBI(UDSScanner):
    """Input output control"""

    def add_parser(self) -> None:
        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="The session in which the requests are made",
        )
        self.parser.add_argument(
            "data_identifier", type=auto_int, help="The data identifier"
        )
        self.parser.add_argument(
            "control_parameter",
            type=str,
            choices=[
                "return-control-to-ecu",
                "reset-to-default",
                "freeze-current-state",
                "short-term-adjustment",
                "without-control-parameter",
            ],
            help='Control parameter sent to the ECU. "short-term-adjustment" and "without-control-parameter"'
            " require passing a new state as well.",
        )
        self.parser.add_argument(
            "--new-state",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help='The new state required in use with the two control parameters "short-term-adjustment"'
            ' and "without-control-parameter".',
        )
        self.parser.add_argument(
            "--control-enable-mask",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="This parameter is used if the data-identifier corresponds to multiple signals."
            "In that case each bit enables or disables setting of each corresponding signal."
            "Can only be used in combination with a control parameter.",
        )

    async def main(self, args: Namespace) -> None:
        try:
            await self.ecu.check_and_set_session(args.session)
        except Exception as e:
            self.logger.log_critical(
                f"Could not change to session: {g_repr(args.session)}: {g_repr(e)}"
            )
            sys.exit(1)

        did = args.data_identifier
        control_enable_mask_record = args.control_enable_mask
        uses_control_parameter = True

        if args.control_parameter == "return-control-to-ecu":
            resp = (
                await self.ecu.input_output_control_by_identifier_return_control_to_ecu(
                    did, control_enable_mask_record
                )
            )
        elif args.control_parameter == "reset-to-default":
            resp = await self.ecu.input_output_control_by_identifier_reset_to_default(
                did, control_enable_mask_record
            )
        elif args.control_parameter == "freeze-current-state":
            resp = (
                await self.ecu.input_output_control_by_identifier_freeze_current_state(
                    did, control_enable_mask_record
                )
            )
        elif args.control_parameter == "short-term-adjustment":
            resp = (
                await self.ecu.input_output_control_by_identifier_short_term_adjustment(
                    did, args.new_state, control_enable_mask_record
                )
            )
        elif args.control_parameter == "without-control-parameter":
            resp = await self.ecu.input_output_control_by_identifier(
                did, args.new_state, control_enable_mask_record
            )
            uses_control_parameter = False
        else:
            self.logger.log_critical("Unhandled control parameter")
            sys.exit(1)

        if isinstance(resp, NegativeResponse):
            self.logger.log_error(resp)
        else:
            self.logger.log_summary("Positive response:")
            data = (
                resp.control_status_record[1:]
                if uses_control_parameter
                else resp.control_status_record
            )
            self.logger.log_summary(f"hex: {data.hex()}")
            self.logger.log_summary(f"raw: {repr(data)}")
