# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import base64
import pickle
import sys
from argparse import BooleanOptionalAction, Namespace

assert sys.platform == "win32"

from gallia.command import AsyncScript, Script
from gallia.transports._ctypes_vector_xl_wrapper import FlexRayCtypesBackend
from gallia.transports.flexray_vector import FlexRayFrame, RawFlexRayTransport, parse_frame_type
from gallia.utils import auto_int


class FRDump(AsyncScript):
    """Dump the content of the flexray bus"""

    COMMAND = "fr-dump"
    SHORT_HELP = "runs a helper tool that dumps flexray bus traffic to stdout"

    def configure_parser(self) -> None:
        self.parser.add_argument("--target-slot", type=auto_int, help="the target flexray slot")
        self.parser.add_argument("--isotp", action="store_true", help="the target flexray slot")
        self.parser.add_argument(
            "--filter-null-frames",
            action=BooleanOptionalAction,
            default=True,
            help="filter mysterious null frames out",
        )
        self.parser.add_argument("slot", type=auto_int, help="filter on flexray slot", nargs="*")

    @staticmethod
    def poor_mans_dissect(frame: FlexRayFrame) -> str:
        res = f"slot_id: {frame.slot_id:03d}; "

        hdr = frame.data[:4]
        res += f"hdr: {hdr.hex()}; "

        frame_type = parse_frame_type(frame.data[4:])
        res += f"type: {frame_type.name}; "
        res += f"data: {frame.data[4:].hex()}"

        return res

    async def main(self, args: Namespace) -> None:
        tp = await RawFlexRayTransport.connect("fr-raw:", None)

        if args.slot:
            tp.add_block_all_filter()
            for slot in args.slot:
                tp.set_acceptance_filter(slot)

        tp.activate_channel()

        while True:
            frame = await tp.read_frame()

            if args.filter_null_frames is True:
                # Best effort; in our use case this was the ISO-TP header.
                # The first ISO-TP header byte is never 0x00.
                if frame.data[0] == 0x00:
                    continue

            if args.isotp:
                print(self.poor_mans_dissect(frame))
            else:
                print(f"slot_id: {frame.slot_id:03d}; data: {frame.data.hex()}")


class FRDumpConfig(Script):
    """Dump the flexray configuration as base64"""

    COMMAND = "fr-dump-config"
    SHORT_HELP = "Dump the flexray configuration as base64"

    def configure_parser(self) -> None:
        self.parser.add_argument("--channel", help="the channel number of the flexray device")
        self.parser.add_argument(
            "-p",
            "--pretty",
            action="store_true",
            default=False,
            help="pretty print the configuration",
        )

    def main(self, args: Namespace) -> None:
        backend = FlexRayCtypesBackend.create(args.channel)
        raw_config = backend.get_configuration()
        config = pickle.dumps(raw_config)

        if args.pretty:
            print(raw_config)
        else:
            print(base64.b64encode(config))
