# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import base64
import pickle
import sys

from gallia.command.base import AsyncScriptConfig, ScriptConfig
from gallia.command.config import AutoInt, Field, Ranges

assert sys.platform == "win32"

from gallia.command import AsyncScript, Script
from gallia.transports._ctypes_vector_xl_wrapper import FlexRayCtypesBackend
from gallia.transports.flexray_vector import FlexRayFrame, RawFlexRayTransport, parse_frame_type


class FRDumpConfig(AsyncScriptConfig):
    target_slot: AutoInt | None = Field(description="the target flexray slot")
    isotp: bool = Field(False, description="the target flexray slot")
    filter_null_frames: bool = Field(True, description="filter mysterious null frames out")
    slot: Ranges = Field([], description="filter on flexray slot")


class FRDump(AsyncScript):
    """Dump the content of the flexray bus"""

    CONFIG_TYPE = FRDumpConfig
    SHORT_HELP = "runs a helper tool that dumps flexray bus traffic to stdout"

    def __init__(self, config: FRDumpConfig):
        super().__init__(config)
        self.config: FRDumpConfig = config

    @staticmethod
    def poor_mans_dissect(frame: FlexRayFrame) -> str:
        res = f"slot_id: {frame.slot_id:03d}; "

        hdr = frame.data[:4]
        res += f"hdr: {hdr.hex()}; "

        frame_type = parse_frame_type(frame.data[4:])
        res += f"type: {frame_type.name}; "
        res += f"data: {frame.data[4:].hex()}"

        return res

    async def main(self) -> None:
        tp = await RawFlexRayTransport.connect("fr-raw:", None)

        if len(self.config.slot) > 0:
            tp.add_block_all_filter()
            for slot in self.config.slot:
                tp.set_acceptance_filter(slot)

        tp.activate_channel()

        while True:
            frame = await tp.read_frame()

            if self.config.filter_null_frames is True:
                # Best effort; in our use case this was the ISO-TP header.
                # The first ISO-TP header byte is never 0x00.
                if frame.data[0] == 0x00:
                    continue

            if self.config.isotp:
                print(self.poor_mans_dissect(frame))
            else:
                print(f"slot_id: {frame.slot_id:03d}; data: {frame.data.hex()}")


class FRConfigDumpConfig(ScriptConfig):
    channel: int | None = Field(description="the channel number of the flexray device")
    pretty: bool = Field(False, description="pretty print the configuration", short="p")


class FRConfigDump(Script):
    """Dump the flexray configuration as base64"""

    CONFIG_TYPE = FRConfigDumpConfig
    SHORT_HELP = "Dump the flexray configuration as base64"

    def __init__(self, config: FRConfigDumpConfig):
        super().__init__(config)
        self.config: FRConfigDumpConfig = config

    def main(self) -> None:
        backend = FlexRayCtypesBackend.create(self.config.channel)
        raw_config = backend.get_configuration()
        config = pickle.dumps(raw_config)

        if self.config.pretty:
            print(raw_config)
        else:
            print(base64.b64encode(config))
