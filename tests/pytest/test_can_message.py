# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.transports.can import CANMessage


def test_can_message_deserialization() -> None:
    test_table = [
        (
            b"\x00\x07\x00\x00\x04\x00\x00\x00s\x02>\x00\x00\x00\x00\x00",
            CANMessage(arbitration_id=0x700, dlc=4, data=bytes([0x73, 0x02, 0x3E, 0x00])),
        ),
    ]

    for input_, output in test_table:
        frame = CANMessage.unpack(input_)
        assert frame == output
