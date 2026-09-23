# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Dissectors for the messages in logfiles.

Transports log the messages which they read or write together with the
protocol of the data (see :attr:`gallia.log.PenlogRecord.proto`). The
protocols are named like the dissectors of Wireshark, e.g. ``uds``. A
dissector returns a short description of a message, e.g. for ``hr``.
"""

import re
from binascii import unhexlify
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto


class DissectionKind(Enum):
    REQUEST = auto()
    RESPONSE = auto()
    ERROR = auto()
    INFO = auto()


@dataclass(frozen=True)
class Dissection:
    text: str
    kind: DissectionKind


#: Returns the dissection of the logged data or None, if it is not
#: a valid message; it may raise exceptions for invalid data as well.
Dissector = Callable[[str], Dissection | None]

DISSECTORS: dict[str, Dissector] = {}


def dissector(proto: str) -> Callable[[Dissector], Dissector]:
    """Registers a dissector for ``proto``."""

    def register(func: Dissector) -> Dissector:
        DISSECTORS[proto] = func
        return func

    return register


def dissect(proto: str, data: str) -> Dissection | None:
    """Dissects ``data`` of the protocol ``proto``; None if there is no
    dissector for the protocol or the data is invalid."""
    if (func := DISSECTORS.get(proto)) is None:
        return None
    try:
        return func(data)
    except Exception:
        return None


@dissector("uds")
def dissect_uds(data: str) -> Dissection | None:
    """Dissects a UDS message in hex."""
    try:
        pdu = unhexlify(data)
    except ValueError:
        return None
    if len(pdu) == 0 or pdu[0] == 0:
        return None

    # Imported lazily; this takes a while and is rarely needed.
    from gallia.services.uds.core.service import NegativeResponse, UDSRequest, UDSResponse

    if pdu[0] & 0x40:
        response = UDSResponse.parse_dynamic(pdu)
        if isinstance(response, NegativeResponse):
            return Dissection(repr(response), DissectionKind.ERROR)
        return Dissection(repr(response), DissectionKind.RESPONSE)
    return Dissection(repr(UDSRequest.parse_dynamic(pdu)), DissectionKind.REQUEST)


# The CAN frames as logged by RawCANTransport: "0x7e0#021003" or
# "0x7e0##021003" for CAN FD.
_CAN_FRAME = re.compile(r"(0x[0-9a-f]+)##?([0-9a-f]*)")


def parse_can_frame(data: str) -> tuple[int, bytes, bool] | None:
    """Returns the ID, the data, and whether it is a CAN FD frame."""
    if (m := _CAN_FRAME.fullmatch(data)) is None:
        return None
    return int(m.group(1), 16), bytes.fromhex(m.group(2)), "##" in data


_FLOW_STATUS = {0: "continue to send", 1: "wait", 2: "overflow"}


@dissector("iso15765")
def dissect_isotp(data: str) -> Dissection | None:
    """Dissects a CAN frame with ISO-TP (normal addressing); the payload of
    single frames is dissected as UDS."""
    if (frame := parse_can_frame(data)) is None:
        return None
    _, payload, _ = frame
    pci, low = payload[0] >> 4, payload[0] & 0x0F
    match pci:
        case 0:
            # The length is in the next byte for CAN FD frames with more than 8 bytes.
            length, start = (low, 1) if low != 0 else (payload[1], 2)
            text = f"single frame, {length} bytes"
            if (uds := dissect("uds", payload[start : start + length].hex())) is not None:
                return Dissection(f"{text}: {uds.text}", uds.kind)
            return Dissection(text, DissectionKind.INFO)
        case 1:
            length = (low << 8) | payload[1]
            if length == 0:
                # Messages with more than 4095 bytes.
                length = int.from_bytes(payload[2:6])
            return Dissection(f"first frame, {length} bytes", DissectionKind.INFO)
        case 2:
            return Dissection(f"consecutive frame {low}", DissectionKind.INFO)
        case 3:
            status = _FLOW_STATUS.get(low, f"invalid status {low}")
            return Dissection(
                f"flow control: {status}, block size {payload[1]}, STmin {payload[2]:#04x}",
                DissectionKind.INFO,
            )
    return None
