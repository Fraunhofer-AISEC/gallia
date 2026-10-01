# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Dissection of single messages with Wireshark (tshark), if installed.

The message is wrapped into a pcap file, which is piped into tshark: CAN
frames as SocketCAN frames, everything else as "exported PDU" for the
Wireshark dissector named like the protocol (see gallia.dissect).
"""

import shutil
import struct
import subprocess

from gallia.dissect import parse_can_frame

_LINKTYPE_WIRESHARK_UPPER_PDU = 252
_LINKTYPE_CAN_SOCKETCAN = 227
_EXP_PDU_TAG_DISSECTOR_NAME = 12
_EXP_PDU_TAG_END_OF_OPT = 0
_CAN_EFF_FLAG = 0x80000000
_CAN_SFF_MASK = 0x7FF
_CANFD_FDF = 0x04

# The protocols of CAN frames and their "Decode As" rules for Wireshark;
# like the UDS client, ISO-TP single frames are dissected as UDS.
_CAN_PROTOCOLS = {
    "can": [],
    "iso15765": ["can.subdissector,iso15765", "iso15765.subdissector,uds"],
}

# The layers which only wrap the message; they are omitted.
_WRAPPERS = ("Frame ", "EXPORTED_PDU")


def available() -> bool:
    return shutil.which("tshark") is not None


def _pcap(linktype: int, packet: bytes) -> bytes:
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, linktype)
    return header + struct.pack("<IIII", 0, 0, len(packet), len(packet)) + packet


def _exported_pdu(proto: str, payload: bytes) -> bytes:
    name = proto.encode()
    return (
        struct.pack(">HH", _EXP_PDU_TAG_DISSECTOR_NAME, len(name))
        + name
        + struct.pack(">HH", _EXP_PDU_TAG_END_OF_OPT, 0)
        + payload
    )


def _socketcan(can_id: int, data: bytes, fd: bool) -> bytes:
    if can_id > _CAN_SFF_MASK:
        can_id |= _CAN_EFF_FLAG
    return struct.pack(">IBBxx", can_id, len(data), _CANFD_FDF if fd else 0) + data


def dissect(proto: str, data: str, timeout: float = 5) -> list[str] | None:
    """Returns the protocol tree of Wireshark for ``data`` of the protocol
    ``proto`` (as logged); None if it cannot be dissected."""
    args = ["tshark", "-r", "-", "-V"]
    if proto in _CAN_PROTOCOLS:
        if (frame := parse_can_frame(data)) is None:
            return None
        pcap = _pcap(_LINKTYPE_CAN_SOCKETCAN, _socketcan(*frame))
        for decode_as in _CAN_PROTOCOLS[proto]:
            args += ["-d", decode_as]
    else:
        try:
            payload = bytes.fromhex(data)
        except ValueError:
            return None
        pcap = _pcap(_LINKTYPE_WIRESHARK_UPPER_PDU, _exported_pdu(proto, payload))

    try:
        result = subprocess.run(args, input=pcap, capture_output=True, timeout=timeout, check=True)
    except (OSError, subprocess.SubprocessError):
        return None

    lines: list[str] = []
    skip = False
    for line in result.stdout.decode(errors="replace").splitlines():
        if not line.startswith(" "):
            skip = line.startswith(_WRAPPERS)
        if not skip and line.strip():
            lines.append(line)
    return lines or None
