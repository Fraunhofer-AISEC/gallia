# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import pytest

from gallia.cli.hr import wireshark
from gallia.dissect import DISSECTORS, Dissection, DissectionKind, dissect, dissector


@pytest.mark.parametrize(
    ("proto", "data", "kind", "text"),
    [
        ("uds", "22f190", DissectionKind.REQUEST, "ReadDataByIdentifierRequest"),
        ("uds", "62f19041", DissectionKind.RESPONSE, "ReadDataByIdentifierResponse"),
        ("uds", "7f2231", DissectionKind.ERROR, "NegativeResponse"),
        ("uds", "no hex", None, None),
        ("uds", "00", None, None),
        ("uds", "", None, None),
        # A single frame: the payload is dissected as UDS.
        ("iso15765", "0x7e0#0322f190aaaaaaaa", DissectionKind.REQUEST, "single frame, 3 bytes: "),
        ("iso15765", "0x7e0#0100", DissectionKind.INFO, "single frame, 1 bytes"),
        # CAN FD: the length is in the second byte.
        ("iso15765", "0x7e0##000322f190", DissectionKind.REQUEST, "single frame, 3 bytes: "),
        ("iso15765", "0x7e8#101462f190574155", DissectionKind.INFO, "first frame, 20 bytes"),
        ("iso15765", "0x7e8#1000000012346200", DissectionKind.INFO, "first frame, 4660 bytes"),
        ("iso15765", "0x7e8#215a5a5a46343043", DissectionKind.INFO, "consecutive frame 1"),
        (
            "iso15765",
            "0x7e0#30000a",
            DissectionKind.INFO,
            "continue to send, block size 0, STmin 0x0a",
        ),
        ("iso15765", "0x7e0#40", None, None),
        # Truncated or invalid frames.
        ("iso15765", "0x7e0#30", None, None),
        ("iso15765", "0x7e0#", None, None),
        ("iso15765", "22f190", None, None),
        ("unknown", "22f190", None, None),
    ],
)
def test_dissect(proto: str, data: str, kind: DissectionKind | None, text: str | None) -> None:
    dissection = dissect(proto, data)
    if kind is None:
        assert dissection is None
        return
    assert dissection is not None
    assert dissection.kind is kind
    assert text is not None and text in dissection.text


def test_register_dissector(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("gallia.dissect.DISSECTORS", dict(DISSECTORS))

    @dissector("test")
    def dissect_test(data: str) -> Dissection:
        if data == "broken":
            raise ValueError("broken")
        return Dissection(data.upper(), DissectionKind.INFO)

    assert dissect("test", "hello") == Dissection("HELLO", DissectionKind.INFO)
    # Exceptions of dissectors do not break hr.
    assert dissect("test", "broken") is None


def test_wireshark_pcap() -> None:
    # As created by text2pcap -F pcap -P uds.
    pcap = wireshark._pcap(252, wireshark._exported_pdu("uds", bytes.fromhex("22f190")))
    record_header = "00000000 00000000 0e000000 0e000000"
    assert pcap[24:] == bytes.fromhex(f"{record_header} 000c0003 756473 00000000 22f190")


@pytest.mark.skipif(not wireshark.available(), reason="tshark is not installed")
@pytest.mark.parametrize(
    ("proto", "data", "expected"),
    [
        ("uds", "22f190", "Data Identifier: 0xf190"),
        ("iso15765", "0x7e0#0322f190aaaaaaaa", "Data Identifier: 0xf190"),
        ("iso15765", "0x7e8#30000000", "Flow status: Continue to Send"),
        ("can", "0x18daf110#0210", "Extended Flag: True"),
    ],
)
def test_wireshark(proto: str, data: str, expected: str) -> None:
    tree = wireshark.dissect(proto, data)
    assert tree is not None
    assert any(expected in line for line in tree)
    # The layers which only wrap the message are omitted.
    assert not any(line.startswith(("Frame ", "EXPORTED_PDU")) for line in tree)


def test_wireshark_invalid() -> None:
    assert wireshark.dissect("uds", "no hex") is None
    assert wireshark.dissect("can", "no frame") is None
