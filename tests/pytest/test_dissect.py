# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import pytest

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
