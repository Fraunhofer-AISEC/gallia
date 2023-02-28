# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from gallia.transports import TargetURI
from gallia.transports.doip import DoIPConfig
from pydantic import ValidationError

uris = [
    "doip://127.0.0.1:13400?src_addr=1&target_addr=1",
    "doip://127.0.0.1:13400?src_addr=0x1&target_addr=1",
    "doip://127.0.0.1:13400?src_addr=1&target_addr=0x1",
]

invalid_uris = [
    "doip://127.0.0.1:13400?src_addr=1",
    "doip://127.0.0.1:13400?target_addr=1"
    "doip://127.0.0.1:13400?src_addr=0x01&target_addr=hans",
    "doip://127.0.0.1:13400?src_addr=hans&target_addr=0x01",
]


def _test_uri(uri: str) -> None:
    parsed_uri = TargetURI(uri)
    match parsed_uri.scheme:
        case "doip":
            DoIPConfig(**parsed_uri.qs_flat)
        case _:
            raise ValueError(f"uncovered scheme: {parsed_uri.scheme}")


def test_uris() -> None:
    for uri in uris:
        _test_uri(uri)


def test_invalid_uris() -> None:
    for uri in invalid_uris:
        with pytest.raises(ValidationError):
            _test_uri(uri)
