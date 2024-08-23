# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

assert sys.platform.startswith("linux"), "unsupported platform"

import pytest
from pydantic import ValidationError

from gallia.transports import TargetURI
from gallia.transports.doip import DoIPConfig
from gallia.transports.isotp import ISOTPConfig
from gallia.transports.schemes import TransportScheme

uris = [
    "doip://127.0.0.1:13400?src_addr=1&target_addr=1",
    "doip://127.0.0.1:13400?src_addr=0x1&target_addr=1",
    "doip://127.0.0.1:13400?src_addr=1&target_addr=0x1",
    "isotp://can0?src_addr=1&dst_addr=1",
    "isotp://can0?src_addr=0x01&dst_addr=1",
    "isotp://can0?src_addr=1&dst_addr=0x01",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=1",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=1",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01&frame_txtime=10&is_extended=true",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01&frame_txtime=10&is_extended=true&tx_padding=0x01",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01&frame_txtime=10&is_extended=true&tx_padding=0x01&rx_padding=0x01",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01&frame_txtime=10&is_extended=true&tx_padding=0x01&rx_padding=0x01&tx_dl=1",
]

invalid_uris = [
    "doip://127.0.0.1:13400?src_addr=1",
    "doip://127.0.0.1:13400?target_addr=1" "doip://127.0.0.1:13400?src_addr=0x01&target_addr=hans",
    "doip://127.0.0.1:13400?src_addr=hans&target_addr=0x01",
    "isotp://can0?src_addr=1",
    "isotp://can0?dst_addr=1",
    "isotp://can0?src_addr=1&dst_addr=0x01&ext_addr=0x01&rx_ext_address=0x01&frame_txtime=foo",
]


def _test_uri(uri: str) -> None:
    parsed_uri = TargetURI(uri)
    match parsed_uri.scheme:
        case TransportScheme.DOIP:
            DoIPConfig(**parsed_uri.qs_flat)
        case TransportScheme.ISOTP:
            ISOTPConfig(**parsed_uri.qs_flat)
        case _:
            raise ValueError(f"uncovered scheme: {parsed_uri.scheme}")


def test_uris() -> None:
    for uri in uris:
        _test_uri(uri)


def test_invalid_uris() -> None:
    for uri in invalid_uris:
        with pytest.raises(ValidationError):
            _test_uri(uri)
