# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import pytest

from gallia.log import setup_logging
from gallia.net import split_host_port
from gallia.services.uds.core.utils import (
    address_and_size_length,
    uds_memory_parameters,
)

setup_logging()


@pytest.mark.parametrize("hostport", ["[fec2::10]:4509823409582350", "hallo:3575983275498230"])
def test_split_host_port_broken(hostport: str) -> None:
    with pytest.raises(ValueError):
        split_host_port(hostport)


@pytest.mark.parametrize(
    "hostport,default_port,expected_host,expected_port",
    [
        ("1.1.1.1", None, "1.1.1.1", None),
        ("1.1.1.1:80", 22, "1.1.1.1", 80),
        ("::1", 22, "::1", 22),
        ("[::1]:80", None, "::1", 80),
        ("[fec2::10]:1234", 22, "fec2::10", 1234),
        ("[fec2::10]:80", None, "fec2::10", 80),
        ("fec2::10", 22, "fec2::10", 22),
        ("foo", 22, "foo", 22),
        ("foo", None, "foo", None),
        ("foo:1234", 22, "foo", 1234),
    ],
)
def test_split_host_port_default(
    hostport: str, default_port: int | None, expected_host: str, expected_port: int | None
) -> None:
    host, port = split_host_port(hostport, default_port)
    assert host == expected_host
    assert port == expected_port


@pytest.mark.parametrize(
    "address,size,addr_and_len,expected_fmt,expected_addr,expected_size",
    [
        # Arbitrary test case with one size having even and one odd nibble size
        (
            0x1234567890,
            0x12345,
            None,
            0x35,
            bytes([0x12, 0x34, 0x56, 0x78, 0x90]),
            bytes([0x01, 0x23, 0x45]),
        ),
        # Using an explicit addressAndLengthFormatIdentifier
        (
            0x1234567890,
            0x12345,
            0x56,
            0x56,
            bytes([0x00, 0x12, 0x34, 0x56, 0x78, 0x90]),
            bytes([0x00, 0x00, 0x01, 0x23, 0x45]),
        ),
        # The value zero should also result in one byte (corner case for lowest applicable value)
        (0x0, 0x0, None, 0x11, bytes([0x00]), bytes([0x00])),
        # The max value should result in the max bytes (corner case for highest applicable value)
        (256**15 - 1, 256**15 - 1, None, 0xFF, bytes([0xFF] * 15), bytes([0xFF] * 15)),
        # Corner case between two byte sizes
        (0xFF, 0x100, None, 0x21, bytes([0xFF]), bytes([0x01, 0x00])),
    ],
)
def test_uds_memory_parameters(
    address: int,
    size: int,
    addr_and_len: int | None,
    expected_fmt: int,
    expected_addr: bytes,
    expected_size: bytes,
) -> None:
    fmt, addr, sz = uds_memory_parameters(address, size, addr_and_len)
    assert fmt == expected_fmt
    assert addr == expected_addr
    assert sz == expected_size


@pytest.mark.parametrize(
    "address,size,address_and_len,expected_exception",
    [
        (256**15, 1, None, OverflowError),
        (1, 256**15, None, OverflowError),
        (-1, 1, None, OverflowError),
        (1, -1, None, OverflowError),
        (256, 0, 0x11, OverflowError),
        (0, 256, 0x11, OverflowError),
        (0, 0, 0x100, ValueError),
        (0, 0, 0x01, ValueError),
        (0, 0, 0x10, ValueError),
    ],
)
def test_uds_memory_parameters_errors(
    address: int, size: int, address_and_len: int | None, expected_exception: type[Exception]
) -> None:
    with pytest.raises(expected_exception):
        uds_memory_parameters(address, size, address_and_len)


@pytest.mark.parametrize(
    "address_and_len,expected_addr_len,expected_size_len",
    [
        # Arbitrary test case with different lengths
        (0x74, 4, 7),
        # Lowest applicable value
        (0x11, 1, 1),
        # Highest applicable value
        (0xFF, 0xF, 0xF),
    ],
)
def test_address_and_size_length(
    address_and_len: int,
    expected_addr_len: int,
    expected_size_len: int,
) -> None:
    address_length, size_length = address_and_size_length(address_and_len)
    assert address_length == expected_addr_len
    assert size_length == expected_size_len


@pytest.mark.parametrize("input_", [0x10, 0x01, 0x100])
def test_invalid_address_and_size_length(input_: int) -> None:
    with pytest.raises(ValueError):
        address_and_size_length(input_)
