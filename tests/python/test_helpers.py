# mypy: allow-untyped-defs

import pytest
from gallia.uds.core.utils import uds_memory_parameters, address_and_size_length
from gallia.uds.helpers import cmd_output, split_host_port


def test_split_host_port_v4():
    host, port = split_host_port("1.2.3.4:82")
    assert host == "1.2.3.4"
    assert port == 82


def test_split_host_port_v6():
    host, port = split_host_port("[fec2::10]:80")
    assert host == "fec2::10"
    assert port == 80
    host, port = split_host_port("[::1]:80")
    assert host == "::1"
    assert port == 80


def test_split_host_port_broken():
    with pytest.raises(ValueError):
        split_host_port("[fec2::10]:4509823409582350")

    with pytest.raises(ValueError):
        split_host_port("hallo:3575983275498230")


def test_split_host_port_default():
    host, port = split_host_port("1.1.1.1", 22)
    assert host == "1.1.1.1"
    assert port == 22
    host, port = split_host_port("1.1.1.1")
    assert port is None
    host, port = split_host_port("fec2::10", 22)
    assert host == "fec2::10"
    assert port == 22
    host, port = split_host_port("::1", 22)
    assert host == "::1"
    assert port == 22
    host, port = split_host_port("[fec2::10]:1234", 22)
    assert host == "fec2::10"
    assert port == 1234
    host, port = split_host_port("foo:1234", 22)
    assert host == "foo"
    assert port == 1234
    host, port = split_host_port("foo", 22)
    assert host == "foo"
    assert port == 22
    host, port = split_host_port("foo")
    assert host == "foo"
    assert port is None


@pytest.mark.asyncio
async def test_cmd_output():
    assert await cmd_output(["uname"]) == "Linux"


def test_uds_memory_parameters():
    # Arbitrary test case with one size having even and one odd nibble size
    fmt, addr, size = uds_memory_parameters(0x1234567890, 0x12345)
    assert fmt == 0x35
    assert addr == bytes([0x12, 0x34, 0x56, 0x78, 0x90])
    assert size == bytes([0x01, 0x23, 0x45])

    # Using an explicit addressAndLengthFormatIdentifier
    fmt, addr, size = uds_memory_parameters(0x1234567890, 0x12345, 0x56)
    assert fmt == 0x56
    assert addr == bytes([0x00, 0x12, 0x34, 0x56, 0x78, 0x90])
    assert size == bytes([0x00, 0x00, 0x01, 0x23, 0x45])

    # The value zero should also result in one byte (corner case for lowest applicable value)
    fmt, addr, size = uds_memory_parameters(0x0, 0x0)
    assert fmt == 0x11
    assert addr == bytes([0x00])
    assert size == bytes([0x00])

    # The max value should result in the max bytes (corner case for highest applicable value)
    fmt, addr, size = uds_memory_parameters(256**15 - 1, 256**15 - 1)
    assert fmt == 0xff
    assert addr == bytes([0xff] * 15)
    assert size == bytes([0xff] * 15)

    # Corner case between two byte sizes
    fmt, addr, size = uds_memory_parameters(0xff, 0x100)
    assert fmt == 0x21
    assert addr == bytes([0xff])
    assert size == bytes([0x01, 0x00])

    # Lowest value which is out of range
    with pytest.raises(OverflowError):
        uds_memory_parameters(256**15, 1)

    # Lowest value which is out of range
    with pytest.raises(OverflowError):
        uds_memory_parameters(1, 256**15)

    # Highest value which is out of range
    with pytest.raises(OverflowError):
        uds_memory_parameters(-1, 1)

    # Highest value which is out of range
    with pytest.raises(OverflowError):
        uds_memory_parameters(1, -1)

    # Values not representable using the given addressAndLengthFormatIdentifier
    with pytest.raises(OverflowError):
        uds_memory_parameters(256, 0, 0x11)

    # Values not representable using the given addressAndLengthFormatIdentifier
    with pytest.raises(OverflowError):
        uds_memory_parameters(0, 256, 0x11)

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        uds_memory_parameters(0, 0, 0x100)

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        uds_memory_parameters(0, 0, 0x01)

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        uds_memory_parameters(0, 0, 0x10)


def test_address_and_size_length():
    # Arbitrary test case with different lengths
    address_length, size_length = address_and_size_length(0x74)
    assert address_length == 4
    assert size_length == 7

    # Lowest applicable value
    address_length, size_length = address_and_size_length(0x11)
    assert address_length == 1
    assert size_length == 1

    # Highest applicable value
    address_length, size_length = address_and_size_length(0xff)
    assert address_length == 0xf
    assert size_length == 0xf

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        address_and_size_length(0x10)

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        address_and_size_length(0x01)

    # Invalid addressAndLengthFormatIdentifier
    with pytest.raises(ValueError):
        address_and_size_length(0x100)
