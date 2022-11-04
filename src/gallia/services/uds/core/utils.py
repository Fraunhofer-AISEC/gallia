# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from binascii import hexlify
from enum import Enum
from math import ceil
from typing import Any

from gallia.services.uds.core.constants import UDSIsoServices


def from_bytes(x: bytes) -> int:
    return int.from_bytes(x, "big")


def to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def check_range(data: int, name: str, min_value: int, max_value: int) -> None:
    if not min_value <= data <= max_value:
        raise ValueError(
            f"The {name} parameter must be between {int_repr(min_value)} and "
            f"{int_repr(max_value)}"
        )


def check_data_identifier(data_identifier: int) -> None:
    if not 0 <= data_identifier <= 0xFFFF:
        raise ValueError(f"Not a valid dataIdentifier: {int_repr(data_identifier)}")


def check_sub_function(sub_function: int) -> None:
    if not 0 <= sub_function <= 0x7F:
        raise ValueError(f"Not a valid subFunction: {int_repr(sub_function)}")


def check_length(
    pdu: bytes, minimal_length: int = 0, maximal_length: int | None = None
) -> None:
    if len(pdu) < 1:
        raise ValueError("The PDU is empty")

    if len(pdu) < minimal_length:
        raise ValueError("The PDU is incomplete")

    if maximal_length is not None and len(pdu) > maximal_length:
        raise ValueError("The PDU contains more data than expected")


def int_repr(n: int, prefix: bool = True) -> str:
    s = f"{n:x}"

    if len(s) % 2 == 1:
        s = f"0{s}"

    if prefix:
        s = f"0x{s}"

    return s


def any_repr(x: Any) -> str:
    if isinstance(x, bool):
        return repr(x)
    if isinstance(x, int):
        return int_repr(x)
    if isinstance(x, (bytes, bytearray)):
        return bytes_repr(x)
    if isinstance(x, list):
        return f'[{", ".join(any_repr(y) for y in x)}]'

    return str(x)


def g_repr(x: Any) -> str:
    """
    Object string representation with default gallia output settings.
    """
    if isinstance(x, Enum):
        return str(x.name)
    if isinstance(x, bool):
        return repr(x)
    if isinstance(x, int):
        return int_repr(x)
    if isinstance(x, str):
        return x
    if isinstance(x, (bytes, bytearray)):
        return bytes_repr(x)
    if isinstance(x, list):
        return f'[{", ".join(g_repr(y) for y in x)}]'
    if isinstance(x, dict):
        return f'{{{", ".join(f"{g_repr(k)}: {g_repr(v)}" for k, v in x.items())}}}'
    # XXX: Avoid the import which causes cyclic imports.
    # TODO: Find out how to replace this helper.
    if type(x).__name__ == "NegativeResponse":
        return str(x)
    return repr(x)


def bytes_repr(b: bytes, prefix: bool = False, max_length: int | None = 20) -> str:
    if len(b) == 0:
        return "''"

    s = hexlify(b).decode()

    if max_length is not None and len(s) > max_length:
        s = s[: max_length - 3] + "..."

    return s


def service_repr(service_id: int) -> str:
    try:
        return str(UDSIsoServices(service_id).name)
    except Exception:
        return f"Unknown service {int_repr(service_id)}"


def uds_memory_parameters(
    memory_address: int, memory_size: int, address_and_length_fmt: int | None = None
) -> tuple[int, bytes, bytes]:
    """Transfers the address and size into bytes and computes the corresponding
    addressAndLengthFormatIdentifier (cf. ISO 14229-1) and returns all three.
    The resulting parameters are used in several memory-related UDSClient services.
    Optionally, a desired addressAndLengthFormatIdentifier can be passed, which
    will then be used to turn the ints to the specified length as opposed to
    the minimal byte length.

    Args:
      memory_address: The memory address.
      memory_size: The memory size.
      address_and_length_fmt: Optionally specifies the byte lengths of the
          address and size. If given, the first returned value will be equal to
          this one.

    Returns:
      The UDSClient memory parameters as a tuple, comprised of
       - the addressAndLengthFormatIdentifier
         which specifies the byte lengths of the address and size.
       - memory address (in bytes).
       - memory size (in bytes).

    Raises:
      OverflowError: If any of the memory_address or memory_size parameters is
          either negative or cannot be represented by at most 15 bytes or the
          number of bytes as specified in address_and_length_fmt if given.
      ValueError: If address_and_length_fmt is given and has a wrong format,
          i.e. it is negative, exceeds 0xff or is zero in any of the two nibbles.
    """
    if memory_address < 0:
        raise OverflowError("The memory address must not be negative")
    if memory_size < 0:
        raise OverflowError("The memory size must not be negative")

    if address_and_length_fmt is not None:
        # If the format is given explicitly, format the parameters accordingly
        addr_len, size_len = address_and_size_length(address_and_length_fmt)
        addr_bytes = memory_address.to_bytes(addr_len, "big")
        size_bytes = memory_size.to_bytes(size_len, "big")
    else:
        # Otherwise transfer the parameters to the UDSClient request format

        # The byte length is always at least one, as also a zero must be encoded.
        addr_length = int(max(1, ceil(memory_address.bit_length() / 8)))
        size_length = int(max(1, ceil(memory_size.bit_length() / 8)))

        if addr_length > 0xF:
            raise OverflowError(
                "The memory address is too big to be encoded in the "
                "addressAndLengthFormatIdentifier"
            )
        if size_length > 0xF:
            raise OverflowError(
                "The memory size is too big to be encoded in the "
                "addressAndLengthFormatIdentifier"
            )

        addr_bytes = memory_address.to_bytes(addr_length, "big")
        size_bytes = memory_size.to_bytes(size_length, "big")
        address_and_length_fmt = (size_length << 4) | addr_length

    return address_and_length_fmt, addr_bytes, size_bytes


def address_and_size_length(address_and_length_fmt: int) -> tuple[int, int]:
    """Computes the memory_address and memory_size parameter's byte length
    based on the corresponding addressAndLengthFormatIdentifier (cf. ISO 14229-1)
    which is used in several memory-related UDSClient services.

    Args:
      address_and_length_fmt: Specifies the byte lengths of the address and size.

    Returns:
      The byte length of the address and size according to the given format as a
      tuple, comprised of:

       - The byte length of the memory address
       - The byte length of the memory size

    Raises:
        ValueError: If address_and_length_fmt has the wrong format,
            i.e. it is negative, exceeds 0xff or is zero in any of the two nibbles.
    """
    if not 0x00 <= address_and_length_fmt <= 0xFF:
        raise ValueError(
            "The addressAndLengthFormatIdentifier must not be negative "
            "nor exceed 0xff"
        )
    if address_and_length_fmt & 0xF0 == 0:
        raise ValueError(
            "The addressAndLengthFormatIdentifier's first nibble must not be 0"
        )
    if address_and_length_fmt & 0x0F == 0:
        raise ValueError(
            "The addressAndLengthFormatIdentifier's second nibble must not be 0"
        )

    addr_length = address_and_length_fmt & 0x0F
    size_length = (address_and_length_fmt & 0xF0) >> 4

    return addr_length, size_length


def sub_function_split(sub_function: int) -> tuple[int, bool]:
    """
    Returns the subFunction without suppress bit and if the bit was set.

    :return: The subFunction without suppress bit and if the bit was set.
    """
    return sub_function % 0x80, sub_function >= 0x80
