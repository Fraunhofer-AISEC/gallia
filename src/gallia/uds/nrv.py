# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from ctypes import (
    CDLL,
    POINTER,
    Array,
    byref,
    c_char,
    c_char_p,
    c_int,
    c_uint,
    create_string_buffer,
)
from ctypes.util import find_library
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _CArgObject

DEFAULT_BUFFER_LIMIT = 2**28
UCL_UNAVAILABLE = "libucl is not available!"


libucl = None
if (lib := find_library("ucl")) is not None:
    libucl = CDLL(lib)


# TODO: Loop for large buffers.
def nrv2b_decompress_8(in_data: bytes | bytearray, out_size: int) -> bytes:
    if libucl is None:
        raise RuntimeError(UCL_UNAVAILABLE)
    in_data_ = bytes(in_data)
    f = libucl.ucl_nrv2b_decompress_safe_8
    f.argtypes = [c_char_p, c_uint, c_char_p, POINTER(c_uint), c_char_p]
    f.restype = c_int
    in_buf = create_string_buffer(in_data_)
    out_buf = create_string_buffer(out_size)
    new_len = c_uint(out_size)
    r = f(in_buf, len(in_data_), out_buf, byref(new_len), None)
    if r != 0:
        raise RuntimeError(f"could not decompress nrv data, exit code {r}")
    return bytes(out_buf.raw)


def _execute_nrv_operation_blindly(
    in_data: bytes | bytearray,
    operation: Callable[[Array[c_char], int, Array[c_char], "_CArgObject"], int],
    buffer_limit: int,
) -> bytes:
    """Executes an NRV operation without knowing the size of the result.

    Args:
      in_data: The data to (de)compress.
      operation: A wrapper around) the function which computes the (de)compression function which
                     takes the four parameters (in_buf, in_buffer_size, out_buf, new_len) and
                     returns the return code of the function.
      buffer_limit: The maximum number of bytes which can be allocated for the output buffer.

    Returns:
      The (de)compressed data.

    """
    in_data_ = bytes(in_data)
    in_buffer_size = len(in_data_)
    in_buf = create_string_buffer(in_data_)

    # We will simply try bigger and bigger buffer sizes until it works but let's start with the
    # size of the incoming data
    out_buffer_size = min(buffer_limit, in_buffer_size * 2)
    out_buf = create_string_buffer(out_buffer_size)
    # For some reason this has to be set to something bigger than the new size in case of
    # decompressing
    new_len = c_uint(out_buffer_size)

    while True:
        r = operation(in_buf, in_buffer_size, out_buf, byref(new_len))

        # If the output buffer is too small
        if r == -202:
            out_buffer_size *= 2
            new_len = c_uint(out_buffer_size)

            if out_buffer_size > buffer_limit:
                raise RuntimeError("Trying to consume too much memory!")

            out_buf = create_string_buffer(out_buffer_size)
            continue

        if r != 0:
            raise RuntimeError(f"Error {r}: could not (de)compress nrv data")

        return bytes(out_buf.raw)[: new_len.value]


def nrv2b_decompress_8_blindly(
    in_data: bytes | bytearray,
    buffer_limit: int = DEFAULT_BUFFER_LIMIT,
) -> bytes:
    """Decompress NRV data without the need to know the size of the output.

    Args:
      in_data: The data to be decompressed
      buffer_limit: The maximum number of bytes which can be allocated for the output buffer.

    Returns:
      The decompressed data.

    """
    if libucl is None:
        raise RuntimeError(UCL_UNAVAILABLE)

    f = libucl.ucl_nrv2b_decompress_safe_8
    f.argtypes = [c_char_p, c_uint, c_char_p, POINTER(c_uint), c_char_p]
    f.restype = c_int

    # Wrapper around f to enable code sharing with nrv2b_compress_blindly using
    # _execute_nrv_operation_blindly
    def f_wrapper(a, b, c, d):  # type: ignore
        return f(a, b, c, d, None)

    return _execute_nrv_operation_blindly(in_data, f_wrapper, buffer_limit)


def nrv2b_compress_blindly(
    in_data: bytes | bytearray,
    level: int = 1,
    buffer_limit: int = DEFAULT_BUFFER_LIMIT,
) -> bytes:
    """Compress NRV data without the need to know the size of the output.

    Args:
      in_data: The data to be compressed
      level: The compression level, where 1 is the lowest and 10 is the highest compression.
      buffer_limit: The maximum number of bytes which can be allocated for the output buffer.

    Returns:
      The compressed data.

    """
    if libucl is None:
        raise RuntimeError(UCL_UNAVAILABLE)

    if level < 1 or level > 10:
        raise ValueError("The compression level must be between 1 and 10!")

    f = libucl.ucl_nrv2b_99_compress
    f.argtypes = [
        c_char_p,
        c_uint,
        c_char_p,
        POINTER(c_uint),
        POINTER(c_int),
        c_int,
        POINTER(c_int),
        POINTER(c_int),
    ]
    f.restype = c_int

    # Wrapper around f to enable code sharing with nrv2b_decompress_8_blindly using
    # _execute_nrv_operation_blindly
    def f_wrapper(a, b, c, d):  # type: ignore
        return f(a, b, c, d, None, level, None, None)

    return _execute_nrv_operation_blindly(in_data, f_wrapper, buffer_limit)
