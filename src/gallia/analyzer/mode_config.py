"""
gallia-analyze Mode Config module
"""

from enum import IntEnum


class ScanMode(IntEnum):
    """
    enum class for scan mode
    """

    SERV = 0x01
    IDEN = 0x02
    UNKNOWN = 0x00


class OpMode(IntEnum):
    """
    enum class for analysis mode
    """

    VEN_SPEC = 0x01
    ISO = 0x02


class LogMode(IntEnum):
    """
    enum class for log mode
    """

    STD_OUT = 0x01
    LOG_FILE = 0x02
    DUBUG = 0x03
