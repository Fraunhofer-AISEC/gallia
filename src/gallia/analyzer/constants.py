"""
gallia-analyze Const module
"""
from enum import IntEnum

if __name__ == "__main__":
    exit()


class UDSIsoSessions(IntEnum):
    """
    enum class for diagnostic sessions defined in UDS ISO standard
    """

    DEFAULT_SESSION = 0x01
    PROGRAMMING_SESSION = 0x02
    EXTENDED_DIAGNOSTIC_SESSION = 0x03
    SAFETY_SYSTEM_DIAGNOSTIC_SESSION = 0x04


class SqlDataType:
    """
    class for SQL data types
    """

    integer = "INTEGER"
    text = "TEXT"
    null = "NULL"
    real = "REAL"
    blob = "BLOB"
