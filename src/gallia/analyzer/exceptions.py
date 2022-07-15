# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""
gallia-analyze Exceptions module
"""


class EmptyTableException(Exception):
    """
    exception class for empty table error
    """

    def __init__(self) -> None:
        super().__init__("Empty Table.")


class ColumnMismatchException(Exception):
    """
    exception class for column mismatch
    """

    def __init__(self) -> None:
        super().__init__("Columns Mismatch.")
