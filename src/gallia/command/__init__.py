# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

__lazy_modules__ = {"gallia.command.uds"}

from gallia.command.base import AsyncScript
from gallia.command.uds import UDSScanner

__all__ = [
    "AsyncScript",
    "UDSScanner",
]
