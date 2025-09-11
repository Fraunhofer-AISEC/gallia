# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from enum import StrEnum, unique

TCP = "tcp"
TCP_LINES = "tcp-lines"
DOIP = "doip"
DUMMY = "dummy"


if sys.platform.startswith("linux"):

    @unique
    class TransportScheme(StrEnum):
        TCP = TCP
        TCP_LINES = TCP_LINES
        DOIP = DOIP
        DUMMY = DUMMY

        HSFZ = "hsfz"
        UNIX = "unix"
        UNIX_LINES = "unix-lines"
        ISOTP = "isotp"
        CAN_RAW = "can-raw"


if sys.platform == "win32":

    @unique
    class TransportScheme(StrEnum):
        TCP = TCP
        TCP_LINES = TCP_LINES
        DOIP = DOIP
        DUMMY = DUMMY

        FLEXRAY_RAW = "fr-raw"
        FLEXRAY_TP_LEGACY = "fr-tp-legacy"
