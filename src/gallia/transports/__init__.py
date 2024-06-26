# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.can import RawCANTransport
from gallia.transports.doip import DoIPTransport
from gallia.transports.isotp import ISOTPTransport
from gallia.transports.tcp import TCPLinesTransport, TCPTransport
from gallia.transports.unix import UnixLinesTransport, UnixTransport

registry: list[type[BaseTransport]] = [
    DoIPTransport,
    ISOTPTransport,
    RawCANTransport,
    TCPLinesTransport,
    TCPTransport,
    UnixLinesTransport,
    UnixTransport,
]

__all__ = [
    "BaseTransport",
    "DoIPTransport",
    "ISOTPTransport",
    "RawCANTransport",
    "TCPLinesTransport",
    "TCPTransport",
    "UnixLinesTransport",
    "UnixTransport",
    "TargetURI",
]


if sys.platform == "windows":
    from gallia.transports import vector

    registry.append(vector.FlexrayTransport)
    __all__.append("FlexrayTransport")
