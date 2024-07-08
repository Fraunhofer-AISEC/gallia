# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.doip import DoIPTransport
from gallia.transports.tcp import TCPLinesTransport, TCPTransport

registry: list[type[BaseTransport]] = [
    DoIPTransport,
    TCPLinesTransport,
    TCPTransport,
]

__all__ = [
    "BaseTransport",
    "DoIPTransport",
    "TCPLinesTransport",
    "TCPTransport",
    "TargetURI",
]


if sys.platform == "linux":
    from gallia.transports.isotp import ISOTPTransport

    registry.append(ISOTPTransport)
    __all__.append("ISOTPTransport")

    from gallia.transports.can import RawCANTransport

    registry.append(RawCANTransport)
    __all__.append("RawCANTransport")

    from gallia.transports.unix import UnixLinesTransport, UnixTransport

    registry.append(UnixLinesTransport)
    __all__.append("UnixLinesTransport")
    registry.append(UnixTransport)
    __all__.append("UnixTransport")


if sys.platform == "win32":
    # from gallia.transports.vector import FlexrayTPTransport, RawFlexrayTransport
    from gallia.transports.vector import RawFlexrayTransport

    registry.append(RawFlexrayTransport)
    __all__.append("RawFlexrayTransport")
    # registry.append(FlexrayTPTransport)
    # __all__.append("FlexrayTPTransport")
