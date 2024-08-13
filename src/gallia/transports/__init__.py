# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.doip import DoIPTransport
from gallia.transports.hsfz import HSFZTransport
from gallia.transports.schemes import TransportScheme
from gallia.transports.tcp import TCPLinesTransport, TCPTransport

registry: list[type[BaseTransport]] = [
    DoIPTransport,
    HSFZTransport,
    TCPLinesTransport,
    TCPTransport,
]

__all__ = [
    "BaseTransport",
    "DoIPTransport",
    "HSFZTransport",
    "TCPLinesTransport",
    "TCPTransport",
    "TargetURI",
    "TransportScheme",
]

if sys.platform.startswith("linux"):
    from gallia.transports.can import RawCANTransport
    from gallia.transports.isotp import ISOTPTransport
    from gallia.transports.unix import UnixLinesTransport, UnixTransport

    registry.append(ISOTPTransport)
    registry.append(RawCANTransport)
    registry.append(UnixLinesTransport)
    registry.append(UnixTransport)

    __all__ += [
        "ISOTPTransport",
        "RawCANTransport",
        "UnixLinesTransport",
        "UnixTransport",
    ]


if sys.platform == "win32":
    from gallia.transports.flexray_vector import FlexRayTPLegacyTransport, RawFlexRayTransport

    registry.append(RawFlexRayTransport)
    registry.append(FlexRayTPLegacyTransport)

    __all__ += ["FlexRayTPTransport", "FlexRayTPLegacyTransport"]
