# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.doip import DoIPConfig, DoIPTransport
from gallia.transports.dummy import DummyTransport
from gallia.transports.hsfz import HSFZConfig, HSFZTransport
from gallia.transports.schemes import TransportScheme
from gallia.transports.tcp import TCPLinesTransport, TCPTransport

registry: list[type[BaseTransport]] = [
    DoIPTransport,
    DummyTransport,
    HSFZTransport,
    TCPLinesTransport,
    TCPTransport,
]

__all__ = [
    "BaseTransport",
    "DoIPConfig",
    "DoIPTransport",
    "DummyTransport",
    "HSFZConfig",
    "HSFZTransport",
    "TCPLinesTransport",
    "TCPTransport",
    "TargetURI",
    "TransportScheme",
]

if sys.platform.startswith("linux"):
    from gallia.transports.can import RawCANConfig, RawCANTransport
    from gallia.transports.isotp import ISOTPConfig, ISOTPTransport
    from gallia.transports.unix import UnixLinesTransport, UnixTransport

    registry.append(ISOTPTransport)
    registry.append(RawCANTransport)
    registry.append(UnixLinesTransport)
    registry.append(UnixTransport)

    __all__ += [
        "ISOTPConfig",
        "ISOTPTransport",
        "RawCANConfig",
        "RawCANTransport",
        "UnixLinesTransport",
        "UnixTransport",
    ]


if sys.platform == "win32":
    from gallia.transports.flexray_vector import (
        FlexrayTPLegacyConfig,
        FlexRayTPLegacyTransport,
        RawFlexRayConfig,
        RawFlexRayTransport,
    )

    registry.append(RawFlexRayTransport)
    registry.append(FlexRayTPLegacyTransport)

    __all__ += [
        "FlexRayTPLegacyTransport",
        "FlexrayTPLegacyConfig",
        "RawFlexRayConfig",
        "RawFlexRayTransport",
    ]
