# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from importlib.metadata import entry_points

from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.can import ISOTPTransport, RawCANTransport
from gallia.transports.doip import DoIPTransport
from gallia.transports.tcp import TCPLinesTransport, TCPTransport


def load_transports() -> list[type[BaseTransport]]:
    out = []
    eps = entry_points()
    if (s := "gallia_transports") in eps:
        for ep in eps.select(group=s):
            for t in ep.load():
                if not issubclass(t, BaseTransport):
                    raise ValueError(f"{type(t)} is not derived from BaseTransport")
                out.append(t)
    return out


def load_transport(target: TargetURI) -> type[BaseTransport]:
    transports: list[type[BaseTransport]] = [
        ISOTPTransport,
        RawCANTransport,
        DoIPTransport,
        TCPTransport,
        TCPLinesTransport,
    ]

    transports += load_transports()

    for transport in transports:
        if target.scheme == transport.SCHEME:
            return transport

    raise ValueError(f"no transport for {target}")
