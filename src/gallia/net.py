# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import json
import subprocess
import sys

import pydantic
from pydantic.networks import IPvAnyAddress

from gallia.log import get_logger

logger = get_logger(__name__)


class AddrInfo(pydantic.BaseModel):
    family: str
    local: IPvAnyAddress
    prefixlen: int
    broadcast: IPvAnyAddress | None = None
    scope: str
    label: str | None = None
    valid_life_time: int
    preferred_life_time: int

    def is_v4(self) -> bool:
        return self.family == "inet"


class Interface(pydantic.BaseModel):
    ifindex: int
    ifname: str
    flags: list[str]
    mtu: int
    qdisc: str
    operstate: str
    group: str
    link_type: str
    address: str | None = None
    broadcast: str | None = None
    addr_info: list[AddrInfo]

    def is_up(self) -> bool:
        return self.operstate == "UP"

    def can_broadcast(self) -> bool:
        return "BROADCAST" in self.flags


def net_if_addrs() -> list[Interface]:
    if sys.platform != "linux":
        raise NotImplementedError("net_if_addrs() is only supported on Linux platforms")

    try:
        p = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, check=True)
    except FileNotFoundError as e:
        logger.warning(f"Could not query information about interfaces: {e}")
        return []

    try:
        return [Interface(**item) for item in json.loads(p.stdout.decode())]
    except pydantic.ValidationError as e:
        logger.error("BUG: A special case for `ip -j address show` is not handled!")
        logger.error("Please report a bug including the following json string.")
        logger.error("https://github.com/Fraunhofer-AISEC/gallia/issues")
        logger.error(e.json())
        raise


def net_if_broadcast_addrs() -> list[AddrInfo]:
    out = []
    for iface in net_if_addrs():
        if not (iface.is_up() and iface.can_broadcast()):
            continue

        for addr in iface.addr_info:
            if not addr.is_v4() or addr.broadcast is None:
                continue
            out.append(addr)
    return out
