# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import ipaddress
import subprocess
from urllib.parse import urlparse

import pydantic
from pydantic.networks import IPvAnyAddress

from gallia.log import get_logger
from gallia.utils import supports_platform

logger = get_logger(__name__)


def split_host_port(
    hostport: str,
    default_port: int | None = None,
) -> tuple[str, int | None]:
    """Splits a combination of ip address/hostname + port into hostname/ip address
    and port.  The default_port argument can be used to return a port if it is
    absent in the hostport argument."""
    # Special case: If hostport is an ipv6 then the urlparser does some weird
    # things with the colons and tries to parse ports. Catch this case early.
    host = ""
    port = default_port
    try:
        # If hostport is a valid ip address (v4 or v6) there
        # is no port included
        host = str(ipaddress.ip_address(hostport))
    except ValueError:
        pass

    # Only parse if hostport is not a valid ip address.
    if host == "":
        # urlparse() and urlsplit() insists on absolute URLs starting with "//".
        url = urlparse(f"//{hostport}")
        host = url.hostname if url.hostname else url.netloc
        port = url.port if url.port else default_port
    return host, port


def join_host_port(host: str, port: int) -> str:
    if ":" in host:
        return f"[{host}]:port"
    return f"{host}:{port}"


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


@supports_platform("linux")
def net_if_addrs() -> list[Interface]:
    try:
        p = subprocess.run(["ip", "-j", "address", "show"], capture_output=True, check=True)
    except FileNotFoundError as e:
        logger.warning(f"Could not query information about interfaces: {e}")
        return []

    try:
        iface_list_type = pydantic.TypeAdapter(list[Interface])
        return iface_list_type.validate_json(p.stdout.decode())
    except pydantic.ValidationError as e:
        logger.error("BUG: A special case for `ip -j address show` is not handled!")
        logger.error("Please report a bug including the following json string.")
        logger.error("https://github.com/Fraunhofer-AISEC/gallia/issues")
        logger.error(e.json())
        raise


@supports_platform("linux")
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
