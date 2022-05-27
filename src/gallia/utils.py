import ipaddress
import re
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse

from gallia.uds.core.utils import bytes_repr, int_repr
from gallia.uds.core.service import NegativeResponse


def split_host_port(
    hostport: str,
    default_port: Optional[int] = None,
) -> tuple[str, Optional[int]]:
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

    # Only parse of hostport is not a valid ip address.
    if host == "":
        # urlparse() and urlsplit() insists on absolute URLs starting with "//".
        url = urlparse(f"//{hostport}")
        host = url.hostname if url.hostname else url.netloc
        port = url.port if url.port else default_port
    return host, port


def camel_to_snake(s: str) -> str:
    """Convert a CamelCase string to a snake_case string."""
    # https://stackoverflow.com/a/12867228
    return re.sub(r"((?<=[a-z0-9])[A-Z]|(?!^)[A-Z](?=[a-z]))", r"_\1", s).lower()


def camel_to_dash(s: str) -> str:
    """Convert a CamelCase string to a dash-case string."""
    return camel_to_snake(s).replace("_", "-")


def isotp_addr_repr(a: int) -> str:
    """
    Default string representation of a CAN id.
    """
    return f"{a:02x}"


def can_id_repr(i: int) -> str:
    """
    Default string representation of a CAN id.
    """
    return f"{i:03x}"


def g_repr(x: Any) -> str:
    """
    Object string representation with default gallia output settings.
    """
    if isinstance(x, Enum):
        return x.name
    if isinstance(x, bool):
        return repr(x)
    if isinstance(x, int):
        return int_repr(x)
    elif isinstance(x, str):
        return x
    elif isinstance(x, (bytes, bytearray)):
        return bytes_repr(x)
    elif isinstance(x, list):
        return f'[{", ".join(g_repr(y) for y in x)}]'
    elif isinstance(x, dict):
        return f'{{{", ".join(f"{g_repr(k)}: {g_repr(v)}" for k, v in x.items())}}}'
    elif isinstance(x, NegativeResponse):
        return str(x)
    else:
        return repr(x)
