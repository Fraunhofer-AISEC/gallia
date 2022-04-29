import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse


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
