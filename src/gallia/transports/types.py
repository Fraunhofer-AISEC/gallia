# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from gallia.utils import join_host_port


class TargetURI:
    """TargetURI represents a target to which gallia can connect.
    The target string must conform to a URI is specified by RFC3986.

    Basically, this is a wrapper around Python's ``urlparse()`` and
    ``parse_qs()`` methods. TargetURI provides frequently used properties
    for a more userfriendly usage. Instances are meant to be passed to
    :meth:`BaseTransport.connect()` of transport implementations.
    """

    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.url = urlparse(raw)
        self.qs = parse_qs(self.url.query)

    @classmethod
    def from_parts(
        cls,
        scheme: str,
        host: str,
        port: int | None,
        args: dict[str, Any],
    ) -> TargetURI:
        """Constructs a instance of TargetURI with the given arguments.
        The ``args`` dict is used for the query string.
        """
        netloc = host if port is None else join_host_port(host, port)
        return TargetURI(urlunparse((scheme, netloc, "", "", urlencode(args), "")))

    @property
    def scheme(self) -> str:
        """The URI scheme"""
        return self.url.scheme

    @property
    def hostname(self) -> str | None:
        """The hostname (without port)"""
        return self.url.hostname

    @property
    def port(self) -> int | None:
        """The port number"""
        return self.url.port

    @property
    def netloc(self) -> str:
        """The hostname and the portnumber, separated by a colon."""
        return self.url.netloc

    @property
    def location(self) -> str:
        """A URI string which only consists of the relevant scheme,
        the host and the port.
        """
        return f"{self.scheme}://{self.url.netloc}"

    @property
    def qs_flat(self) -> dict[str, str]:
        """A dict which contains the query string's key/value pairs.
        In case a key appears multiple times, this variant only
        contains the first found key/value pair. In contrast to
        :attr:`qs`, this variant avoids lists and might be easier
        to use for some cases.
        """
        d = {}
        for k, v in self.qs.items():
            d[k] = v[0]
        return d

    def __str__(self) -> str:
        return self.raw
