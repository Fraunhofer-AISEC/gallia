# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import io
from abc import ABC, abstractmethod
from typing import Any, Protocol, Self
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from gallia.log import get_logger
from gallia.net import join_host_port
from gallia.transports.schemes import TransportScheme

logger = get_logger(__name__)


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
    ) -> Self:
        """Constructs a instance of TargetURI with the given arguments.
        The ``args`` dict is used for the query string.
        """
        netloc = host if port is None else join_host_port(host, port)
        return cls(urlunparse((scheme, netloc, "", "", urlencode(args), "")))

    @property
    def scheme(self) -> TransportScheme:
        """The URI scheme"""
        return TransportScheme(self.url.scheme)

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
    def path(self) -> str:
        """The path property of the url."""
        return self.url.path

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


class TransportProtocol(Protocol):
    mutex: asyncio.Lock
    target: TargetURI
    is_closed: bool

    def get_writer(self) -> asyncio.StreamWriter:
        raise NotImplementedError

    def get_reader(self) -> asyncio.StreamReader:
        raise NotImplementedError


class BaseTransport(ABC):
    """BaseTransport is the base class providing the required
    interface for all transports used by gallia.

    A transport usually is some kind of network protocol which
    carries an application level protocol. A good example is
    DoIP carrying UDS requests which acts as a minimal middleware
    on top of TCP.

    This class is to be used as a subclass with all abstractmethods
    implemented and the SCHEME property filled.

    A few methods provide a ``tags`` argument. The debug logs of these
    calls include these tags in the ``tags`` property of the relevant
    :class:`gallia.log.PenlogRecord`.
    """

    #: The scheme for the implemented protocol, e.g. "doip".
    SCHEME: str = ""
    #: The buffersize of the transport. Might be used in read() calls.
    #: Defaults to :const:`io.DEFAULT_BUFFER_SIZE`.
    BUFSIZE: int = io.DEFAULT_BUFFER_SIZE

    def __init__(self, target: TargetURI) -> None:
        self.mutex = asyncio.Lock()
        self.target = target
        self.is_closed = False

    def __init_subclass__(
        cls,
        /,
        scheme: str,
        bufsize: int = io.DEFAULT_BUFFER_SIZE,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls.SCHEME = scheme
        cls.BUFSIZE = bufsize

    @classmethod
    def check_scheme(cls, target: TargetURI) -> None:
        """Checks if the provided URI has the correct scheme."""
        if target.scheme != cls.SCHEME:
            raise ValueError(f"invalid scheme: {target.scheme}; expected: {cls.SCHEME}")

    @classmethod
    @abstractmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
        """Classmethod to connect the transport to a relevant target.
        The target argument is a URI, such as `doip://192.0.2.2:13400?src_addr=0xf4&dst_addr=0x1d"`
        An instance of the relevant transport class is returned.
        """

    @abstractmethod
    async def close(self) -> None:
        """Terminates the connection and clean up all allocated ressources."""

    async def reconnect(self, timeout: float | None = None) -> Self:
        """Closes the connection to the target and attempts to reconnect every
        100 ms until at max timeout. If timeout is None, only attempt to connect
        once.
        A new instance of this class is returned rendering the old one obsolete.
        This method is safe for concurrent use.
        """
        async with self.mutex:
            try:
                await self.close()
            except ConnectionError as e:
                logger.warning(f"close() failed during reconnect ({e!r}); ignoring")

            async with asyncio.timeout(timeout):
                logger.debug(
                    f"Attempting to establish a new connection with a timeout of {timeout}"
                )
                while True:
                    try:
                        return await self.connect(self.target)
                    except ConnectionError as e:
                        logger.info(f"Connection attempt failed while reconnecting: {e!r}")
                        if timeout is None:
                            logger.debug("Breaking out of the reconnect-loop since timeout is None")
                            raise e
                        await asyncio.sleep(0.1)

    @abstractmethod
    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        """Reads one message and returns its raw byte representation.
        An example for one message is 'one line, terminated by newline'
        for a TCP transport yielding lines.
        """

    @abstractmethod
    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        """Writes one message and return the number of written bytes."""

    async def request(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        """Chains a :meth:`write()` call with a :meth:`read()` call.
        The call is protected by a mutex and is thus safe for concurrent
        use.
        """
        async with self.mutex:
            return await self.request_unsafe(data, timeout, tags)

    async def request_unsafe(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        """Chains a :meth:`write()` call with a :meth:`read()` call.
        The call is **not** protected by a mutex. Only use this method
        when you know what you are doing.
        """
        await self.write(data, timeout, tags)
        return await self.read(timeout, tags)


class LinesTransportMixin:
    async def write(
        self: TransportProtocol,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]

        logger.trace(data.hex() + "0a", extra={"tags": t})

        writer = self.get_writer()
        writer.write(binascii.hexlify(data) + b"\n")
        await asyncio.wait_for(writer.drain(), timeout)
        return len(data)

    async def read(
        self: TransportProtocol,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await asyncio.wait_for(self.get_reader().readline(), timeout)
        d = data.decode().strip()

        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(d + "0a", extra={"tags": t})

        return binascii.unhexlify(d)
