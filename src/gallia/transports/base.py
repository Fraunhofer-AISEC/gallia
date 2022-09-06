# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import io
from abc import ABC, abstractmethod
from typing import Any, Optional, TypeVar
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from gallia.log import get_logger
from gallia.utils import join_host_port


class TargetURI:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.url = urlparse(raw)
        self.qs = parse_qs(self.url.query)

    @classmethod
    def from_parts(
        cls,
        scheme: str,
        host: str,
        port: Optional[int],
        args: dict[str, Any],
    ) -> TargetURI:
        netloc = host if port is None else join_host_port(host, port)
        return TargetURI(urlunparse((scheme, netloc, "", "", urlencode(args), "")))

    @property
    def scheme(self) -> str:
        return self.url.scheme

    @property
    def hostname(self) -> Optional[str]:
        return self.url.hostname

    @property
    def port(self) -> Optional[int]:
        return self.url.port

    @property
    def netloc(self) -> str:
        return self.url.netloc

    @property
    def location(self) -> str:
        assert self.scheme != "", "url scheme is empty"
        return f"{self.scheme}://{self.url.netloc}"

    def __str__(self) -> str:
        return self.raw


# TODO: Replace this with Self type: Python 3.11
TransportT = TypeVar("TransportT", bound="BaseTransport")


class BaseTransport(ABC):
    SCHEME: str = ""
    BUFSIZE: int = io.DEFAULT_BUFFER_SIZE

    def __init__(self, target: TargetURI) -> None:
        if target.scheme != self.SCHEME:
            raise ValueError(
                f"invalid scheme: {target.scheme}; expected: {self.SCHEME}"
            )

        self._args: dict[str, Any] = {}
        self.mutex = asyncio.Lock()
        self.logger = get_logger(self.SCHEME)
        self.target = target

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
    @abstractmethod
    async def connect(
        cls: type[TransportT],
        target: TargetURI,
        timeout: Optional[float] = None,
    ) -> TransportT:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

    async def reconnect(
        self: TransportT, timeout: Optional[float] = None
    ) -> TransportT:
        async with self.mutex:
            await self.close()
            return await self.connect(self.target)

    @abstractmethod
    async def read(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        ...

    @abstractmethod
    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        ...

    async def request(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        async with self.mutex:
            return await self.request_unsafe(data, timeout, tags)

    async def request_unsafe(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> bytes:
        await self.write(data, timeout, tags)
        return await self.read(timeout, tags)
