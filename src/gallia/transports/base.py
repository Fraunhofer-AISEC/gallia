# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import io
from abc import ABC, abstractmethod
from typing import Any, TypeVar
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
        port: int | None,
        args: dict[str, Any],
    ) -> TargetURI:
        netloc = host if port is None else join_host_port(host, port)
        return TargetURI(urlunparse((scheme, netloc, "", "", urlencode(args), "")))

    @property
    def scheme(self) -> str:
        return self.url.scheme

    @property
    def hostname(self) -> str | None:
        return self.url.hostname

    @property
    def port(self) -> int | None:
        return self.url.port

    @property
    def netloc(self) -> str:
        return self.url.netloc

    @property
    def location(self) -> str:
        assert self.scheme != "", "url scheme is empty"
        return f"{self.scheme}://{self.url.netloc}"

    @property
    def qs_flat(self) -> dict[str, str]:
        d = {}
        for k, v in self.qs.items():
            d[k] = v[0]
        return d

    def __str__(self) -> str:
        return self.raw


# TODO: Replace this with Self type: Python 3.11
TransportT = TypeVar("TransportT", bound="BaseTransport")


class BaseTransport(ABC):
    SCHEME: str = ""
    BUFSIZE: int = io.DEFAULT_BUFFER_SIZE

    def __init__(self, target: TargetURI) -> None:
        self.mutex = asyncio.Lock()
        self.logger = get_logger(self.SCHEME)
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
        if target.scheme != cls.SCHEME:
            raise ValueError(f"invalid scheme: {target.scheme}; expected: {cls.SCHEME}")

    @classmethod
    @abstractmethod
    async def connect(
        cls: type[TransportT],
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> TransportT:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

    async def reconnect(self: TransportT, timeout: float | None = None) -> TransportT:
        async with self.mutex:
            await self.close()
            return await self.connect(self.target)

    @abstractmethod
    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        ...

    @abstractmethod
    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        ...

    async def request(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        async with self.mutex:
            return await self.request_unsafe(data, timeout, tags)

    async def request_unsafe(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        await self.write(data, timeout, tags)
        return await self.read(timeout, tags)
