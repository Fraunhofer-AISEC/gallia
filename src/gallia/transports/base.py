from __future__ import annotations

import asyncio
import io
from abc import ABC, abstractmethod
from typing import Any, Callable, Optional
from urllib.parse import parse_qs, urlparse

from gallia.penlog import Logger


class TargetURI:
    def __init__(self, raw: str) -> None:
        self.raw = raw
        self.url = urlparse(raw)
        self.qs = parse_qs(self.url.query)

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

    @property
    def src_addr(self) -> Optional[int]:
        if "src_addr" not in self.qs:
            return None
        return int(self.qs["src_addr"][0], 0)

    @property
    def dst_addr(self) -> Optional[int]:
        if "dst_addr" not in self.qs:
            return None
        return int(self.qs["dst_addr"][0], 0)

    def __str__(self) -> str:
        return self.raw


def _bool_spec(default: Optional[bool]) -> Callable[..., Optional[bool]]:
    def func(*args: str) -> Optional[bool]:
        if len(args) == 0:
            return default
        s_low = args[0].lower()
        if s_low == "true":
            return True
        elif s_low == "false":
            return False
        raise ValueError(f"invalid bool value: {args[0]}")

    return func


def _int_spec(default: Optional[int]) -> Callable[..., Optional[int]]:
    def func(*args: str) -> Optional[int]:
        if len(args) == 0:
            return default
        return int(args[0], base=0)

    return func


class BaseTransport(ABC):
    SPEC: dict[str, tuple[Callable[..., Any], bool]] = {}
    SCHEME: str = ""
    BUFSIZE: int = io.DEFAULT_BUFFER_SIZE

    def __init__(self, target: TargetURI) -> None:
        if target.scheme != self.SCHEME:
            raise ValueError(
                f"invalid scheme: {target.scheme}; expected: {self.SCHEME}"
            )

        self._args: dict[str, Any] = {}
        self.mutex = asyncio.Lock()
        self.logger = Logger(self.SCHEME, flush=True)
        self.target = target
        self.parse_args()

    def __init_subclass__(
        cls,
        /,
        scheme: str,
        spec: dict[str, tuple[Callable[..., Any], bool]],
        bufsize: int = io.DEFAULT_BUFFER_SIZE,
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls.SCHEME = scheme
        cls.SPEC = spec
        cls.BUFSIZE = bufsize

    def parse_args(self) -> None:
        # Check if a mandatory arg is missing.
        for k, v in self.SPEC.items():
            mandatory = v[1]
            default = v[0]()
            if k not in self.target.qs:
                if mandatory:
                    raise ValueError(f"mandatory argument {k} missing")
                # Not mandatory, set default.
                self._args[k] = default

        # Parse the arguments according to the spec.
        for k, v in self.target.qs.items():
            if k not in self.SPEC:
                self.logger.log_warning(f"ignoring unknown argument: {k}:{v}")
                continue

            self.logger.log_debug(f"got {k}:{v}")
            parse_func = self.SPEC[k][0]
            # We do not support arg lists.
            parsed_v = parse_func(v[0])
            self._args[k] = parsed_v

    @abstractmethod
    async def connect(self, timeout: Optional[float] = None) -> None:
        ...

    @abstractmethod
    async def reconnect(self, timeout: Optional[float] = None) -> None:
        ...

    @abstractmethod
    async def terminate(self) -> None:
        ...

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

    @abstractmethod
    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        ...

    @abstractmethod
    async def recvfrom(
        self,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> tuple[int, bytes]:
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
