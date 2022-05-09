from __future__ import annotations

import asyncio
import functools
import io
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Any, Callable, ClassVar, Generic, Optional, TypeVar, NewType
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


T = TypeVar("T")


@dataclass
class ArgumentContainer:

    def to_dict(self) -> dict[str, Argument]:
        d = asdict(self)
        for k, v in d.items():
            if issubclass(type(v), Argument) is False:
                raise ValueError(f"field {k} is not a subclass of `Argument`: {type(v)}")
        return d


ArgumentContainerT = TypeVar("ArgumentContainerT", bound="ArgumentContainer")


class Argument(Generic[T]):
    TYPE: Callable[..., T]

    def __init__(self, *, mandatory: bool, default: T):
        self.mandatory = mandatory
        self.default = default
        self._val: Optional[T] = None

    def __init_subclass__(
        cls,
        /,
        type: Callable[..., Optional[T]],
        **kwargs: Any,
    ) -> None:
        super().__init_subclass__(**kwargs)
        cls.TYPE = type

    def parse(self, str_val: str) -> None:
        self._val = self.TYPE(str_val)

    @property
    def val(self) -> T:
        if self._val is None:
            return self.default
        return self._val


class IntArg(Argument[int], type=functools.partial(int, base=0)):
    pass


def _bool_type(str_val: str) -> bool:
    s_low = str_val.lower()
    if s_low == "true":
        return True
    elif s_low == "false":
        return False
    raise ValueError(f"invalid bool value: {str_val}")


class BoolArg(Argument[int], type=_bool_type):
    pass


# TODO: Replace this with Self type: Python 3.11
TransportT = TypeVar("TransportT")


class BaseTransport(ABC, Generic[ArgumentContainerT]):
    SCHEME: ClassVar[str] = ""
    BUFSIZE: ClassVar[int] = io.DEFAULT_BUFFER_SIZE

    def __init__(self, target: TargetURI, args: ArgumentContainerT) -> None:
        if target.scheme != self.SCHEME:
            raise ValueError(
                f"invalid scheme: {target.scheme}; expected: {self.SCHEME}"
            )

        self.mutex = asyncio.Lock()
        self.logger = Logger(self.SCHEME, flush=True)
        self.target = target
        self.args = args
        self.parse_args()

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

    def parse_args(self) -> None:
        # Check if a mandatory arg is missing.
        for k, v in self.args.items():
            if k not in self.target.qs:
                if v.mandatory:
                    raise ValueError(f"mandatory argument {k} missing")

        # Parse the arguments according to the spec.
        for k, v in self.target.qs.items():
            if k not in self.args:
                self.logger.log_warning(f"ignoring unknown argument: {k}:{v}")
                continue

            self.logger.log_debug(f"parsing argument {k}:{v}")
            # We do not support arg lists.
            self.args[k].parse(v[0])

    @abstractmethod
    async def connect(
        self,
        target: TargetURI,
        timeout: Optional[float] = None,
    ) -> TransportT:
        ...

    @abstractmethod
    async def close(self) -> None:
        ...

    async def reconnect(self, timeout: Optional[float] = None) -> TransportT:
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
