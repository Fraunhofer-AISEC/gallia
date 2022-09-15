# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from gallia.transports.base import TargetURI


class BaseNetzteil(ABC):
    PRODUCT_ID = ""

    def __init__(self, target: TargetURI, timeout: float | None) -> None:
        self.target = target
        self.timeout = timeout
        self.ident = ""

    @classmethod
    async def connect(cls, target: TargetURI, timeout: float | None) -> BaseNetzteil:
        nt = cls(target, timeout)
        await nt.probe()
        return nt

    async def probe(self) -> None:
        self.ident = await self.get_ident()

    @abstractmethod
    async def status(self) -> dict[str, Any]:
        ...

    @abstractmethod
    async def get_ident(self) -> str:
        ...

    @abstractmethod
    async def get_master(self) -> bool:
        ...

    @abstractmethod
    async def set_master(self, enabled: bool) -> None:
        ...

    @abstractmethod
    async def get_channels(self) -> int:
        ...

    @abstractmethod
    async def get_current(self, channel: int) -> float:
        ...

    @abstractmethod
    async def set_current(self, channel: int, value: float) -> None:
        ...

    @abstractmethod
    async def get_voltage(self, channel: int) -> float:
        ...

    @abstractmethod
    async def set_voltage(self, channel: int, value: float) -> None:
        ...

    @abstractmethod
    async def get_output(self, channel: int) -> bool:
        ...

    @abstractmethod
    async def set_output(self, channel: int, enabled: bool) -> None:
        ...

    @abstractmethod
    async def get_ocp(self, channel: int) -> bool:
        ...

    @abstractmethod
    async def set_ocp(self, channel: int, enabled: bool) -> None:
        ...

    @abstractmethod
    async def get_ovp(self, channel: int) -> bool:
        ...

    @abstractmethod
    async def set_ovp(self, channel: int, enabled: bool) -> None:
        ...

    @abstractmethod
    async def set_beep(self, enabled: bool) -> None:
        ...
