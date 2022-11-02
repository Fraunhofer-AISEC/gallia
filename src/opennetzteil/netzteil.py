# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from gallia.transports import TargetURI


class BaseNetzteil(ABC):
    #: The product_id is used to choose the relevant implementation.
    PRODUCT_ID = ""

    def __init__(self, target: TargetURI, timeout: float | None) -> None:
        self.target = target
        self.timeout = timeout
        self.ident = ""

    @classmethod
    async def connect(cls, target: TargetURI, timeout: float | None) -> BaseNetzteil:
        """Connects to ``target`` and checks for connectivity using :meth:`probe()`."""
        nt = cls(target, timeout)
        await nt.probe()
        return nt

    async def probe(self) -> None:
        """Checks for connectivity. The default implementation
        reads out the version number and model string by calling
        :meth:`get_ident()`.
        """
        self.ident = await self.get_ident()

    @abstractmethod
    async def status(self) -> dict[str, Any]:
        ...

    @abstractmethod
    async def get_ident(self) -> str:
        """Reads the version number and model string."""

    @abstractmethod
    async def get_master(self) -> bool:
        """Reads the status of the master switch."""

    @abstractmethod
    async def set_master(self, enabled: bool) -> None:
        """Sets the status of the master switch."""

    @abstractmethod
    async def get_channels(self) -> int:
        """Returns the number of available channels."""

    @abstractmethod
    async def get_current(self, channel: int) -> float:
        """Returns the max. current value."""

    @abstractmethod
    async def set_current(self, channel: int, value: float) -> None:
        """Sets the max. current value."""

    @abstractmethod
    async def get_voltage(self, channel: int) -> float:
        """Returns the max. voltage value."""

    @abstractmethod
    async def set_voltage(self, channel: int, value: float) -> None:
        """Sets the max. voltage value."""

    @abstractmethod
    async def get_output(self, channel: int) -> bool:
        """Returns the state (on/off) of the supplied channel."""

    @abstractmethod
    async def set_output(self, channel: int, enabled: bool) -> None:
        """Sets the state (on/off) of the supplied channel."""

    @abstractmethod
    async def get_ocp(self, channel: int) -> bool:
        """Gets the state (on/off) of the overcurrent protection."""

    @abstractmethod
    async def set_ocp(self, channel: int, enabled: bool) -> None:
        """Sets the state (on/off) of the overcurrent protection."""

    @abstractmethod
    async def get_ovp(self, channel: int) -> bool:
        """Gets the state (on/off) of the overvoltage protection."""

    @abstractmethod
    async def set_ovp(self, channel: int, enabled: bool) -> None:
        """Sets the state (on/off) of the overvoltage protection."""

    @abstractmethod
    async def set_beep(self, enabled: bool) -> None:
        """Sets the state (on/off) of the alarm."""
