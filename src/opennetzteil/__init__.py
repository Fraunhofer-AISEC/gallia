# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from urllib.parse import urljoin
from typing import Any, cast

import aiohttp


class Netzteil:
    URL_PREFIX = "/_netzteil/api/"

    def __init__(
        self,
        session: aiohttp.ClientSession,
        host: str,
        ident: str,
        device: int,
    ):
        self.host = host
        self.baseurl = urljoin(host, self.URL_PREFIX)
        self.device = device
        self.session = session
        self.ident = ident

    @classmethod
    async def connect(cls, host: str, device: int) -> Netzteil:
        baseurl = urljoin(host, cls.URL_PREFIX)
        u = urljoin(baseurl, f"devices/{device}/ident")
        s = aiohttp.ClientSession()
        r = await s.get(u)
        r.raise_for_status()
        ident = await r.json()
        return cls(s, host, ident, device)

    async def _put_value(self, endpoint: str, channel: int, val: Any) -> None:
        p = f"devices/{self.device}/channels/{channel}/{endpoint}"
        u = urljoin(self.baseurl, p)
        r = await self.session.put(u, json=val)
        r.raise_for_status()

    async def _get_value(self, endpoint: str, channel: int) -> Any:
        p = f"devices/{self.device}/channels/{channel}/{endpoint}"
        u = urljoin(self.baseurl, p)
        r = await self.session.get(u)
        r.raise_for_status()
        return await r.json()

    async def set_channel(self, channel: int, enabled: bool) -> None:
        return await self._put_value("out", channel, enabled)

    async def get_channel(self, channel: int) -> bool:
        return cast(bool, await self._get_value("out", channel))

    async def set_master(self, enabled: bool) -> None:
        return await self.set_channel(0, enabled)

    async def get_master(self) -> bool:
        return await self.get_channel(0)

    async def set_current(self, channel: int, val: float) -> None:
        return await self._put_value("out", channel, val)

    async def get_current(self, channel: int) -> float:
        return cast(float, await self._get_value("out", channel))

    async def set_voltage(self, channel: int, val: float) -> None:
        return await self._put_value("voltage", channel, val)

    async def get_voltage(self, channel: int) -> float:
        return cast(float, self._get_value("voltage", channel))

    async def set_ocp(self, channel: int, enabled: bool) -> None:
        return await self._put_value("ocp", channel, enabled)

    async def get_ocp(self, channel: int) -> bool:
        return cast(bool, await self._get_value("ocp", channel))

    async def set_ovp(self, channel: int, enabled: bool) -> None:
        return await self._put_value("ovp", channel, enabled)

    async def get_ovp(self, channel: int) -> bool:
        return cast(bool, await self._get_value("ovp", channel))
