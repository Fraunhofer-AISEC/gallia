# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, cast
from urllib.parse import urljoin

import aiohttp

from gallia.transports import TargetURI
from opennetzteil.exceptions import OperationNotSupportedError
from opennetzteil.netzteil import BaseNetzteil


class HTTPNetzteil(BaseNetzteil):
    URL_PREFIX = "/_netzteil/api/"
    PRODUCT_ID = "opennetzteil"

    def __init__(  # pylint: disable=super-init-not-called
        self,
        session: aiohttp.ClientSession,
        host: str,
        device: int,
    ):
        self.host = host
        self.baseurl = urljoin(host, self.URL_PREFIX)
        self.device_id = device
        self.session = session

    @classmethod
    async def connect(cls, target: TargetURI, timeout: float | None) -> BaseNetzteil:
        if "id" in target.qs:
            device_id = int(target.qs["id"][0], 0)
        else:
            device_id = 1

        return cls(aiohttp.ClientSession(), target.location, device_id)

    async def _put_value(self, endpoint: str, channel: int, val: Any) -> None:
        p = f"devices/{self.device_id}/channels/{channel}/{endpoint}"
        u = urljoin(self.baseurl, p)
        r = await self.session.put(u, json=val)
        r.raise_for_status()

    async def _get_value(self, endpoint: str, channel: int) -> Any:
        p = f"devices/{self.device_id}/channels/{channel}/{endpoint}"
        u = urljoin(self.baseurl, p)
        r = await self.session.get(u)
        r.raise_for_status()
        return await r.json()

    async def get_ident(self) -> str:
        u = urljoin(self.baseurl, f"devices/{self.device_id}/ident")
        r = await self.session.get(u)
        r.raise_for_status()
        return cast(str, await r.json())

    async def get_channels(self) -> int:
        u = urljoin(self.baseurl, f"devices/{self.device_id}/channels")
        r = await self.session.get(u)
        r.raise_for_status()
        return cast(int, await r.json())

    async def set_output(self, channel: int, enabled: bool) -> None:
        return await self._put_value("out", channel, enabled)

    async def get_output(self, channel: int) -> bool:
        return cast(bool, await self._get_value("out", channel))

    async def set_master(self, enabled: bool) -> None:
        return await self.set_output(0, enabled)

    async def get_master(self) -> bool:
        return await self.get_output(0)

    async def set_current(self, channel: int, value: float) -> None:
        return await self._put_value("current", channel, value)

    async def get_current(self, channel: int) -> float:
        return cast(float, await self._get_value("current", channel))

    async def set_voltage(self, channel: int, value: float) -> None:
        return await self._put_value("voltage", channel, value)

    async def status(self) -> dict[str, Any]:
        raise OperationNotSupportedError()

    async def get_voltage(self, channel: int) -> float:
        return cast(float, await self._get_value("voltage", channel))

    async def set_ocp(self, channel: int, enabled: bool) -> None:
        return await self._put_value("ocp", channel, enabled)

    async def get_ocp(self, channel: int) -> bool:
        return cast(bool, await self._get_value("ocp", channel))

    async def set_ovp(self, channel: int, enabled: bool) -> None:
        return await self._put_value("ovp", channel, enabled)

    async def get_ovp(self, channel: int) -> bool:
        return cast(bool, await self._get_value("ovp", channel))

    async def set_beep(self, enabled: bool) -> None:
        raise OperationNotSupportedError()
