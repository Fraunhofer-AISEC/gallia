# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from functools import partial
from typing import Callable, Optional, Union

from gallia.log import get_logger
from gallia.transports.base import TargetURI
from opennetzteil import Netzteil


class PowerSupplyURI(TargetURI):
    def __init__(self, raw: str) -> None:
        super().__init__(raw)
        if "id" not in self.qs:
            raise ValueError("id is missing in power-supply URI")
        if "channel" not in self.qs:
            raise ValueError("channel is missing in power-supply URI")

    @property
    def id(self) -> int:
        return int(self.qs["id"][0], 0)

    @property
    def channel(self) -> Union[int, list[int]]:
        if len(ch := self.qs["channel"]) == 1:
            return int(ch[0], 0)
        return list(map(partial(int, base=0), ch))


class PowerSupply:
    def __init__(self, channel_id: Union[int, list[int]], client: Netzteil) -> None:
        self.logger = get_logger("power_supply")
        self.channel_id = channel_id
        self.netzteil = client
        self.mutex = asyncio.Lock()

    @classmethod
    async def connect(cls, target: PowerSupplyURI) -> PowerSupply:
        client = await Netzteil.connect(target.location, target.id)
        return cls(target.channel, client)

    async def _power(self, op: bool) -> None:
        assert self.netzteil
        if isinstance(self.channel_id, list):
            for id_ in self.channel_id:
                await self.netzteil.set_channel(id_, op)
        elif isinstance(self.channel_id, int):
            await self.netzteil.set_channel(self.channel_id, op)

    async def power_up(self) -> None:
        self.logger.info("power up experiment")
        await self._power(True)

    async def power_down(self) -> None:
        self.logger.info("power down experiment")
        await self._power(False)

    async def power_cycle(
        self,
        sleep: float = 2.0,
        callback: Optional[Callable] = None,
    ) -> None:
        async with self.mutex:
            await self.power_down()
            await asyncio.sleep(sleep)
            await self.power_up()
            if callback:
                await callback()
