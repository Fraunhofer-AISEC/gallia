# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from functools import partial

from gallia.log import get_logger
from gallia.transports import TargetURI
from opennetzteil import netzteile
from opennetzteil.netzteil import BaseNetzteil


class PowerSupplyURI(TargetURI):
    @property
    def id(self) -> int:
        if "id" in self.qs:
            return int(self.qs["id"][0], 0)
        return 0

    @property
    def channel(self) -> int | list[int]:
        if "channel" in self.qs:
            if len(ch := self.qs["channel"]) == 1:
                return int(ch[0], 0)
            return list(map(partial(int, base=0), ch))
        return 0

    @property
    def product_id(self) -> str:
        if "product_id" in self.qs:
            return self.qs["product_id"][0]
        return ""


class PowerSupply:
    def __init__(self, client: BaseNetzteil, channel_id: int | list[int]) -> None:
        self.logger = get_logger("power_supply")
        self.channel_id = channel_id
        self.netzteil = client
        self.mutex = asyncio.Lock()

    @classmethod
    async def connect(cls, target: PowerSupplyURI) -> PowerSupply:
        if target.product_id == "":
            raise ValueError("no device_id specified")

        for netzteil in netzteile:
            if target.product_id == netzteil.PRODUCT_ID:
                client = await netzteil.connect(target, timeout=1.0)
                return cls(client, target.channel)
        raise ValueError(f"{target.product_id} is not supported")

    async def _power(self, op: bool) -> None:
        assert self.netzteil
        if isinstance(self.channel_id, list):
            for id_ in self.channel_id:
                if id_ == 0:
                    await self.netzteil.set_master(op)
                else:
                    await self.netzteil.set_output(id_, op)
        elif isinstance(self.channel_id, int):
            if self.channel_id == 0:
                await self.netzteil.set_master(op)
            else:
                await self.netzteil.set_output(self.channel_id, op)

    async def power_up(self) -> None:
        self.logger.info("power up experiment")
        await self._power(True)

    async def power_down(self) -> None:
        self.logger.info("power down experiment")
        await self._power(False)

    async def power_cycle(
        self,
        sleep: float = 2.0,
        callback: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        async with self.mutex:
            await self.power_down()
            await asyncio.sleep(sleep)
            await self.power_up()
            if callback is not None:
                await callback()
