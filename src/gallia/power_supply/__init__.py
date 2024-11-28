# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from collections.abc import Awaitable, Callable
from typing import Self

from gallia.log import get_logger
from gallia.power_supply.base import BasePowerSupplyDriver
from gallia.power_supply.devices.rs.hmc804 import HMC804
from gallia.power_supply.uri import PowerSupplyURI

power_supply_drivers: list[type[BasePowerSupplyDriver]] = [HMC804]

logger = get_logger(__name__)


class PowerSupply:
    def __init__(self, driver: BasePowerSupplyDriver, channel_id: int | list[int]) -> None:
        self.channel_id = channel_id
        self.driver = driver
        self.mutex = asyncio.Lock()

    @classmethod
    async def connect(cls, target: PowerSupplyURI) -> Self:
        if target.product_id == "":
            raise ValueError("no device_id specified")

        for driver in power_supply_drivers:
            if target.product_id == driver.PRODUCT_ID:
                client = await driver.connect(target, timeout=1.0)
                return cls(client, target.channel)
        raise ValueError(f"{target.product_id} is not supported")

    async def _power(self, op: bool) -> None:
        assert self.driver
        if isinstance(self.channel_id, list):
            for id_ in self.channel_id:
                if id_ == 0:
                    await self.driver.set_master(op)
                else:
                    await self.driver.set_output(id_, op)
        elif isinstance(self.channel_id, int):
            if self.channel_id == 0:
                await self.driver.set_master(op)
            else:
                await self.driver.set_output(self.channel_id, op)

    async def power_up(self) -> None:
        logger.info("power up")
        await self._power(True)

    async def power_down(self) -> None:
        logger.info("power down")
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
