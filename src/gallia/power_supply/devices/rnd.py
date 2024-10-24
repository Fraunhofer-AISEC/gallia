# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from pathlib import Path
from typing import Any

from gallia.power_supply.base import BasePowerSupplyDriver
from gallia.power_supply.exceptions import OperationNotSupportedError


class RND320(BasePowerSupplyDriver):
    PRODUCT_ID = "RND320"

    def _send(self, data: str) -> None:
        with Path(self.target.path).open("w") as f:
            f.write(data)

    async def get_ident(self) -> str:
        raise OperationNotSupportedError

    async def get_master(self) -> bool:
        raise OperationNotSupportedError

    async def set_master(self, enabled: bool) -> None:
        cmd = "OUT1" if enabled else "OUT0"
        await asyncio.to_thread(self._send, cmd)

    async def get_channels(self) -> int:
        return 1

    async def get_current(self, channel: int) -> float:
        raise OperationNotSupportedError

    async def set_current(self, channel: int, value: float) -> None:
        raise OperationNotSupportedError

    async def get_voltage(self, channel: int) -> float:
        raise OperationNotSupportedError

    async def set_voltage(self, channel: int, value: float) -> None:
        raise OperationNotSupportedError

    async def get_output(self, channel: int) -> bool:
        raise OperationNotSupportedError

    async def set_output(self, channel: int, enabled: bool) -> None:
        await self.set_master(enabled)

    async def status(self) -> dict[str, Any]:
        raise OperationNotSupportedError

    async def get_ocp(self, channel: int) -> bool:
        raise OperationNotSupportedError

    async def set_ocp(self, channel: int, enabled: bool) -> None:
        raise OperationNotSupportedError

    async def get_ovp(self, channel: int) -> bool:
        raise OperationNotSupportedError

    async def set_ovp(self, channel: int, enabled: bool) -> None:
        raise OperationNotSupportedError

    async def set_beep(self, enabled: bool) -> None:
        raise OperationNotSupportedError
