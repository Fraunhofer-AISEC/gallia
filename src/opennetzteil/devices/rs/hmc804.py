# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
from typing import Any

from gallia.utils import strtobool
from opennetzteil.exceptions import OperationNotSupportedError
from opennetzteil.netzteil import BaseNetzteil


class HMC804(BaseNetzteil):
    """Rohde&Schwarz power supply: R&S HMC804x
    https://www.rohde-schwarz.com/de/produkte/messtechnik/dc-netzgeraete/rs-hmc804x-dc-netzgeraeteserie_63493-61542.html
    """

    PRODUCT_ID = "hmc804"

    async def _connect(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(self.target.hostname, self.target.port),
            self.timeout,
        )

    async def _send_line(self, writer: asyncio.StreamWriter, data: str) -> None:
        writer.write(data.encode() + b"\n")
        await asyncio.wait_for(writer.drain(), self.timeout)

    async def _recv_line(self, reader: asyncio.StreamReader) -> str:
        return (
            (await asyncio.wait_for(reader.readline(), self.timeout)).decode().strip()
        )

    async def _close_conn(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), self.timeout)

    async def _request(self, data: str) -> str:
        reader, writer = await self._connect()
        await self._send_line(writer, data)

        resp = await self._recv_line(reader)
        await self._close_conn(writer)
        return resp

    async def _send(self, data: str) -> None:
        _, writer = await self._connect()
        await self._send_line(writer, data)
        await self._close_conn(writer)

    async def _send_multi(self, data_list: list[str]) -> None:
        _, writer = await self._connect()
        for datum in data_list:
            await self._send_line(writer, datum)
        await self._close_conn(writer)

    async def get_ident(self) -> str:
        cmd = "*IDN?"
        resp = await self._request(cmd)
        return resp

    async def get_master(self) -> bool:
        cmd = "OUTP:MAST:STAT?"
        resp = await self._request(cmd)
        return strtobool(resp)

    async def set_master(self, enabled: bool) -> None:
        cmd = "OUTP:MAST ON" if enabled else "OUTP:MAST OFF"
        await self._send(cmd)

    async def get_channels(self) -> int:
        raise OperationNotSupportedError()

    async def get_current(self, channel: int) -> float:
        cmd = f"INST OUT{channel:d}"
        await self._send(cmd)
        cmd = "CURR?"
        return float(await self._request(cmd))

    async def set_current(self, channel: int, value: float) -> None:
        cmds = [
            f"INST OUT{channel:d}",
            f"CURR {value:.3f}",
        ]
        await self._send_multi(cmds)

    async def get_voltage(self, channel: int) -> float:
        cmd = f"INST OUT{channel:d}"
        await self._send(cmd)
        cmd = "VOLT?"
        return float(await self._request(cmd))

    async def set_voltage(self, channel: int, value: float) -> None:
        cmds = [
            f"INST OUT{channel:d}",
            f"VOLT {value:.3f}",
        ]
        await self._send_multi(cmds)

    async def get_output(self, channel: int) -> bool:
        cmd = f"INST OUT{channel:d}"
        await self._send(cmd)
        cmd = "OUTP:STAT?"
        return strtobool(await self._request(cmd))

    async def set_output(self, channel: int, enabled: bool) -> None:
        cmds = [
            f"INST OUT{channel:d}",
        ]
        if enabled:
            cmds.append("OUTP:CHAN ON")
        else:
            cmds.append("OUTP:CHAN OFF")
        await self._send_multi(cmds)

    async def status(self) -> dict[str, Any]:
        raise OperationNotSupportedError()

    async def get_ocp(self, channel: int) -> bool:
        raise OperationNotSupportedError()

    async def set_ocp(self, channel: int, enabled: bool) -> None:
        raise OperationNotSupportedError()

    async def get_ovp(self, channel: int) -> bool:
        raise OperationNotSupportedError()

    async def set_ovp(self, channel: int, enabled: bool) -> None:
        raise OperationNotSupportedError()

    async def set_beep(self, enabled: bool) -> None:
        raise OperationNotSupportedError()
