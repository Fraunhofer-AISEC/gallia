# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio

from gallia.log import get_logger
from gallia.power_supply.base import BasePowerSupplyDriver, ChannelStatus, PowerSupplyStatus
from gallia.transports import TargetURI
from gallia.utils import strtobool

logger = get_logger(__name__)

# The maximum current depends on the model, the voltage range does not.
MAX_CURRENT = {
    "HMC8041": 10.0,
    "HMC8042": 5.0,
    "HMC8043": 3.0,
}
MIN_CURRENT = 0.0005
MIN_VOLTAGE = 0.0
MAX_VOLTAGE = 32.05


def _on_off(enabled: bool) -> str:
    return "ON" if enabled else "OFF"


class HMC804(BasePowerSupplyDriver):
    """Rohde&Schwarz power supply: R&S HMC804x
    https://www.rohde-schwarz.com/de/produkte/messtechnik/dc-netzgeraete/rs-hmc804x-dc-netzgeraeteserie_63493-61542.html

    SCPI reference:
    https://scdn.rohde-schwarz.com/ur/pws/dl_downloads/dl_common_library/dl_manuals/dl_user_manual/HMC804x_SCPI_ProgrammersManual_en_02.pdf

    Each operation uses its own connection, such that other tools (e.g. netzteil)
    can access the device while a scanner is running. Channel specific commands
    select the channel via INST:NSEL on the same connection.
    """

    PRODUCT_ID = "hmc804"

    def __init__(self, target: TargetURI, timeout: float | None) -> None:
        super().__init__(target, timeout)
        self.model = ""

    async def _connect(
        self,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        return await asyncio.wait_for(
            asyncio.open_connection(self.target.hostname, self.target.port),
            self.timeout,
        )

    async def _send_line(self, writer: asyncio.StreamWriter, data: str) -> None:
        logger.trace(f"--> {data}")
        writer.write(data.encode() + b"\n")
        await asyncio.wait_for(writer.drain(), self.timeout)

    async def _recv_line(self, reader: asyncio.StreamReader) -> str:
        resp = (await asyncio.wait_for(reader.readline(), self.timeout)).decode().strip()
        logger.trace(f"<-- {resp}")
        return resp

    async def _close_conn(self, writer: asyncio.StreamWriter) -> None:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), self.timeout)

    async def _transfer(self, cmds: list[str]) -> list[str]:
        """Sends all cmds over one connection and returns the responses of the queries."""
        reader, writer = await self._connect()
        try:
            resps = []
            for cmd in cmds:
                await self._send_line(writer, cmd)
                if cmd.endswith("?"):
                    resps.append(await self._recv_line(reader))
            return resps
        finally:
            await self._close_conn(writer)

    async def _request(self, cmd: str, channel: int | None = None) -> str:
        return (await self._transfer(self._cmds(cmd, channel)))[0]

    async def _send(self, cmd: str, channel: int | None = None) -> None:
        # *OPC? blocks until all previous commands are processed; otherwise
        # setters would return before the device has applied the setting.
        await self._transfer(self._cmds(cmd, channel) + ["*OPC?"])

    def _cmds(self, cmd: str, channel: int | None) -> list[str]:
        if channel is None:
            return [cmd]
        return [self._select(channel), cmd]

    def _select(self, channel: int) -> str:
        if not 1 <= channel <= self.channels:
            raise ValueError(f"channel must be in range 1 to {self.channels}")
        return f"INST:NSEL {channel:d}"

    @property
    def channels(self) -> int:
        # The model names end with the number of channels, e.g. HMC8043.
        return int(self.model[-1])

    @property
    def _output_cmd(self) -> str:
        # The HMC8041 supports neither OUTP:CHAN nor OUTP:MAST, but OUTP
        # switches its single channel including the master output.
        return "OUTP" if self.channels == 1 else "OUTP:CHAN"

    async def probe(self) -> None:
        await super().probe()
        # *IDN? returns e.g. "Rohde&Schwarz,HMC8043,<serial>,<firmware>"
        fields = self.ident.split(",")
        if len(fields) < 2 or fields[1] not in MAX_CURRENT:
            raise ValueError(f"unsupported device: {self.ident}")
        self.model = fields[1]

    async def get_ident(self) -> str:
        return await self._request("*IDN?")

    async def get_master(self) -> bool:
        if self.channels == 1:
            return await self.get_output(1)
        return strtobool(await self._request("OUTP:MAST?"))

    async def set_master(self, enabled: bool) -> None:
        if self.channels == 1:
            return await self.set_output(1, enabled)
        await self._send(f"OUTP:MAST {_on_off(enabled)}")

    async def get_channels(self) -> int:
        return self.channels

    async def get_current(self, channel: int) -> float:
        return float(await self._request("CURR?", channel))

    async def set_current(self, channel: int, value: float) -> None:
        max_current = MAX_CURRENT[self.model]
        if not MIN_CURRENT <= value <= max_current:
            raise ValueError(f"current must be in range {MIN_CURRENT} A to {max_current} A")
        await self._send(f"CURR {value:.4f}", channel)

    async def get_voltage(self, channel: int) -> float:
        return float(await self._request("VOLT?", channel))

    async def set_voltage(self, channel: int, value: float) -> None:
        if not MIN_VOLTAGE <= value <= MAX_VOLTAGE:
            raise ValueError(f"voltage must be in range {MIN_VOLTAGE} V to {MAX_VOLTAGE} V")
        await self._send(f"VOLT {value:.3f}", channel)

    async def measure_voltage(self, channel: int) -> float:
        return float(await self._request("MEAS:VOLT?", channel))

    async def measure_current(self, channel: int) -> float:
        return float(await self._request("MEAS:CURR?", channel))

    async def measure_power(self, channel: int) -> float:
        return float(await self._request("MEAS:POW?", channel))

    async def get_output(self, channel: int) -> bool:
        return strtobool(await self._request(f"{self._output_cmd}?", channel))

    async def set_output(self, channel: int, enabled: bool) -> None:
        await self._send(f"{self._output_cmd} {_on_off(enabled)}", channel)

    async def status(self) -> PowerSupplyStatus:
        # Everything is queried over one connection, as this is polled.
        queries = [
            "VOLT?",
            "CURR?",
            "MEAS:VOLT?",
            "MEAS:CURR?",
            "MEAS:POW?",
            f"{self._output_cmd}?",
            "FUSE?",
            "VOLT:PROT?",
        ]
        cmds = []
        for channel in range(1, self.channels + 1):
            cmds.append(self._select(channel))
            cmds.extend(queries)
        if self.channels > 1:
            cmds.append("OUTP:MAST?")

        resps = await self._transfer(cmds)

        channels = {}
        for channel in range(1, self.channels + 1):
            start = (channel - 1) * len(queries)
            v, c, mv, mc, mp, out, ocp, ovp = resps[start : start + len(queries)]
            channels[channel] = ChannelStatus(
                voltage=float(v),
                current=float(c),
                measured_voltage=float(mv),
                measured_current=float(mc),
                measured_power=float(mp),
                output=strtobool(out),
                ocp=strtobool(ocp),
                ovp=strtobool(ovp),
            )
        master = strtobool(resps[-1]) if self.channels > 1 else channels[1].output
        return PowerSupplyStatus(ident=self.ident, master=master, channels=channels)

    async def get_ocp(self, channel: int) -> bool:
        # The HMC804x implements overcurrent protection as electronic fuse.
        return strtobool(await self._request("FUSE?", channel))

    async def set_ocp(self, channel: int, enabled: bool) -> None:
        await self._send(f"FUSE {_on_off(enabled)}", channel)

    async def get_ovp(self, channel: int) -> bool:
        return strtobool(await self._request("VOLT:PROT?", channel))

    async def set_ovp(self, channel: int, enabled: bool) -> None:
        await self._send(f"VOLT:PROT {_on_off(enabled)}", channel)

    async def set_beep(self, enabled: bool) -> None:
        await self._send(f"SYST:BEEP:STAT {_on_off(enabled)}")
