# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

import pytest

from gallia.power_supply import PowerSupply
from gallia.power_supply.devices.rs.hmc804 import HMC804
from gallia.power_supply.uri import PowerSupplyURI


@dataclass
class FakeChannel:
    voltage: float = 0.0
    current: float = 0.1
    output: bool = False
    fuse: bool = False
    ovp: bool = False


@dataclass
class FakeHMC804:
    """Emulates the subset of the HMC804x SCPI interface used by the driver.

    Like the real device, the channel selection persists across connections.
    """

    model: str = "HMC8043"
    selected: int = 1
    master: bool = False
    beep: bool = True
    channels: dict[int, FakeChannel] = field(default_factory=dict)
    log: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.channels = {i: FakeChannel() for i in range(1, int(self.model[-1]) + 1)}

    def handle(self, line: str) -> str | None:
        self.log.append(line)
        cmd, _, arg = line.partition(" ")
        ch = self.channels[self.selected]
        single = len(self.channels) == 1

        match cmd:
            case "*OPC?":
                return "1"
            case "*IDN?":
                return f"Rohde&Schwarz,{self.model},012345,HW50020001/SW01.00"
            case "INST:NSEL":
                self.selected = int(arg)
            case "VOLT":
                ch.voltage = float(arg)
            case "VOLT?":
                return f"{ch.voltage:.3f}"
            case "CURR":
                ch.current = float(arg)
            case "CURR?":
                return f"{ch.current:.4f}"
            case "MEAS:VOLT?":
                return f"{ch.voltage if ch.output and self.master else 0.0:.3f}"
            case "MEAS:CURR?":
                return "0.0420"
            case "MEAS:POW?":
                return "0.123"
            case "OUTP" if single:
                ch.output = self.master = arg == "ON"
            case "OUTP?" if single:
                return str(int(ch.output))
            case "OUTP:CHAN" if not single:
                ch.output = arg == "ON"
            case "OUTP:CHAN?" if not single:
                return str(int(ch.output))
            case "OUTP:MAST" if not single:
                self.master = arg == "ON"
            case "OUTP:MAST?" if not single:
                return str(int(self.master))
            case "FUSE":
                ch.fuse = arg == "ON"
            case "FUSE?":
                return str(int(ch.fuse))
            case "VOLT:PROT":
                ch.ovp = arg == "ON"
            case "VOLT:PROT?":
                return str(int(ch.ovp))
            case "SYST:BEEP:STAT":
                self.beep = arg == "ON"
            case _:
                raise AssertionError(f"unexpected command: {line}")
        return None

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while line := await reader.readline():
            if (resp := self.handle(line.decode().strip())) is not None:
                writer.write(resp.encode() + b"\n")
                await writer.drain()
        writer.close()


async def _serve(device: FakeHMC804) -> AsyncIterator[tuple[FakeHMC804, PowerSupplyURI]]:
    server = await asyncio.start_server(device.serve, host="127.0.0.1", port=0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        yield device, PowerSupplyURI(f"tcp://127.0.0.1:{port}?product_id=hmc804")


@pytest.fixture
async def hmc8043() -> AsyncIterator[tuple[FakeHMC804, PowerSupplyURI]]:
    async for item in _serve(FakeHMC804("HMC8043")):
        yield item


@pytest.fixture
async def hmc8041() -> AsyncIterator[tuple[FakeHMC804, PowerSupplyURI]]:
    async for item in _serve(FakeHMC804("HMC8041")):
        yield item


async def test_probe(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    _, uri = hmc8043
    driver = await HMC804.connect(uri, timeout=1.0)
    assert driver.model == "HMC8043"
    assert await driver.get_channels() == 3


async def test_probe_unsupported(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8043
    device.model = "HMC9999"
    with pytest.raises(ValueError, match="unsupported device"):
        await HMC804.connect(uri, timeout=1.0)


async def test_channel_settings(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8043
    driver = await HMC804.connect(uri, timeout=1.0)

    await driver.set_voltage(2, 12.5)
    await driver.set_current(2, 0.25)
    await driver.set_output(2, True)
    await driver.set_ocp(2, True)
    await driver.set_ovp(3, True)

    assert device.channels[2] == FakeChannel(12.5, 0.25, output=True, fuse=True)
    assert device.channels[3].ovp
    assert device.channels[1] == FakeChannel()

    assert await driver.get_voltage(2) == 12.5
    assert await driver.get_current(2) == 0.25
    assert await driver.get_output(2)
    assert not await driver.get_output(1)
    assert await driver.get_ocp(2)
    assert await driver.get_ovp(3)


async def test_select_on_same_connection(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8043
    driver = await HMC804.connect(uri, timeout=1.0)
    device.log.clear()

    await driver.get_voltage(3)
    assert device.log == ["INST:NSEL 3", "VOLT?"]

    device.log.clear()
    await driver.set_voltage(1, 5)
    assert device.log == ["INST:NSEL 1", "VOLT 5.000", "*OPC?"]


async def test_limits(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    _, uri = hmc8043
    driver = await HMC804.connect(uri, timeout=1.0)

    with pytest.raises(ValueError):
        await driver.set_voltage(1, 40)
    with pytest.raises(ValueError):
        await driver.set_current(1, 5)
    with pytest.raises(ValueError):
        await driver.get_voltage(4)


async def test_status(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8043
    driver = await HMC804.connect(uri, timeout=1.0)
    device.channels[1].voltage = 5.0
    device.channels[1].output = True
    device.master = True

    status = await driver.status()
    assert status.master
    assert sorted(status.channels) == [1, 2, 3]
    assert status.channels[1].measured_voltage == 5.0
    assert status.channels[1].output
    assert status.channels[2].measured_voltage == 0.0
    assert status.channels[2].measured_power == 0.123


async def test_single_channel_model(hmc8041: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8041
    driver = await HMC804.connect(uri, timeout=1.0)

    # The fake device rejects OUTP:CHAN and OUTP:MAST like a real HMC8041.
    await driver.set_master(True)
    assert device.master
    assert await driver.get_master()
    assert await driver.get_output(1)

    await driver.set_current(1, 8.0)
    status = await driver.status()
    assert status.master
    assert list(status.channels) == [1]


async def test_power_cycle(hmc8043: tuple[FakeHMC804, PowerSupplyURI]) -> None:
    device, uri = hmc8043
    psu = await PowerSupply.connect(PowerSupplyURI(f"{uri.raw}&channel=2&channel=3"))

    await psu.power_up()
    assert device.channels[2].output
    assert device.channels[3].output
    assert not device.channels[1].output

    await psu.power_cycle(sleep=0)
    assert device.channels[2].output
    assert "OUTP:CHAN OFF" in device.log
