# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0
from abc import ABC
from dataclasses import asdict
from typing import Any, Literal, Self

from pydantic import field_serializer, model_validator

from gallia.cli.gallia import parse_and_run
from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import Field, InitializeIdempotent
from gallia.command.uds import UDSScannerConfig
from gallia.power_supply import power_supply_drivers
from gallia.power_supply.base import BasePowerSupplyDriver
from gallia.power_supply.uri import PowerSupplyURI
from gallia.transports import TargetURI
from gallia.utils import strtobool


class CLIConfig(AsyncScriptConfig):
    power_supply: InitializeIdempotent[PowerSupplyURI] = Field(
        description="URI specifying the location of the powersupply",
        metavar="URI",
        short="t",
        config_section=UDSScannerConfig._config_section,
    )

    @field_serializer("power_supply")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_power_supply_requirements(self) -> Self:
        if self.power_supply.product_id not in power_supply_drivers:
            raise ValueError(f"powersupply {self.power_supply.product_id} is not supported")

        return self


class GetCLIConfig(CLIConfig):
    channel: int = Field(description="the channel number to control", short="c")
    attr: Literal[
        "voltage",
        "current",
        "output",
        "ocp",
        "ovp",
        "measured-voltage",
        "measured-current",
        "measured-power",
    ] = Field(description="the attribute to read", short="a")


class SetCLIConfig(CLIConfig):
    channel: int = Field(description="the channel number to control", short="c")
    attr: Literal["voltage", "current", "output", "ocp", "ovp"] = Field(
        description="the attribute to control", short="a"
    )
    value: str = Field(positional=True)


class StatusCLIConfig(CLIConfig):
    cursed: bool = Field(False, description="show the status in an interactive curses based view")
    interval: float = Field(0.5, description="refresh interval in seconds for --cursed", short="i")


class CLI(AsyncScript, ABC):
    def __init__(self, config: CLIConfig):
        super().__init__(config)
        self.config: CLIConfig = config

    async def _client(self) -> BasePowerSupplyDriver:
        driver = power_supply_drivers[self.config.power_supply.product_id]
        return await driver.connect(self.config.power_supply, timeout=1.0)


class GetCLI(CLI):
    CONFIG_TYPE = GetCLIConfig
    SHORT_HELP = "Get properties of the power supply"

    def __init__(self, config: GetCLIConfig):
        super().__init__(config)
        self.config: GetCLIConfig = config

    async def main(self) -> None:
        client = await self._client()
        channel = self.config.channel

        match self.config.attr:
            case "voltage":
                print(await client.get_voltage(channel))
            case "current":
                print(await client.get_current(channel))
            case "output":
                if channel == 0:
                    print(await client.get_master())
                else:
                    print(await client.get_output(channel))
            case "ocp":
                print(await client.get_ocp(channel))
            case "ovp":
                print(await client.get_ovp(channel))
            case "measured-voltage":
                print(await client.measure_voltage(channel))
            case "measured-current":
                print(await client.measure_current(channel))
            case "measured-power":
                print(await client.measure_power(channel))


class SetCLI(CLI):
    CONFIG_TYPE = SetCLIConfig
    SHORT_HELP = "Set properties of the power supply"

    def __init__(self, config: SetCLIConfig):
        super().__init__(config)
        self.config: SetCLIConfig = config

    async def main(self) -> None:
        client = await self._client()
        channel = self.config.channel

        match self.config.attr:
            case "voltage":
                await client.set_voltage(channel, float(self.config.value))
            case "current":
                await client.set_current(channel, float(self.config.value))
            case "output":
                if channel == 0:
                    await client.set_master(strtobool(self.config.value))
                else:
                    await client.set_output(channel, strtobool(self.config.value))
            case "ocp":
                await client.set_ocp(channel, strtobool(self.config.value))
            case "ovp":
                await client.set_ovp(channel, strtobool(self.config.value))


class StatusCLI(CLI):
    CONFIG_TYPE = StatusCLIConfig
    SHORT_HELP = "Show settings and measurements of all channels"

    def __init__(self, config: StatusCLIConfig):
        super().__init__(config)
        self.config: StatusCLIConfig = config

    async def main(self) -> None:
        client = await self._client()

        if self.config.cursed:
            # curses is not available on Windows; keep the other subcommands usable there.
            from gallia.cli.cursed_netzteil import CursedNetzteil

            await CursedNetzteil(client, self.config.interval).run()
            return

        status = await client.status()

        print(status.ident)
        print(f"master: {status.master}")
        for channel, channel_status in status.channels.items():
            print(f"channel {channel}:")
            for key, value in asdict(channel_status).items():
                print(f"  {key}: {value}")


def main() -> None:
    parse_and_run({"get": GetCLI, "set": SetCLI, "status": StatusCLI})


if __name__ == "__main__":
    main()
