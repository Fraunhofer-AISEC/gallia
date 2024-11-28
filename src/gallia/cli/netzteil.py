# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0
from abc import ABC
from typing import Any, Literal, Self

from pydantic import field_serializer, model_validator

from gallia.cli.gallia import parse_and_run
from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig, ScannerConfig
from gallia.command.config import Field, Idempotent
from gallia.power_supply import power_supply_drivers
from gallia.power_supply.base import BasePowerSupplyDriver
from gallia.power_supply.uri import PowerSupplyURI
from gallia.transports import TargetURI
from gallia.utils import strtobool


class CLIConfig(AsyncScriptConfig):
    power_supply: Idempotent[PowerSupplyURI] = Field(
        description="URI specifying the location of the powersupply",
        metavar="URI",
        short="t",
        config_section=ScannerConfig._config_section,
    )
    channel: int = Field(description="the channel number to control", short="c")
    attr: Literal["voltage", "current", "output"] = Field(
        description="the attribute to control", short="a"
    )

    @field_serializer("power_supply")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_power_supply_requirements(self) -> Self:
        for driver in power_supply_drivers:
            if self.power_supply.product_id == driver.PRODUCT_ID:
                break
        else:
            raise ValueError(f"powersupply {self.power_supply.product_id} is not supported")

        return self


class GetCLIConfig(CLIConfig):
    pass


class SetCLIConfig(CLIConfig):
    value: str = Field(positional=True)


class CLI(AsyncScript, ABC):
    def __init__(self, config: CLIConfig):
        super().__init__(config)
        self.config: CLIConfig = config

    async def _client(self) -> BasePowerSupplyDriver:
        for driver in power_supply_drivers:
            if self.config.power_supply.product_id == driver.PRODUCT_ID:
                return await driver.connect(self.config.power_supply, timeout=1.0)

        assert False


class GetCLI(CLI, ABC):
    CONFIG_TYPE = GetCLIConfig
    SHORT_HELP = "Get properties of the power supply"

    def __init__(self, config: GetCLIConfig):
        super().__init__(config)
        self.config: GetCLIConfig = config

    async def main(self) -> None:
        client = await self._client()

        match self.config.attr:
            case "voltage":
                print(await client.get_voltage(self.config.channel))
            case "current":
                print(await client.get_current(self.config.channel))
            case "output":
                if self.config.channel == 0:
                    print(await client.get_master())
                else:
                    print(await client.get_output(self.config.channel))


class SetCLI(CLI, ABC):
    CONFIG_TYPE = SetCLIConfig
    SHORT_HELP = "Set properties of the power supply"

    def __init__(self, config: SetCLIConfig):
        super().__init__(config)
        self.config: SetCLIConfig = config

    async def main(self) -> None:
        client = await self._client()

        match self.config.attr:
            case "voltage":
                await client.set_voltage(self.config.channel, float(self.config.value))
            case "current":
                await client.set_current(self.config.channel, float(self.config.value))
            case "output":
                if self.config.channel == 0:
                    await client.set_master(strtobool(self.config.value))
                else:
                    await client.set_output(self.config.channel, strtobool(self.config.value))


def main() -> None:
    parse_and_run({"get": GetCLI, "set": SetCLI})


if __name__ == "__main__":
    main()
