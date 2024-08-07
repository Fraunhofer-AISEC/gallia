# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Literal, Self

from gallia.cli import parse_and_run
from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig, ScannerConfig
from gallia.command.config import Field, idempotent
from gallia.plugins.plugin import Command
from gallia.powersupply import PowerSupplyURI
from gallia.transports import TargetURI
from gallia.utils import strtobool
from pydantic import field_serializer, model_validator

from opennetzteil import netzteile


class CLIConfig(AsyncScriptConfig):
    power_supply: idempotent(PowerSupplyURI) = Field(
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
    def serialize_target_uri(self, target_uri: TargetURI | None, _info) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        for netzteil in netzteile:
            if self.power_supply.product_id == netzteil.PRODUCT_ID:
                break
        else:
            raise ValueError(f"powersupply {self.power_supply.product_id} is not supported")

        return self


class GetCLIConfig(CLIConfig):
    pass


class SetCLIConfig(CLIConfig):
    value: str = Field(positional=True)


class CLI(AsyncScript):
    def __init__(self, config: CLIConfig):
        super().__init__(config)
        self.config = config

    async def main(self) -> None:
        for netzteil in netzteile:
            if self.config.power_supply.product_id == netzteil.PRODUCT_ID:
                client = await netzteil.connect(self.config.power_supply, timeout=1.0)
                break

        assert client

        if isinstance(self.config, GetCLIConfig):
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
        elif isinstance(self.config, SetCLIConfig):
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
    parse_and_run(
        {
            "get": Command(
                description="Get properties of the power supply", config=GetCLIConfig, command=CLI
            ),
            "set": Command(
                description="Set properties of the power supply", config=SetCLIConfig, command=CLI
            ),
        }
    )


if __name__ == "__main__":
    main()
