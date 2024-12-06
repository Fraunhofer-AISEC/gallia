# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Annotated, cast

from pydantic import BeforeValidator

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, err_int
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class DDDIPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU properties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="The session in which the requests are made")


def parse_definitions(value: str | tuple[int, ...], expected_len: int) -> tuple[int, ...]:
    if isinstance(value, tuple):
        if len(value) != expected_len:
            raise ValueError(f"Need exactly {expected_len} values for each definition")

        return value

    values = value.split(":")

    if len(values) != expected_len:
        raise ValueError(f"Need exactly {expected_len} values for each definition")

    return tuple(err_int(x, 0) for x in values)


def parse_id(value: str | tuple[int, int, int]) -> tuple[int, int, int]:
    return cast(tuple[int, int, int], parse_definitions(value, 3))


def parse_mem(value: str | tuple[int, int]) -> tuple[int, int]:
    return cast(tuple[int, int], parse_definitions(value, 2))


class DefineByIdentifierDDDIPrimitiveConfig(DDDIPrimitiveConfig):
    data_identifier: AutoInt = Field(
        description="The new dynamically defined data identifier", positional=True
    )
    sources: list[Annotated[tuple[int, int, int], BeforeValidator(parse_id)]] = Field(
        description="The definitions of the source data to be included in the dynamically defined data. Each of them consists of a data identifier, the start byte of the corresponding data record (1-indexed) and its length in bytes",
        metavar="ID:START:LENGTH",
    )


class DefineByMemoryAddressDDDIPrimitiveConfig(DDDIPrimitiveConfig):
    data_identifier: AutoInt = Field(
        description="The new dynamically defined data identifier", positional=True
    )
    sources: list[Annotated[tuple[int, int], BeforeValidator(parse_mem)]] = Field(
        description="The definitions of the source data to be included in the dynamically defined data. each of them consists of a memory address and the length in bytes",
        metavar="ADDRESS:LENGTH",
    )
    address_format: AutoInt | None = Field(
        None,
        description="The addressAndLengthFormatIdentifier, which can be set manually or deduced automatically if not given explicitly",
    )


class ClearDynamicallyDefinedDataIdentifierDDDIPrimitiveConfig(DDDIPrimitiveConfig):
    data_identifier: AutoInt | None = Field(
        description="The dynamically defined data identifier to be cleared. Omit if all dynamically defined identifiers should be cleared."
    )


class DDDIPrimitive(UDSScanner):
    """dynamically define data identifiers"""

    CONFIG_TYPE = DDDIPrimitiveConfig
    SHORT_HELP = "DynamicallyDefineDataIdentifiers"

    def __init__(self, config: DDDIPrimitiveConfig):
        super().__init__(config)
        self.config: DDDIPrimitiveConfig = config

    async def main(self) -> None:
        try:
            await self.ecu.check_and_set_session(self.config.session)
        except Exception as e:
            logger.critical(f"Could not change to session: {g_repr(self.config.session)}: {e!r}")
            sys.exit(1)


class DefineByIdentifierDDDIPrimitive(DDDIPrimitive):
    CONFIG_TYPE = DefineByIdentifierDDDIPrimitiveConfig
    SHORT_HELP = "DefineByIdentifier"

    def __init__(self, config: DefineByIdentifierDDDIPrimitiveConfig):
        super().__init__(config)
        self.config: DefineByIdentifierDDDIPrimitiveConfig = config

    async def main(self) -> None:
        await super().main()

        source_identifiers = []
        start_positions = []
        lengths = []

        for identifier, start, length in self.config.sources:
            source_identifiers.append(identifier)
            start_positions.append(start)
            lengths.append(length)

        response = await self.ecu.define_by_identifier(
            self.config.data_identifier, source_identifiers, start_positions, lengths
        )

        if isinstance(response, NegativeResponse):
            logger.error(response)
        else:
            # There is not real data returned, only echoes
            logger.result("Success")


class DefineByMemoryAddressDDDIPrimitive(DDDIPrimitive):
    CONFIG_TYPE = DefineByMemoryAddressDDDIPrimitiveConfig
    SHORT_HELP = "DefineByMemoryAddress"

    def __init__(self, config: DefineByMemoryAddressDDDIPrimitiveConfig):
        super().__init__(config)
        self.config: DefineByMemoryAddressDDDIPrimitiveConfig = config

    async def main(self) -> None:
        await super().main()

        addresses = []
        lengths = []

        for address, length in self.config.sources:
            addresses.append(address)
            lengths.append(length)

        response = await self.ecu.define_by_memory_address(
            self.config.data_identifier, addresses, lengths, self.config.address_format
        )

        if isinstance(response, NegativeResponse):
            logger.error(response)
        else:
            # There is not real data returned, only echoes
            logger.result("Success")


class ClearDynamicallyDefinedDataIdentifierDDDIPrimitive(DDDIPrimitive):
    CONFIG_TYPE = ClearDynamicallyDefinedDataIdentifierDDDIPrimitiveConfig
    SHORT_HELP = "ClearDynamicallyDefinedDataIdentifier"

    def __init__(self, config: ClearDynamicallyDefinedDataIdentifierDDDIPrimitiveConfig):
        super().__init__(config)
        self.config: ClearDynamicallyDefinedDataIdentifierDDDIPrimitiveConfig = config

    async def main(self) -> None:
        await super().main()

        response = await self.ecu.clear_dynamically_defined_data_identifier(
            self.config.data_identifier
        )

        if isinstance(response, NegativeResponse):
            logger.error(response)
        else:
            # There is not real data returned, only echoes
            logger.result("Success")
