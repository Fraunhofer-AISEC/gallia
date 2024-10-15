# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


from gallia.command import Scanner
from gallia.command.base import ScannerConfig
from gallia.command.config import Field, HexBytes
from gallia.command.uds import UDSScannerConfig


class GenericPDUPrimitiveConfig(ScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    pdu: HexBytes = Field(description="raw pdu to send", positional=True)


class GenericPDUPrimitive(Scanner):
    """A raw scanner to send a plain pdu"""

    CONFIG_TYPE = GenericPDUPrimitiveConfig
    SHORT_HELP = "send a plain PDU"

    def __init__(self, config: GenericPDUPrimitiveConfig):
        super().__init__(config)
        self.config: GenericPDUPrimitiveConfig = config

    async def main(self) -> None:
        await self.transport.write(self.config.pdu)
