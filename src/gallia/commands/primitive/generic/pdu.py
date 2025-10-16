# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0


from typing import Any

from pydantic import field_serializer

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import Field, HexBytes, Idempotent
from gallia.command.uds import UDSScannerConfig
from gallia.plugins.plugin import load_transport
from gallia.transports.base import TargetURI


class GenericPDUPrimitiveConfig(AsyncScriptConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    pdu: HexBytes = Field(description="raw pdu to send", positional=True)
    target: Idempotent[TargetURI] = Field(
        description="URI that describes the target", metavar="TARGET"
    )

    @field_serializer("target")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw


class GenericPDUPrimitive(AsyncScript):
    """A raw scanner to send a plain pdu"""

    CONFIG_TYPE = GenericPDUPrimitiveConfig
    SHORT_HELP = "send a plain PDU"

    def __init__(self, config: GenericPDUPrimitiveConfig):
        super().__init__(config)
        self.config: GenericPDUPrimitiveConfig = config

    async def main(self) -> None:
        transport = load_transport(self.config.target)

        await transport.connect()

        await transport.write(self.config.pdu)
