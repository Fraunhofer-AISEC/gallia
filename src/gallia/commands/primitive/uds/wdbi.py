# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from pathlib import Path
from typing import Self

from pydantic import model_validator

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse

logger = get_logger(__name__)


class WriteByIdentifierPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    data_identifier: AutoInt = Field(description="The data identifier", positional=True)
    session: AutoInt = Field(0x01, description="set session perform test in")
    data: HexBytes | None = Field(None, description="The data which should be written")
    data_file: Path | None = Field(
        None, description="The path to a file with the binary data which should be written"
    )

    @model_validator(mode="after")
    def check_data_source(self) -> Self:
        if not (self.data is None) ^ (self.data_file is None):
            raise ValueError("Exactly one of data or data-file is required")

        return self


class WriteByIdentifierPrimitive(UDSScanner):
    """A simple scanner to talk to the write by identifier service"""

    CONFIG_TYPE = WriteByIdentifierPrimitiveConfig
    SHORT_HELP = "WriteDataByIdentifier"

    def __init__(self, config: WriteByIdentifierPrimitiveConfig):
        super().__init__(config)
        self.config: WriteByIdentifierPrimitiveConfig = config

    async def main(self) -> None:
        try:
            if self.config.session != 0x01:
                resp: UDSResponse = await self.ecu.set_session(self.config.session)
                if isinstance(resp, NegativeResponse):
                    logger.critical(f"could not change to session: {resp}")
                    sys.exit(1)
        except Exception as e:
            logger.critical(f"fatal error: {e!r}")
            sys.exit(1)

        if self.config.data is not None:
            data = self.config.data
        else:
            assert self.config.data_file is not None

            with self.config.data_file.open("rb") as file:
                data = file.read()

        resp = await self.ecu.write_data_by_identifier(self.config.data_identifier, data)
        if isinstance(resp, NegativeResponse):
            logger.error(resp)
        else:
            logger.result("Success")
