# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class ECUResetPrimitiveConfig(UDSScannerConfig):
    properties: bool = Field(
        False,
        description="Read and store the ECU proporties prior and after scan",
        cli_group=UDSScannerConfig._cli_group,
        config_section=UDSScannerConfig._config_section,
    )
    session: AutoInt = Field(0x01, description="set session perform test in")
    subfunc: AutoInt = Field(0x01, description="subfunc", short="f")


class ECUResetPrimitive(UDSScanner):
    """Use the ECUReset UDS service to reset the ECU"""

    CONFIG_TYPE = ECUResetPrimitiveConfig
    SHORT_HELP = "ECUReset"

    def __init__(self, config: ECUResetPrimitiveConfig):
        super().__init__(config)
        self.config: ECUResetPrimitiveConfig = config

    async def main(self) -> None:
        resp: UDSResponse = await self.ecu.set_session(self.config.session)
        if isinstance(resp, NegativeResponse):
            logger.error(f"could not change to session: {g_repr(self.config.session)}")
            return

        try:
            logger.info(f"try sub-func: {g_repr(self.config.subfunc)}")
            resp = await self.ecu.ecu_reset(self.config.subfunc)
            if isinstance(resp, NegativeResponse):
                msg = f"ECU Reset {g_repr(self.config.subfunc)} failed in session: {g_repr(self.config.session)}: {resp}"
                logger.error(msg)
            else:
                logger.result(f"ECU Reset {g_repr(self.config.subfunc)} succeeded")
        except TimeoutError:
            logger.error("Timeout")
            await asyncio.sleep(10)
        except ConnectionError:
            msg = f"Lost connection to ECU, session: {g_repr(self.config.session)} subFunc: {g_repr(self.config.subfunc)}"
            logger.error(msg)
            return
