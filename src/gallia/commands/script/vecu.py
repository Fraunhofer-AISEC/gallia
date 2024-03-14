# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import json
import random
import sys
from pathlib import Path

from pydantic_argparse import BaseCommand

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import Field
from gallia.log import get_logger
from gallia.services.uds.core.constants import UDSIsoServices
from gallia.services.uds.server import (
    DBUDSServer,
    RandomUDSServer,
    TCPUDSServerTransport,
    UDSServer,
    UDSServerTransport,
    UnixUDSServerTransport,
)
from gallia.transports import TargetURI, TransportScheme

dynamic_attr_prefix = "dynamic_attr_"

logger = get_logger(__name__)


class VirtualECUConfig(AsyncScriptConfig):
    target: TargetURI = Field(positional=True)


class DbVirtualECUConfig(VirtualECUConfig):
    path: Path = Field(positional=True)
    ecu: str | None
    properties: dict | None


class RngVirtualECUConfig(VirtualECUConfig):
    seed: str = Field(
        random.randint(0, sys.maxsize),
        description="Set the seed of the internal random number generator. This supports reproducibility.",
    )


class VirtualECUConfigCommand(BaseCommand):
    db: DbVirtualECUConfig | None = None
    rng: RngVirtualECUConfig | None = None


class VirtualECU(AsyncScript):
    """Spawn a virtual ECU for testing purposes"""

    SHORT_HELP = "spawn a virtual UDS ECU"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/virtual_ecu.html"

    def __init__(self, config: VirtualECUConfig):
        super().__init__(config)
        self.config = config

    async def main(self) -> None:
        cmd: str = self.config.cmd
        server: UDSServer

        if cmd == "db":
            server = DBUDSServer(self.config.path, self.config.ecu, self.config.properties)
        elif cmd == "rng":
            server = RandomUDSServer(self.config.seed)
        else:
            raise AssertionError()

        for key, value in vars(self.config).items():
            if key.startswith(dynamic_attr_prefix) and value is not None:
                setattr(
                    server,
                    key[len(dynamic_attr_prefix) :],
                    eval(value, {service.name: service for service in UDSIsoServices}),
                )

        target: TargetURI = self.config.target
        transport: UDSServerTransport

        if sys.platform.startswith("linux"):
            from gallia.services.uds.server import (
                ISOTPUDSServerTransport,
                UnixUDSServerTransport,
            )

            match target.scheme:
                case TransportScheme.TCP:
                    transport = TCPUDSServerTransport(server, target)
                case TransportScheme.ISOTP:
                    transport = ISOTPUDSServerTransport(server, target)
                case TransportScheme.UNIX_LINES:
                    transport = UnixUDSServerTransport(server, target)
                case _:
                    self.parser.error(
                        f"Unsupported transport scheme! Use any of ["
                        f"{TransportScheme.TCP}, {TransportScheme.ISOTP}, {TransportScheme.UNIX_LINES}]"
                    )
        if sys.platform.startswith("win32"):
            match target.scheme:
                case TransportScheme.TCP:
                    transport = TCPUDSServerTransport(server, target)
                case _:
                    self.parser.error(
                        f"Unsupported transport scheme! Use any of [" f"{TransportScheme.TCP}]"
                    )

        try:
            await server.setup()
            await transport.run()
        finally:
            await server.teardown()
