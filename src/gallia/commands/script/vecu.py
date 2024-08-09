# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import random
import sys
from pathlib import Path
from typing import Self

from pydantic import field_serializer, model_validator

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import Field, idempotent
from gallia.log import get_logger
from gallia.services.uds.server import (
    DBUDSServer,
    RandomUDSServer,
    TCPUDSServerTransport,
    UDSServer,
    UDSServerTransport,
)
from gallia.transports import TargetURI, TransportScheme

logger = get_logger(__name__)


class VirtualECUConfig(AsyncScriptConfig):
    target: idempotent(TargetURI) = Field(positional=True)

    @field_serializer("target")
    def serialize_target_uri(self, target_uri: TargetURI | None, _info):
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        supported: list[TransportScheme] = []

        if sys.platform.startswith("linux"):
            supported = [TransportScheme.TCP, TransportScheme.ISOTP, TransportScheme.UNIX_LINES]

        if sys.platform.startswith("win32"):
            supported = [TransportScheme.TCP]

        if self.target.scheme not in supported:
            raise ValueError(f"Unsupported transport scheme! Use any of {supported}")

        return self


class DbVirtualECUConfig(VirtualECUConfig, DBUDSServer.Behavior):
    path: Path = Field(positional=True)
    ecu: str | None
    properties: dict | None


class RngVirtualECUConfig(
    VirtualECUConfig, RandomUDSServer.Behavior, RandomUDSServer.RandomnessParameters
):
    seed: int = Field(
        random.randint(0, sys.maxsize),
        description="Set the seed of the internal random number generator. This supports reproducibility.",
    )


class VirtualECU(AsyncScript):
    """Spawn a virtual ECU for testing purposes"""

    SHORT_HELP = "spawn a virtual UDS ECU"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/virtual_ecu.html"

    def __init__(self, config: VirtualECUConfig):
        super().__init__(config)
        self.config = config

    async def main(self) -> None:
        server: UDSServer

        if isinstance(self.config, DbVirtualECUConfig):
            server = DBUDSServer(
                self.config.path, self.config.ecu, self.config.properties, self.config
            )
        elif isinstance(self.config, RngVirtualECUConfig):
            server = RandomUDSServer(self.config.seed, self.config, self.config)
        else:
            raise AssertionError()

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
                    assert False

        if sys.platform.startswith("win32"):
            match target.scheme:
                case TransportScheme.TCP:
                    transport = TCPUDSServerTransport(server, target)
                case _:
                    assert False

        try:
            await server.setup()
            await transport.run()
        finally:
            await server.teardown()
