# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import random
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Self

from pydantic import field_serializer, model_validator

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import Field, Idempotent
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
    target: Idempotent[TargetURI] = Field(positional=True)

    @field_serializer("target")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
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
    properties: dict[str, Any] | None = Field(metavar="PROPERTIES")


class RngVirtualECUConfig(
    VirtualECUConfig, RandomUDSServer.Behavior, RandomUDSServer.RandomnessParameters
):
    seed: int = Field(
        random.randint(0, sys.maxsize),
        description="Set the seed of the internal random number generator. This supports reproducibility.",
    )


class VirtualECU(AsyncScript, ABC):
    """Spawn a virtual ECU for testing purposes"""

    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/virtual_ecu.html"

    def __init__(self, config: VirtualECUConfig):
        super().__init__(config)
        self.config: VirtualECUConfig = config

    @abstractmethod
    def _server(self) -> UDSServer: ...

    async def main(self) -> None:
        server = self._server()

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


class RngVirtualECU(VirtualECU):
    CONFIG_TYPE = RngVirtualECUConfig
    SHORT_HELP = "Virtual ECU with randomized behavior"

    def __init__(self, config: RngVirtualECUConfig):
        super().__init__(config)
        self.config: RngVirtualECUConfig = config

    def _server(self) -> RandomUDSServer:
        return RandomUDSServer(self.config.seed, self.config, self.config)


class DbVirtualECU(VirtualECU):
    CONFIG_TYPE = DbVirtualECUConfig
    SHORT_HELP = "Virtual ECU which mimics the behavior of an ECU according to logs in the database"

    def __init__(self, config: DbVirtualECUConfig):
        super().__init__(config)
        self.config: DbVirtualECUConfig = config

    def _server(self) -> DBUDSServer:
        return DBUDSServer(self.config.path, self.config.ecu, self.config.properties, self.config)
