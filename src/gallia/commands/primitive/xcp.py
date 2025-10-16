# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from collections.abc import Awaitable, Callable
from typing import Any, Self, TypeVar

from pydantic import field_serializer, model_validator

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field, Idempotent
from gallia.log import get_logger
from gallia.plugins.plugin import load_transport
from gallia.services.xcp import CANXCPSerivce, XCPService
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI

T = TypeVar("T")
logger = get_logger(__name__)


async def catch_and_log_exception(
    func: Callable[..., Awaitable[T]],
    *args: Any,
    **kwargs: Any,
) -> T | None:
    try:
        return await func(*args, **kwargs)
    except Exception as e:
        logger.error(f"func {func.__name__} failed: {repr(e)}")
        return None


class SimpleTestXCPConfig(AsyncScriptConfig):
    can_master: AutoInt | None = Field(None)
    can_slave: AutoInt | None = Field(None)
    target: Idempotent[TargetURI] = Field(
        description="URI that describes the target", metavar="TARGET"
    )

    @field_serializer("target")
    def serialize_target_uri(self, target_uri: TargetURI | None) -> Any:
        if target_uri is None:
            return None

        return target_uri.raw

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        if self.target.scheme == RawCANTransport.SCHEME and (
            self.can_master is None or self.can_slave is None
        ):
            raise ValueError("For CAN interfaces, master and slave address are required!")

        if self.target.scheme == ISOTPTransport.SCHEME:
            raise ValueError("Use can-raw for CAN interfaces!")

        return self


class SimpleTestXCP(AsyncScript):
    """Test XCP Slave"""

    CONFIG_TYPE = SimpleTestXCPConfig
    SHORT_HELP = "XCP tester"

    def __init__(self, config: SimpleTestXCPConfig):
        super().__init__(config)
        self.config: SimpleTestXCPConfig = config
        self.service: XCPService

    async def setup(self) -> None:
        transport = load_transport(self.config.target)
        await transport.connect()

        if isinstance(transport, RawCANTransport):
            assert self.config.can_master is not None and self.config.can_slave is not None

            self.service = CANXCPSerivce(transport, self.config.can_master, self.config.can_slave)
        else:
            self.service = XCPService(transport)

        await super().setup()

    async def main(self) -> None:
        await catch_and_log_exception(self.service.connect)
        await catch_and_log_exception(self.service.get_status)
        await catch_and_log_exception(self.service.get_comm_mode_info)
        await catch_and_log_exception(self.service.disconnect)
