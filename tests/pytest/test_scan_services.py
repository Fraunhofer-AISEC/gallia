# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from collections.abc import AsyncIterator

import pytest

from gallia.commands.scan.uds.services import ServicesScanner, ServicesScannerConfig
from gallia.log import get_logger
from gallia.services.uds import UDSIsoServices, UDSRequest, UDSResponse
from gallia.services.uds.core.service import (
    DiagnosticSessionControlRequest,
    DiagnosticSessionControlResponse,
)
from gallia.services.uds.server import (
    QueueServerTransport,
    UDSServer,
)
from gallia.transports import DummyTransport, TargetURI

logger = get_logger(__name__)


class _TestTransport(DummyTransport, scheme="dummy"):
    def __init__(
        self,
        target: TargetURI,
        read_queue: asyncio.Queue[bytes],
        write_queue: asyncio.Queue[bytes],
    ) -> None:
        super().__init__(target)
        self.read_queue = read_queue
        self.write_queue = write_queue

    async def read(self, timeout: float | None = None, tags: list[str] | None = None) -> bytes:
        async with asyncio.timeout(timeout):
            return await self.read_queue.get()

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        await self.write_queue.put(data)
        return len(data)


class UDSTestServer(UDSServer):
    @property
    def supported_services(self) -> dict[int, dict[UDSIsoServices, list[int] | None]]:
        return {
            0x01: {
                UDSIsoServices.DiagnosticSessionControl: [0x01, 0x02, 0x03],
            }
        }

    async def respond_after_default(self, request: UDSRequest) -> UDSResponse | None:
        match request:
            case DiagnosticSessionControlRequest():
                return DiagnosticSessionControlResponse(
                    diagnostic_session_type=request.diagnostic_session_type,
                    session_parameter_record=bytes([0xAF, 0xFE]),
                )
            case _:
                raise NotImplementedError


class TestScanServices:
    @pytest.fixture()
    async def transport(self) -> AsyncIterator[_TestTransport]:
        read_queue: asyncio.Queue[bytes] = asyncio.Queue()
        write_queue: asyncio.Queue[bytes] = asyncio.Queue()

        self.server = UDSTestServer()
        server_transport = QueueServerTransport(self.server, read_queue, write_queue)

        await self.server.setup()
        server_task = asyncio.create_task(server_transport.run())

        yield _TestTransport(TargetURI("dummy:"), write_queue, read_queue)

        server_task.cancel()
        await server_task

    @pytest.mark.asyncio()
    async def test_basic_service_discovery(self, transport: _TestTransport) -> None:
        config = ServicesScannerConfig(
            target=TargetURI("dummy:"),
            transport=transport,
        )
        scanner = ServicesScanner(config)

        await scanner.entry_point()

        assert len(scanner.result) == 1
