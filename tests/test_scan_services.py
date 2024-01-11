# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from gallia.commands.scan.uds.services import ServicesScanner
from gallia.log import get_logger
from gallia.services.uds import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.server import RandomUDSServer, UDSServerTransport
from gallia.transports import TargetURI

logger = get_logger("pytest")


@dataclass
class Args:
    target = TargetURI("unix-lines://tmp/mock.socket")
    power_supply = None
    power_cycle = False
    dumpcap = False
    oem = "default"
    timeout = 1
    max_retries = 3
    ecu_reset = None
    ping = True
    tester_present = True
    tester_present_interval = 0.1
    properties = False
    sessions = [0x01]
    skip = {0x01: list(set(range(0xFF)).difference({0x27}))}
    check_session = True
    scan_response_ids = False


class Action(Enum):
    PASS = 1
    RAISE = 2
    TIMEOUT = 4


class ScanServicesMock:
    hook_request: Callable[
        [bytes, bytes, list[str] | None], Awaitable[tuple[Action, Any]]
    ] | None = None
    req_pdu = b"00"
    args = Args()
    scanner = None

    async def init(self) -> None:
        self.scanner = ServicesScanner(None)  # type: ignore
        self.server = RandomUDSServer(1)
        self.transport = UDSServerTransport(self.server, None)  # type: ignore
        await self.server.setup()

    async def mock_read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        logger.debug("read out of request_unsafe")
        data = bytes(
            [
                UDSIsoServices.NegativeResponse,
                self.req_pdu[0],
                UDSErrorCodes.serviceNotSupported,
            ]
        )
        return await self.send_response(self.req_pdu, data, tags)

    async def send_response(
        self, req: bytes, res: bytes, tags: list[str] | None
    ) -> bytes:
        action = Action.PASS
        arg = res
        if self.hook_request:
            action, arg = await self.hook_request(req, res, tags)

        match action:
            case Action.PASS:
                logger.debug(f"forward response: {req.hex()} -> {arg.hex()}")
                return arg
            case Action.TIMEOUT:
                logger.debug(f"simulate timeout on request: {req.hex()}")
                raise TimeoutError
            case Action.RAISE:
                assert isinstance(arg, Exception)
                logger.debug(f"simulate exception on request: {req.hex()} -> {arg!r}")
                raise arg

    async def mock_write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        logger.debug(f"write out of request_unsafe: {data.hex()}")
        self.req_pdu = data
        return len(data)

    async def mock_close(self) -> None:
        logger.debug("mock_close")

    async def mock_reconnect(self, timeout: float | None = None) -> AsyncMock:
        logger.debug("mock_reconnect")
        return await self.mock_connect(self.args.target)

    async def mock_request_unsafe(
        self, data: bytes, timeout: float | None = None, tags: list[str] | None = None
    ) -> bytes:
        res, duration = await self.transport.handle_request(data)
        if not res:
            raise TimeoutError
        return await self.send_response(data, res, tags)

    async def mock_connect(
        self, target: str | TargetURI, timeout: float | None = None
    ) -> AsyncMock:
        con = AsyncMock()
        con.close.side_effect = self.mock_close
        con.write.side_effect = self.mock_write
        con.read.side_effect = self.mock_read
        con.reconnect.side_effect = self.mock_reconnect
        con.request_unsafe.side_effect = self.mock_request_unsafe
        return con

    @pytest.mark.asyncio
    @pytest.fixture
    @patch("gallia.transports.unix.UnixTransport.connect")
    @patch("gallia.command.uds.UDSScanner.configure_class_parser")
    @patch("gallia.commands.scan.uds.services.ServicesScanner.configure_parser")
    async def setup(
        self,
        mock_configure_parser: MagicMock,
        mock_configure_class_parser: MagicMock,
        mock_transport: MagicMock,
    ) -> None:
        await self.init()
        mock_transport.side_effect = self.mock_connect
        await self.scanner.setup(self.args)  # type: ignore

    @pytest.mark.asyncio
    @pytest.fixture
    async def teardown(self) -> None:
        await self.scanner.teardown(self.args)  # type: ignore


class TestScanServices(ScanServicesMock):
    @pytest.mark.asyncio
    async def test_1(self, setup: None, teardown: None) -> None:
        """Basic test of Service Scan against vECU.
        Scanner should scan Session 1 and skip all SIDs expect 0x27.
        """
        assert self.scanner is not None
        await self.scanner.main(self.args)  # type: ignore

        assert len(self.scanner.found) == 1
        assert len(self.scanner.found[1]) == 1
        assert 0x27 in self.scanner.found[1]

    @pytest.mark.asyncio
    async def test_2(self, setup: None, teardown: None) -> None:
        """Test TimeoutError on Service Scan.
        On SID 0x27 a TimeoutError is simulated.
        The Scanner should return this in the result.
        """
        assert self.scanner is not None

        async def handle(
            req: bytes, res: bytes, tags: list[str] | None
        ) -> tuple[Action, Any]:
            if req[0] == 0x27:
                return Action.TIMEOUT, None
            return Action.PASS, res

        self.hook_request = handle

        await self.scanner.main(self.args)  # type: ignore

        assert self.scanner.found[1][0x27] == TimeoutError.__name__

    @pytest.mark.asyncio
    async def test_3(self, setup: None, teardown: None) -> None:
        """Test NegativeResponse on Service Scan.
        On SID 0x27 the NRC brakeSwitchNotClosed is simulated.
        The Scanner should return this NRC in the result.
        """
        assert self.scanner is not None

        async def handle(
            req: bytes, res: bytes, tags: list[str] | None
        ) -> tuple[Action, Any]:
            if req[0] == 0x27:
                return Action.PASS, bytes(
                    [
                        UDSIsoServices.NegativeResponse,
                        0x27,
                        UDSErrorCodes.brakeSwitchNotClosed,
                    ]
                )
            return Action.PASS, res

        self.hook_request = handle

        await self.scanner.main(self.args)  # type: ignore

        assert (
            self.scanner.found[1][0x27].response_code
            == UDSErrorCodes.brakeSwitchNotClosed
        )
