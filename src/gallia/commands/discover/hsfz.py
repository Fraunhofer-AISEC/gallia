# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio

from gallia.command import UDSDiscoveryScanner
from gallia.command.config import AutoInt, Field
from gallia.command.uds import UDSDiscoveryScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.service import (
    DiagnosticSessionControlRequest,
    DiagnosticSessionControlResponse,
    UDSRequest,
)
from gallia.services.uds.helpers import raise_for_mismatch
from gallia.transports.base import TargetURI
from gallia.transports.hsfz import HSFZConnection
from gallia.utils import write_target_list

logger = get_logger(__name__)


class HSFZDiscovererConfig(UDSDiscoveryScannerConfig):
    reversed: bool = Field(False, description="scan in reversed order")
    src_addr: AutoInt = Field(0xF4, description="HSFZ source address")
    start: AutoInt = Field(0x00, description="set start address", metavar="INT")
    stop: AutoInt = Field(0xFF, description="set end address", metavar="INT")


class HSFZDiscoverer(UDSDiscoveryScanner):
    """ECU and routing discovery scanner for HSFZ"""

    SHORT_HELP = ""

    CONFIG_TYPE = HSFZDiscovererConfig

    def __init__(self, config: HSFZDiscovererConfig):
        super().__init__(config)
        self.config: HSFZDiscovererConfig = config

    async def _probe(self, conn: HSFZConnection, req: UDSRequest, timeout: float) -> bool:
        data = req.pdu
        result = False

        await asyncio.wait_for(conn.write_diag_request(data), timeout)

        # Broadcast endpoints deliver more responses.
        # Make sure to flush the receive queue properly.
        while True:
            try:
                raw_resp = await asyncio.wait_for(conn.read_diag_request(), timeout)
            except TimeoutError:
                return result

            resp = DiagnosticSessionControlResponse.parse_static(raw_resp)
            raise_for_mismatch(req, resp)
            result = True

    async def probe(
        self,
        host: str,
        port: int,
        src_addr: int,
        dst_addr: int,
        timeout: float,
        ack_timeout: float = 1.0,
    ) -> TargetURI | None:
        req = DiagnosticSessionControlRequest(0x01)

        try:
            conn = await HSFZConnection.connect(host, port, src_addr, dst_addr, ack_timeout)
        except TimeoutError:
            return None

        try:
            result = await self._probe(conn, req, timeout)
        except (TimeoutError, ConnectionError):
            return None
        finally:
            await conn.close()

        if result:
            return TargetURI.from_parts(
                "hsfz",
                host,
                port,
                {
                    "src_addr": f"{src_addr:#02x}",
                    "dst_addr": f"{dst_addr:#02x}",
                    "ack_timeout": int(ack_timeout) * 1000,
                },
            )
        return None

    async def main(self) -> None:
        found = []
        gen = (
            range(self.config.stop + 1, self.config.start)
            if self.config.reversed
            else range(self.config.start, self.config.stop + 1)
        )

        for dst_addr in gen:
            logger.info(f"testing target {dst_addr:#02x}")

            hostname = self.config.target.hostname
            port = self.config.target.port

            assert hostname is not None
            assert port is not None

            target = await self.probe(
                hostname,
                port,
                self.config.src_addr,
                dst_addr,
                self.config.timeout,
            )

            if target is not None:
                logger.info(f"found {dst_addr:#02x}")
                found.append(target)

        logger.result(f"Found {len(found)} targets")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        logger.result(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)
