# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.command import UDSDiscoveryScanner
from gallia.log import get_logger
from gallia.services.uds.core.service import (
    DiagnosticSessionControlRequest,
    DiagnosticSessionControlResponse,
    UDSRequest,
)
from gallia.services.uds.helpers import raise_for_mismatch
from gallia.transports.base import TargetURI
from gallia.transports.hsfz import HSFZConnection
from gallia.utils import auto_int, write_target_list

logger = get_logger(__name__)


class HSFZDiscoverer(UDSDiscoveryScanner):
    """ECU and routing discovery scanner for HSFZ"""

    COMMAND = "hsfz"
    SHORT_HELP = ""

    def configure_parser(self) -> None:
        self.parser.add_argument("--reversed", action="store_true", help="scan in reversed order")
        self.parser.add_argument(
            "--src-addr", type=auto_int, default=0xF4, help="HSFZ source address"
        )
        self.parser.add_argument(
            "--start", metavar="INT", type=auto_int, default=0x00, help="set start address"
        )
        self.parser.add_argument(
            "--stop", metavar="INT", type=auto_int, default=0xFF, help="set end address"
        )

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

    async def main(self, args: Namespace) -> None:
        found = []
        gen = (
            range(args.stop + 1, args.start) if args.reversed else range(args.start, args.stop + 1)
        )

        for dst_addr in gen:
            logger.info(f"testing target {dst_addr:#02x}")

            target = await self.probe(
                args.target.hostname, args.target.port, args.src_addr, dst_addr, args.timeout
            )

            if target is not None:
                logger.info(f"found {dst_addr:#02x}")
                found.append(target)

        logger.result(f"Found {len(found)} targets")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        logger.result(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)
