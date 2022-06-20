# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.transports.base import TargetURI
from gallia.transports.doip import (
    DiagnosticMessage,
    DoIPConnection,
    GenericHeader,
    PayloadTypes,
    ProtocolVersions,
    RoutingActivationRequest,
    RoutingActivationRequestTypes,
)
from gallia.uds.core.service import (
    DiagnosticSessionControlRequest,
    DiagnosticSessionControlResponse,
)
from gallia.uds.helpers import raise_for_mismatch
from gallia.udscan.core import DiscoveryScanner
from gallia.utils import auto_int, write_target_list


class DiscoverDoIP(DiscoveryScanner):
    """ECU and routing discovery scanner for DoIP"""

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--reversed",
            action="store_true",
            help="scan in reversed order",
        )
        self.parser.add_argument(
            "-r",
            "--request-type",
            default=RoutingActivationRequestTypes.WWH_OBD,
            help="specify the routing request type",
        )
        self.parser.add_argument(
            "--src-addr",
            type=auto_int,
            default=0x0E00,
            help="DoIP source address",
        )
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=auto_int,
            default=0x00,
            help="set start address",
        )
        self.parser.add_argument(
            "--stop",
            metavar="INT",
            type=auto_int,
            default=0xFFFF,
            help="set end address",
        )

    async def probe(
        self,
        conn: DoIPConnection,
        host: str,
        port: int,
        src_addr: int,
        target_addr: int,
        activation_type: RoutingActivationRequestTypes,
        timeout: float,
    ) -> TargetURI:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.RoutingActivationRequest,
            PayloadLength=7,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = RoutingActivationRequest(
            SourceAddress=src_addr,
            ActivationType=activation_type,
            Reserved=0x00,
        )
        await conn.write_request_raw(hdr, payload)

        req = DiagnosticSessionControlRequest(0x01)
        data = req.pdu

        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.DiagnosticMessage,
            PayloadLength=len(data) + 4,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = DiagnosticMessage(
            SourceAddress=src_addr,
            TargetAddress=target_addr,
            UserData=data,
        )
        await asyncio.wait_for(conn.write_request_raw(hdr, payload), timeout)

        _, diag_msg = await asyncio.wait_for(conn.read_diag_request_raw(), timeout)

        resp = DiagnosticSessionControlResponse.parse_static(diag_msg.UserData)
        raise_for_mismatch(req, resp)

        return TargetURI.from_parts(
            "doip",
            host,
            port,
            {
                "src_addr": diag_msg.SourceAddress,
                "dst_addr": diag_msg.TargetAddress,
                "activation_type": activation_type.value,
            },
        )

    async def main(self, args: Namespace) -> None:
        found = []
        src_gen = (
            range(args.stop + 1, args.start)
            if args.reversed
            else range(args.start, args.stop + 1)
        )

        for target_addr in src_gen:
            self.logger.log_info(f"testing target {target_addr:#02x}")
            conn = await DoIPConnection.connect(
                args.target.hostname,
                args.target.port,
                args.src_addr,
                target_addr,
            )

            try:
                target = await self.probe(
                    conn,
                    args.target.hostname,
                    args.target.port,
                    args.src_addr,
                    target_addr,
                    args.request_type,
                    args.timeout,
                )
            except (BrokenPipeError, asyncio.TimeoutError):
                continue
            finally:
                await conn.close()

            self.logger.log_info(f"found {target_addr:#02x}")
            found.append(target)

        self.logger.log_summary(f"Found {len(found)} targets")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        self.logger.log_summary(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)
