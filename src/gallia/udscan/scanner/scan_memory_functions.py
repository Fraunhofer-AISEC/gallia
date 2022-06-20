# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from argparse import Namespace
from binascii import unhexlify

from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.constants import UDSErrorCodes
from gallia.uds.core.service import NegativeResponse
from gallia.uds.core.utils import uds_memory_parameters
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class ScanWriteDataByAddress(UDSScanner):
    """This scanner scans functions with direct access to memory.
    Specifically, these are service 0x3d WriteMemoryByAddress, 0x34 RequestDownload
    and 0x35 RequestUpload, which all share the same packet structure, except for
    0x3d which requires an additional data field.
    """

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--session", type=auto_int, default=0x03, help="set session to perform test"
        )
        self.parser.add_argument(
            "--check-session",
            nargs="?",
            const=1,
            type=int,
            help="Check current session via read DID [for every nth MemoryAddress] and try to recover session",
        )
        self.parser.add_argument(
            "--sid",
            required=True,
            choices=[0x23, 0x3D, 0x34, 0x35],
            type=auto_int,
            help="Choose between 0x23 ReadMemoryByAddress 0x3d WriteMemoryByAddress, "
            "0x34 RequestDownload and 0x35 RequestUpload",
        )
        self.parser.add_argument(
            "--data",
            default="0000000000000000",
            type=unhexlify,
            help="Service 0x3d requires a data payload which can be specified with this flag as a hex string",
        )

    async def main(self, args: Namespace) -> None:
        resp = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            self.logger.log_critical(f"could not change to session: {resp}")
            sys.exit(1)

        for i in range(5):
            await self.scan_memory_address(args, i)

    async def scan_memory_address(self, args: Namespace, addr_offset: int = 0) -> None:
        sid = args.sid
        data = args.data if sid == 0x3D else None  # Only service 0x3d has a data field
        memory_size = len(data) if data else 0x1000

        for i in range(0x100):
            addr = i << (addr_offset * 8)

            (
                addr_and_length_identifier,
                addr_bytes,
                mem_size_bytes,
            ) = uds_memory_parameters(addr, memory_size)

            pdu = bytes([sid])
            if sid in [0x34, 0x35]:
                # RequestUpload and RequestDownload require a DataFormatIdentifier
                # byte that defines encryption and compression. 00 is neither.
                pdu += bytes([00])
            pdu += bytes([addr_and_length_identifier])
            pdu += addr_bytes + mem_size_bytes
            pdu += data if data else b""

            if args.check_session and i % args.check_session == 0:
                # Check session and try to recover from wrong session (max 3 times), else skip session
                if not await self.ecu.check_and_set_session(args.session):
                    self.logger.log_error(
                        f"Aborting scan on session {g_repr(args.session)}; "
                        + f"current memory address was {g_repr(addr)}"
                    )
                    sys.exit(1)

            try:
                resp = await self.ecu.send_raw(
                    pdu, config=UDSRequestConfig(tags=["ANALYZE"])
                )
            except asyncio.TimeoutError:
                self.logger.log_summary(f"Address {g_repr(addr)}: timeout")
                continue

            if isinstance(resp, NegativeResponse):
                if resp.response_code is UDSErrorCodes.requestOutOfRange:
                    self.logger.log_info(f"Address {g_repr(addr)}: {resp}")
                else:
                    self.logger.log_summary(f"Address {g_repr(addr)}: {resp}")
            else:
                self.logger.log_summary(f"Address {g_repr(addr)}: {resp}")
