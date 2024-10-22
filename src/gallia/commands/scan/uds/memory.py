# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Literal

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, AutoLiteral, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSErrorCodes, UDSRequestConfig
from gallia.services.uds import UDSIsoServices as Services
from gallia.services.uds.core.utils import g_repr, uds_memory_parameters

logger = get_logger(__name__)


class MemoryFunctionsScannerConfig(UDSScannerConfig):
    session: AutoInt = Field(0x03, description="set session to perform test")
    check_session: int | None = Field(
        None,
        description="Check current session via read DID [for every nth MemoryAddress] and try to recover session",
        const=1,
    )
    service: AutoLiteral[
        Literal[
            Services.ReadMemoryByAddress,
            Services.WriteMemoryByAddress,
            Services.RequestDownload,
            Services.RequestUpload,
        ]
    ] = Field(
        description="Choose between 0x23 ReadMemoryByAddress 0x3d WriteMemoryByAddress, 0x34 RequestDownload and 0x35 RequestUpload"
    )
    data: HexBytes = Field(
        bytes(8),
        description="Service 0x3d requires a data payload which can be specified with this flag as a hex string",
    )


class MemoryFunctionsScanner(UDSScanner):
    """This scanner scans functions with direct access to memory.
    Specifically, these are service 0x3d WriteMemoryByAddress, 0x34 RequestDownload
    and 0x35 RequestUpload, which all share the same packet structure, except for
    0x3d which requires an additional data field.
    """

    CONFIG_TYPE = MemoryFunctionsScannerConfig
    SHORT_HELP = "scan services with direct memory access"

    def __init__(self, config: MemoryFunctionsScannerConfig):
        super().__init__(config)
        self.config: MemoryFunctionsScannerConfig = config

    async def main(self) -> None:
        resp = await self.ecu.set_session(self.config.session)
        if isinstance(resp, NegativeResponse):
            logger.critical(f"could not change to session: {resp}")
            sys.exit(1)

        for i in range(5):
            await self.scan_memory_address(i)

        logger.info(f"Scan in session {g_repr(self.config.session)} is complete!")
        logger.info(f"Leaving session {g_repr(self.config.session)} via hook")
        await self.ecu.leave_session(self.config.session, sleep=self.config.power_cycle_sleep)

    async def scan_memory_address(self, addr_offset: int = 0) -> None:
        sid = self.config.service.value
        data = self.config.data if sid == 0x3D else None  # Only service 0x3d has a data field
        memory_size = len(data) if data else 0x1000

        for i in range(0x100):
            addr = i << addr_offset * 8

            addr_and_length_identifier, addr_bytes, mem_size_bytes = uds_memory_parameters(
                addr, memory_size
            )

            pdu = bytes([sid])
            if sid in [0x34, 0x35]:
                # RequestUpload and RequestDownload require a DataFormatIdentifier
                # byte that defines encryption and compression. 00 is neither.
                pdu += bytes([0])
            pdu += bytes([addr_and_length_identifier])
            pdu += addr_bytes + mem_size_bytes
            pdu += data if data else b""

            if self.config.check_session and i % self.config.check_session == 0:
                # Check session and try to recover from wrong session (max 3 times), else skip session
                if not await self.ecu.check_and_set_session(self.config.session):
                    logger.error(
                        f"Aborting scan on session {g_repr(self.config.session)}; "
                        + f"current memory address was {g_repr(addr)}"
                    )
                    sys.exit(1)

            try:
                resp = await self.ecu.send_raw(pdu, config=UDSRequestConfig(tags=["ANALYZE"]))
            except TimeoutError:
                logger.result(f"Address {g_repr(addr)}: timeout")
                continue

            if isinstance(resp, NegativeResponse):
                if resp.response_code is UDSErrorCodes.requestOutOfRange:
                    logger.info(f"Address {g_repr(addr)}: {resp}")
                else:
                    logger.result(f"Address {g_repr(addr)}: {resp}")
            else:
                logger.result(f"Address {g_repr(addr)}: {resp}")
