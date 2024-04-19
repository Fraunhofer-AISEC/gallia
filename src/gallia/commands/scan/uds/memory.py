# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import Namespace
from binascii import unhexlify

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSErrorCodes, UDSRequestConfig
from gallia.services.uds.core.utils import g_repr, uds_memory_parameters
from gallia.utils import auto_int

logger = get_logger("gallia.scan.memory")


class MemoryFunctionsScanner(UDSScanner):
    """This scanner targets ECUs (Electronic Control Units) and scans functions that provide direct access to memory.

    It focuses on the following services defined by the Unified Diagnostic Service (UDS) standard:

    * ReadMemoryByAddress (service ID 0x23): This service allows reading data from a specified memory address.
    * WriteMemoryByAddress (service ID 0x3D): This service allows writing data to a specified memory address.
    * RequestDownload (service ID 0x34): This service allows downloading a block of data from the ECU's memory.
    * RequestUpload (service ID 0x35): This service allows uploading a block of data to the ECU's memory.

    These services all share a similar packet structure, with the exception of WriteMemoryByAddress which requires an additional data field.

    This scanner class provides functionality to iterate through a range of memory addresses and attempt to:
        * Read or write data using the specified UDS service.
        * Handle potential timeouts that might occur during communication with the ECU.
        * Analyze the ECU's response to these memory access attempts, which might indicate vulnerabilities or security mechanisms.

    The scanner offers several configuration options through command-line arguments to customize its behavior:
        * Target diagnostic session (default: 0x03).
        * Optionally verify and potentially recover the session before each memory access.
        * Specify the UDS service to use for memory access (required, choices: 0x23, 0x3D, 0x34, 0x35).
        * Provide data to write for service 0x3D WriteMemoryByAddress (hex string).
    """

    SHORT_HELP = "scan services with direct memory access"
    COMMAND = "memory"

    def configure_parser(self) -> None:
        """Adds arguments specific to the memory scanner to the argument parser.

        * `--session`: Diagnostic session to use during communication (default: 0x03).
        * `--check-session`: Optionally verify the current session before each memory access 
                          and attempt to recover if lost (default: False). Provide the number of 
                          memory accesses between checks as an argument (e.g., --check-session 10).
        * `--sid`: Service ID to use for memory access (required, choices: 0x23, 0x3D, 0x34, 0x35).
        * `--data`: Data payload to send with service 0x3d WriteMemoryByAddress (hex string).
        """

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x03,
            help="set session to perform test",
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
        """
        The main entry point for the memory scanner.

        Establishes the target session, then scans several memory addresses using 
        `scan_memory_address`.

        Args:
            args: Namespace object containing parsed command-line arguments.
        """

        resp = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            logger.critical(f"could not change to session: {resp}")
            sys.exit(1)

        for i in range(5):
            await self.scan_memory_address(args, i)

    async def scan_memory_address(self, args: Namespace, addr_offset: int = 0) -> None:
        """
        Scans a single memory address using the specified service and parameters.

        Args:
            args: Namespace object containing parsed command-line arguments.
            addr_offset: Optional offset to apply to the base memory address during scanning 
                         (default: 0). Useful for scanning consecutive memory regions.
        """

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
                    logger.error(
                        f"Aborting scan on session {g_repr(args.session)}; "
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
