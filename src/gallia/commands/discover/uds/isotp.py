# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace
from binascii import unhexlify

from gallia.command import UDSDiscoveryScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSClient, UDSRequest
from gallia.services.uds.core.utils import g_repr
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI
from gallia.utils import auto_int, can_id_repr, write_target_list

logger = get_logger("gallia.discover.isotp")


class IsotpDiscoverer(UDSDiscoveryScanner):
    """
    ## IsotpDiscoverer Class and Methods

    This class, `IsotpDiscoverer`, implements a UDS discovery scanner specifically designed to discover UDS endpoints on an Electronic Control Unit (ECU) using the ISO-TP normal addressing scheme. 

    ###  Key functionalities:

    * Discovers endpoints using ISO-TP normal addressing, the default protocol employed by OBD. 
    * Iterates through a specified CAN ID range to locate potential ECU endpoints.
    * Sends a user-defined ISO-TP PDU (Protocol Data Unit) to the discovered CAN IDs to identify responsive endpoints.
    * Analyzes the response to determine if a valid UDS endpoint is present.
    * Optionally queries the ECU description using a Diagnostic Trouble Code (DTC) identifier.

    ###  Usable arguments:

    * `--target`: URI defining the target ECU (mandatory). Example: `isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700` specifies an ISO-TP connection on virtual CAN interface vcan0 (CAN FD disabled, standard frames, source address 0x701, destination address 0x700).
    * `--sid`: UDS service ID to use for memory access (required, choices: 0x23, 0x3D, 0x34, 0x35). Not applicable to this class focussing on discovery.
    * `--session (optional)`: Diagnostic session to use during communication (default: 0x03). Not applicable to this class focussing on discovery.
    * `--start`: Starting CAN ID for the scanning range (mandatory).
    * `--stop`: Ending CAN ID for the scanning range (mandatory).
    * `--padding (optional)`: Sets ISO-TP padding value.
    * `--pdu`: Defines the ISO-TP PDU used for discovery (defaults to bytes([0x3E, 0x00])). 
    * `--sleep`: Sets the sleep time between scans (default: 0.01 seconds).
    * `--extended-addr`: Enables the use of extended ISO-TP addresses.
    * `--tester-addr`: Sets the tester address when extended addressing is enabled (default: 0x6F1).
    * `--query`: Triggers querying the ECU description via a Diagnostic Trouble Code (DTC) identifier after discovery.
    * `--info-did`: Specifies the DID (Data Identifier) used to query the ECU description (default: 0xF197).
    * `--sniff-time`: Sets the time duration (in seconds) to sniff the CAN bus for current traffic before initiating the scan (default: 5 seconds).

    ### Methods:

    * **constructor (__init__())** - Initializes the class and inherits functionalities from the parent class `UDSDiscoveryScanner`.
    * **configure_parser(self) -> None:** Defines the command-line arguments specific to the IsotpDiscoverer scanner.
    * **setup(self, args: Namespace) -> None:** Performs initial setup tasks based on the provided arguments. Validates arguments and ensures compatibility.
    * **query_description(self, target_list: list[TargetURI], did: int) -> None:** Queries the ECU description for each discovered endpoint using the specified DID.
    * **_build_isotp_frame_extended(self, pdu: bytes, ext_addr: int) -> bytes:** Constructs an ISO-TP frame with extended addressing.
    * **_build_isotp_frame(self, pdu: bytes) -> bytes:** Constructs a standard ISO-TP frame without extended addressing. 
    * **build_isotp_frame(self, req: UDSRequest, ext_addr: int | None = None, padding: int | None = None) -> bytes:** Builds an ISO-TP frame based on the provided UDS request, incorporating extended addressing and padding if specified.
    * **main(self, args: Namespace) -> None:** The main execution function that orchestrates the discovery process.

    This IsotpDiscoverer class offers a comprehensive solution to discover UDS endpoints on an ECU utilizing ISO-TP normal addressing. It provides informative logging and allows for various configuration options to tailor the scanning process.
    """

    SUBGROUP = "uds"
    COMMAND = "isotp"
    SHORT_HELP = "ISO-TP enumeration scanner"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=auto_int,
            required=True,
            help="set start address",
        )
        self.parser.add_argument(
            "--stop",
            metavar="INT",
            type=auto_int,
            required=True,
            help="set end address",
        )
        self.parser.add_argument(
            "--padding",
            type=auto_int,
            default=None,
            help="set isotp padding",
        )
        self.parser.add_argument(
            "--pdu",
            type=unhexlify,
            default=bytes([0x3E, 0x00]),
            help="set pdu used for discovery",
        )
        self.parser.add_argument(
            "--sleep",
            type=float,
            default=0.01,
            help="set sleeptime between loop iterations",
        )
        self.parser.add_argument(
            "--extended-addr",
            action="store_true",
            help="use extended isotp addresses",
        )
        self.parser.add_argument(
            "--tester-addr",
            type=auto_int,
            default=0x6F1,
            help="tester address for --extended",
        )
        self.parser.add_argument(
            "--query",
            action="store_true",
            help="query ECU description via RDBID",
        )
        self.parser.add_argument(
            "--info-did",
            metavar="DID",
            type=auto_int,
            default=0xF197,
            help="DID to query ECU description",
        )
        self.parser.add_argument(
            "--sniff-time",
            default=5,
            type=int,
            metavar="SECONDS",
            help="Time in seconds to sniff on bus for current traffic",
        )

    async def setup(self, args: Namespace) -> None:
        """
        Performs initial setup and validation based on provided arguments.

        Raises:
            argparse.ArgumentError: If an unsupported transport schema is provided or 
                                    if extended addressing is used with start/stop 
                                    values exceeding 0xFF.

        Calls the parent class `UDSDiscoveryScanner` setup method after performing 
        initial checks.
        """
        
        if args.target is not None and not args.target.scheme == RawCANTransport.SCHEME:
            self.parser.error(
                f"Unsupported transport schema {args.target.scheme}; must be can-raw!"
            )
        if args.extended_addr and (args.start > 0xFF or args.stop > 0xFF):
            self.parser.error("--start/--stop maximum value is 0xFF")
        await super().setup(args)

    async def query_description(self, target_list: list[TargetURI], did: int) -> None:
        """
        Queries the ECU description for each discovered endpoint in the target list 
        using the specified DID (Data Identifier).

        Args:
            target_list: List of TargetURI objects representing discovered endpoints.
            did: The DID (Data Identifier) used to query the ECU description.
        """
        
        logger.info("reading info DID from all discovered endpoints")
        for target in target_list:
            logger.result("----------------------------")
            logger.result(f"Probing ECU: {target}")

            transport = await ISOTPTransport.connect(target)
            uds_client = UDSClient(transport, timeout=2)
            logger.result(f"reading device description at {g_repr(did)}")
            try:
                resp = await uds_client.read_data_by_identifier(did)
                if isinstance(resp, NegativeResponse):
                    logger.result(f"could not read did: {resp}")
                else:
                    logger.result(f"response was: {resp}")
            except Exception as e:
                logger.result(f"reading description failed: {e!r}")

    def _build_isotp_frame_extended(
        self,
        pdu: bytes,
        ext_addr: int,
    ) -> bytes:
        """
        Constructs an ISO-TP frame using extended addressing.

        Args:
            pdu: The UDS Request PDU (Protocol Data Unit) to be encapsulated within the frame.
            ext_addr: The extended ISO-TP address (1 byte).

        Returns:
            The complete ISO-TP frame with extended addressing prepended to the PDU.
        """
        
        isotp_hdr = bytes([ext_addr, len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def _build_isotp_frame(self, pdu: bytes) -> bytes:
        """
        Constructs a standard ISO-TP frame without extended addressing.

        Args:
            pdu: The UDS Request PDU (Protocol Data Unit) to be encapsulated within the frame.

        Returns:
            The complete ISO-TP frame with standard addressing prepended to the PDU.
        """
        
        isotp_hdr = bytes([len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def build_isotp_frame(
        self,
        req: UDSRequest,
        ext_addr: int | None = None,
        padding: int | None = None,
    ) -> bytes:
        """
        Constructs an ISO-TP frame based on the provided UDS request, incorporating extended addressing and padding if specified.

        Args:
            req: The UDSRequest object containing the PDU to be transmitted.
            ext_addr: The extended ISO-TP address to be used (optional).
            padding: The padding value to be inserted in the frame (optional).

        Raises:
            ValueError: If the provided UDS request PDU exceeds the maximum allowed length for a single ISO-TP frame.

        Returns:
            The complete ISO-TP frame ready for transmission.

        This method first retrieves the PDU from the UDS request object. It then checks the PDU size against the maximum allowed length for a single ISO-TP frame. If the PDU is too large, a ValueError is raised.

        Depending on the presence of the `ext_addr` argument, the method calls either `_build_isotp_frame_extended` (for extended addressing) or `_build_isotp_frame` (for standard addressing) to construct the base frame.

        Finally, if padding is specified (`padding` argument is not None), the method calculates the required padding length and appends the padding bytes to the frame.
        """
        
        pdu = req.pdu
        max_pdu_len = 7 if ext_addr is None else 6
        if len(pdu) > max_pdu_len:
            raise ValueError("UDSRequest too large, ConsecutiveFrames not implemented")

        if ext_addr is None:
            frame = self._build_isotp_frame(pdu)
        else:
            frame = self._build_isotp_frame_extended(pdu, ext_addr)

        if padding is not None:
            pad_len = 8 - len(frame)
            frame += bytes([padding]) * pad_len

        return frame

    async def main(self, args: Namespace) -> None:
        """
        The main execution function that orchestrates the UDS endpoint discovery process on ISOTP.

        Args:
            args: A Namespace object containing parsed command-line arguments.

        This method performs the following steps:

        1. **Connect to CAN Transport:**
            - Establishes a connection to the specified CAN interface using the `RawCANTransport.connect` method.

        2. **Record Idle Bus Communication (Optional):**
            - If `args.sniff_time` is greater than zero, the method sniffs the CAN bus for the specified duration to capture any existing communication.
            - The captured CAN addresses are stored in the `addr_idle` variable.
            - The transport filter is then set to exclude these idle addresses using `transport.set_filter(addr_idle, inv_filter=True)`.

        3. **Parse UDS Request:**
            - Parses the UDS service PDU (Protocol Data Unit) from the provided `args.pdu` argument using the `UDSRequest.parse_dynamic` method.

        4. **Build ISO-TP Frame:**
            - Constructs an ISO-TP frame based on the parsed UDS request.
            - If `args.padding` is provided, the frame is padded with the specified value.
            - The `build_isotp_frame` method is used, potentially incorporating extended addressing if `args.extended_addr` is True.

        5. **Iterate Through CAN IDs:**
            - Loops through the CAN ID range specified by `args.start` and `args.stop` (inclusive).
            - A short sleep is introduced between iterations using `asyncio.sleep(args.sleep)`.

        6. **Send ISO-TP Frame and Handle Response:**
            - Determines the destination address (DST) for the frame:
                - If extended addressing is enabled (`args.extended_addr`), the tester address (`args.tester_addr`) is used.
                - Otherwise, the current CAN ID from the loop (`ID`) is used.
            - Sends the constructed ISO-TP frame to the determined DST address with a timeout of 0.1 seconds using `transport.sendto`.
            - Attempts to receive a response within a timeout of 0.1 seconds using `transport.recvfrom`.
                - If no response is received within the timeout, the loop continues to the next CAN ID.
                - If the received address (source address) matches the transmitted address (DST), it's considered a self-response and the loop skips to the next CAN ID.

            - Handles received responses:
                - If multiple responses are received for the same CAN ID, it's potentially indicative of a broadcast triggered by the request.
                    - The method logs a message and continues iterating.
                - If the response size suggests a large ISO-TP packet, it might be a multi-frame response.
                    - The method logs a message and continues iterating.

        7. **Identify UDS Endpoint:**
            - If a valid response is received from a different address than the transmitted one, a UDS endpoint is potentially discovered on the current CAN ID.
                - The method logs a success message and extracts details from the response:
                    - Source and destination CAN IDs.
                    - Response payload in hexadecimal format.
                - A `TargetURI` object is constructed representing the discovered endpoint, incorporating relevant details like transport scheme, hostname, addresses (source and destination), extended addressing settings (if applicable), and potentially padding values (if used).
                - The discovered endpoint is appended to the `found` list.
                - The loop exits, as a UDS endpoint has been identified on the current CAN ID.

        8. **Compile Results and Write to File:**
            - After iterating through the CAN ID range, the method logs the total number of discovered UDS endpoints.
            - It constructs the file path for storing the discovered endpoints in a text file named "ECUs.txt" within the `artifacts_dir` directory.
            - The `write_target_list` method is called asynchronously to write the list of discovered endpoints along with any associated database information (using `self.db_handler`) to the file.

        9. **Optional: Query ECU Description (Diagnostics):**
            - If `args.query` is True, the method calls the `query_description` method to retrieve the ECU description for each discovered endpoint using the specified DID (Data Identifier) from `args.info_did`.
        """
        transport = await RawCANTransport.connect(args.target)
        found = []

        sniff_time: int = args.sniff_time
        logger.result(f"Recording idle bus communication for {sniff_time}s")
        addr_idle = await transport.get_idle_traffic(sniff_time)

        logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)

        req = UDSRequest.parse_dynamic(args.pdu)
        pdu = self.build_isotp_frame(req, padding=args.padding)

        for ID in range(args.start, args.stop + 1):
            await asyncio.sleep(args.sleep)

            dst_addr = args.tester_addr if args.extended_addr else ID
            if args.extended_addr:
                pdu = self.build_isotp_frame(req, ID, padding=args.padding)

            logger.info(f"Testing ID {can_id_repr(ID)}")
            is_broadcast = False

            await transport.sendto(pdu, timeout=0.1, dst=dst_addr)
            try:
                addr, payload = await transport.recvfrom(timeout=0.1)
                if addr == ID:
                    logger.info(f"The same CAN ID {can_id_repr(ID)} answered. Skipping…")
                    continue
            except TimeoutError:
                continue

            while True:
                # The recv buffer needs to be flushed to avoid
                # wrong results...
                try:
                    new_addr, _ = await transport.recvfrom(timeout=0.1)
                    if new_addr != addr:
                        is_broadcast = True
                        logger.result(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(new_addr)}"
                        )
                    else:
                        logger.info(
                            f"seems like a large ISO-TP packet was received on CAN ID {can_id_repr(ID)}"
                        )
                except TimeoutError:
                    if is_broadcast:
                        logger.result(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, "
                            f"got answer from {can_id_repr(addr)}"
                        )
                    else:
                        logger.result(
                            f"found endpoint on CAN ID [src:dst]: {can_id_repr(ID)}:{can_id_repr(addr)}: {payload.hex()}"
                        )
                        target_args = {}
                        target_args["is_fd"] = str(transport.config.is_fd).lower()
                        target_args["is_extended"] = str(transport.config.is_extended).lower()

                        if args.extended_addr:
                            target_args["ext_address"] = hex(ID)
                            target_args["rx_ext_address"] = hex(args.tester_addr & 0xFF)
                            target_args["src_addr"] = hex(args.tester_addr)
                            target_args["dst_addr"] = hex(addr)
                        else:
                            target_args["src_addr"] = hex(ID)
                            target_args["dst_addr"] = hex(addr)

                        if args.padding is not None:
                            target_args["tx_padding"] = f"{args.padding}"
                        if args.padding is not None:
                            target_args["rx_padding"] = f"{args.padding}"

                        target = TargetURI.from_parts(
                            ISOTPTransport.SCHEME,
                            args.target.hostname,
                            None,
                            target_args,
                        )
                        found.append(target)
                    break

        logger.result(f"finished; found {len(found)} UDS endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        logger.result(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)

        if args.query:
            await self.query_description(found, args.info_did)
