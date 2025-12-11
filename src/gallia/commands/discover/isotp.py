# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from itertools import product

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSClient, UDSRequest
from gallia.services.uds.core.utils import g_repr
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI

logger = get_logger(__name__)


class IsotpDiscovererConfig(AsyncScriptConfig):
    iface: str = Field(description="Discover on this CAN interface")
    start: AutoInt = Field(0, description="set start address", metavar="INT")
    stop: AutoInt = Field(0x7FF, description="set end address", metavar="INT")
    force_extended_ids: bool = Field(
        False, description="Force extended CAN IDs bit also for IDs in range 0-0x7FF"
    )
    is_fd: bool = Field(False, description="Enable CAN-FD")
    padding: AutoInt | None = Field(None, description="set isotp padding")
    pdu: HexBytes = Field(bytes([0x3E, 0x00]), description="set pdu used for discovery")
    sleep: float = Field(0.01, description="set sleeptime between loop iterations")
    extended_addr: bool = Field(False, description="use extended isotp addresses")
    tester_addr: AutoInt = Field(0x6F1, description="tester address for --extended")
    query: bool = Field(False, description="query ECU description via RDBID")
    info_did: AutoInt = Field(0xF197, description="DID to query ECU description", metavar="DID")
    sniff_time: int = Field(
        5, description="Time in seconds to sniff on bus for current traffic", metavar="SECONDS"
    )


class IsotpDiscoverer(AsyncScript):
    """Discovers all UDS endpoints on an ECU using ISO-TP normal addressing.
    This is the default protocol used by OBD.
    When using normal addressing, the ISO-TP header does not include an address and there is no generic tester address.
    Addressing is only done via CAN IDs. Every endpoint has a source and destination CAN ID.
    Typically, there is also a broadcast destination ID to address all endpoints."""

    CONFIG_TYPE = IsotpDiscovererConfig
    SHORT_HELP = "ISO-TP enumeration scanner"

    def __init__(self, config: IsotpDiscovererConfig):
        super().__init__(config)
        self.config: IsotpDiscovererConfig = config

    async def query_description(self, target_list: list[TargetURI], did: int) -> None:
        logger.info("reading info DID from all discovered endpoints")
        for target in target_list:
            logger.result("----------------------------")
            logger.result(f"Probing ECU: {target}")

            transport = ISOTPTransport(target)
            await transport.connect()
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

    def _build_isotp_frame_extended(self, pdu: bytes, ext_addr: int) -> bytes:
        isotp_hdr = bytes([ext_addr, len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def _build_isotp_frame(self, pdu: bytes) -> bytes:
        isotp_hdr = bytes([len(pdu) & 0x0F])
        return isotp_hdr + pdu

    def build_isotp_frame(
        self, req: UDSRequest, ext_addr: int | None = None, padding: int | None = None
    ) -> bytes:
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

    async def main(self) -> None:
        if self.config.extended_addr and (self.config.start > 0xFF or self.config.stop > 0xFF):
            logger.warning(
                "Capping maximum value of start/stop to 0xFF, because it is the maximum of ISOTP's extended addressing!"
            )
            self.config.start = min(self.config.start, 0xFF)
            self.config.stop = min(self.config.stop, 0xFF)

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run(ISOTPTransport.SCHEME)
            except Exception as e:
                logger.warning(f"Could not write the discovery run to the database: {e!r}")

        transport = RawCANTransport(
            TargetURI.from_parts(
                RawCANTransport.SCHEME,
                self.config.iface,
                None,
                {
                    "force_extended_ids": "true" if self.config.force_extended_ids else "false",
                    "is_fd": "true" if self.config.is_fd else "false",
                },
            )
        )
        await transport.connect()
        found: list[TargetURI] = []

        sniff_time: int = self.config.sniff_time
        logger.result(f"Recording idle bus communication for {sniff_time}s")
        addr_idle = await transport.get_idle_traffic(sniff_time)

        logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)

        req = UDSRequest.parse_dynamic(self.config.pdu)

        # If not explicitly specified, attempt without and with 0xAA padding for each ID
        if self.config.padding is None:
            padding: list[None | int] = [None, 0xAA]
        else:
            padding = [self.config.padding]

        for ID, padding_byte in product(range(self.config.start, self.config.stop + 1), padding):
            await asyncio.sleep(self.config.sleep)

            tx_id = self.config.tester_addr if self.config.extended_addr else ID
            if self.config.extended_addr is True:
                pdu = self.build_isotp_frame(req, ID, padding=padding_byte)
            else:
                pdu = self.build_isotp_frame(req, padding=padding_byte)

            logger.info(f"Testing ID {hex(ID)}")
            is_broadcast = False

            await transport.sendto(pdu, timeout=0.1, arbitration_id=tx_id)
            try:
                rx_id, payload = await transport.recvfrom(timeout=0.1)
                if rx_id == ID:
                    logger.info(f"The same CAN ID {hex(ID)} responded. Skipping…")
                    continue
            except TimeoutError:
                continue

            while True:
                # The recv buffer needs to be flushed to avoid
                # wrong results...
                try:
                    new_id, _ = await transport.recvfrom(timeout=0.1)
                    if new_id != rx_id:
                        is_broadcast = True
                        logger.result(
                            f"seems that broadcast was triggered on CAN ID {hex(ID)}, got response from {hex(new_id)}"
                        )
                    else:
                        logger.info(
                            f"seems like a large ISO-TP packet was received on CAN ID {hex(ID)}"
                        )
                except TimeoutError:
                    # This branch is reached if there is no other response after the first
                    if is_broadcast:
                        logger.result(
                            f"seems that broadcast was triggered on CAN ID {hex(ID)}, got response from {hex(rx_id)}"
                        )
                    # Check if ID is already in list of found IDs
                    elif hex(ID) in [
                        x.qs_flat["ext_address"]
                        if "ext_address" in x.qs_flat
                        else x.qs_flat["tx_id"]
                        for x in found
                    ]:
                        logger.result(f"Found {hex(ID)} multiple times, ignoring!")
                    else:
                        logger.result(
                            f"Found endpoint for CAN IDs [tx:rx]: {hex(ID)}:{hex(rx_id)} | {payload.hex()}"
                        )
                        target_args = {}
                        if self.config.extended_addr is True:
                            target_args["ext_address"] = hex(ID)
                            target_args["rx_ext_address"] = hex(self.config.tester_addr & 0xFF)
                            target_args["tx_id"] = hex(self.config.tester_addr)
                            target_args["rx_id"] = hex(rx_id)
                        else:
                            target_args["tx_id"] = hex(tx_id)
                            target_args["rx_id"] = hex(rx_id)

                        # Only add the following if required, since "false"/None is ISOTP's default
                        if self.config.is_fd is True:
                            target_args["is_fd"] = "true"

                        if self.config.force_extended_ids is True:
                            target_args["force_extended"] = "true"

                        if padding_byte is not None:
                            target_args["tx_padding"] = hex(padding_byte)
                            target_args["rx_padding"] = hex(padding_byte)

                        target = TargetURI.from_parts(
                            ISOTPTransport.SCHEME, self.config.iface, None, target_args
                        )
                        found.append(target)
                    break

        logger.result(f"Finished: found {len(found)} UDS endpoints")

        if len(found) > 0:
            for target in found:
                logger.result(f" -> {target}")

            if self.artifacts_dir is not None:
                ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
                logger.result(f"Writing targets to file: {ecus_file}")
                with ecus_file.open("w") as f:
                    for target in found:
                        f.write(f"{target}\n")

            if self.db_handler is not None:
                logger.result("Adding targets to database")
                for target in found:
                    await self.db_handler.insert_discovery_result(str(target))

        if self.config.query:
            await self.query_description(found, self.config.info_did)
