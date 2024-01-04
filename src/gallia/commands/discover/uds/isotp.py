# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from typing import Self

from pydantic import model_validator

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import UDSDiscoveryScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSDiscoveryScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSClient, UDSRequest
from gallia.services.uds.core.utils import g_repr
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI
from gallia.utils import can_id_repr, write_target_list

logger = get_logger(__name__)


class IsotpDiscovererConfig(UDSDiscoveryScannerConfig):
    start: AutoInt = Field(description="set start address", metavar="INT")
    stop: AutoInt = Field(description="set end address", metavar="INT")
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

    @model_validator(mode="after")
    def check_transport_requirements(self) -> Self:
        if self.target is not None and (not self.target.scheme == RawCANTransport.SCHEME):
            raise ValueError(f"Unsupported transport schema {self.target.scheme}; must be can-raw!")
        if self.extended_addr and (self.start > 0xFF or self.stop > 0xFF):
            raise ValueError("start/stop maximum value is 0xFF")

        return self


class IsotpDiscoverer(UDSDiscoveryScanner):
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
        transport = await RawCANTransport.connect(self.config.target)
        found = []

        sniff_time: int = self.config.sniff_time
        logger.result(f"Recording idle bus communication for {sniff_time}s")
        addr_idle = await transport.get_idle_traffic(sniff_time)

        logger.result(f"Found {len(addr_idle)} CAN Addresses on idle Bus")
        transport.set_filter(addr_idle, inv_filter=True)

        req = UDSRequest.parse_dynamic(self.config.pdu)
        pdu = self.build_isotp_frame(req, padding=self.config.padding)

        for ID in range(self.config.start, self.config.stop + 1):
            await asyncio.sleep(self.config.sleep)

            dst_addr = self.config.tester_addr if self.config.extended_addr else ID
            if self.config.extended_addr:
                pdu = self.build_isotp_frame(req, ID, padding=self.config.padding)

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
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, got answer from {can_id_repr(new_addr)}"
                        )
                    else:
                        logger.info(
                            f"seems like a large ISO-TP packet was received on CAN ID {can_id_repr(ID)}"
                        )
                except TimeoutError:
                    if is_broadcast:
                        logger.result(
                            f"seems that broadcast was triggered on CAN ID {can_id_repr(ID)}, got answer from {can_id_repr(addr)}"
                        )
                    else:
                        logger.result(
                            f"found endpoint on CAN ID [src:dst]: {can_id_repr(ID)}:{can_id_repr(addr)}: {payload.hex()}"
                        )
                        target_args = {}
                        target_args["is_fd"] = str(transport.config.is_fd).lower()
                        target_args["is_extended"] = str(transport.config.is_extended).lower()

                        if self.config.extended_addr:
                            target_args["ext_address"] = hex(ID)
                            target_args["rx_ext_address"] = hex(self.config.tester_addr & 0xFF)
                            target_args["src_addr"] = hex(self.config.tester_addr)
                            target_args["dst_addr"] = hex(addr)
                        else:
                            target_args["src_addr"] = hex(ID)
                            target_args["dst_addr"] = hex(addr)

                        if self.config.padding is not None:
                            target_args["tx_padding"] = f"{self.config.padding}"
                        if self.config.padding is not None:
                            target_args["rx_padding"] = f"{self.config.padding}"

                        hostname = self.config.target.hostname
                        assert hostname is not None

                        target = TargetURI.from_parts(
                            ISOTPTransport.SCHEME, hostname, None, target_args
                        )
                        found.append(target)
                    break

        logger.result(f"finished; found {len(found)} UDS endpoints")
        ecus_file = self.artifacts_dir.joinpath("ECUs.txt")
        logger.result(f"Writing urls to file: {ecus_file}")
        await write_target_list(ecus_file, found, self.db_handler)

        if self.config.query:
            await self.query_description(found, self.config.info_did)
