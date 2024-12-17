# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import socket
from collections.abc import Iterable
from itertools import product
from urllib.parse import parse_qs, urlparse

from gallia.command import AsyncScript
from gallia.command.base import AsyncScriptConfig
from gallia.command.config import AutoInt, Field
from gallia.log import get_logger
from gallia.net import net_if_broadcast_addrs
from gallia.services.uds.core.service import TesterPresentRequest, TesterPresentResponse
from gallia.transports.doip import (
    DiagnosticMessageNegativeAckCodes,
    DoIPConnection,
    DoIPEntityStatusResponse,
    DoIPNegativeAckError,
    DoIPRoutingActivationDeniedError,
    GenericHeader,
    PayloadTypes,
    ProtocolVersions,
    RoutingActivationRequestTypes,
    RoutingActivationResponseCodes,
    TimingAndCommunicationParameters,
    VehicleAnnouncementMessage,
)

logger = get_logger(__name__)


class DoIPDiscovererConfig(AsyncScriptConfig):
    start: AutoInt = Field(
        0x00, description="Set start address of TargetAddress search range", metavar="INT"
    )
    stop: AutoInt = Field(
        0xFFFF, description="Set stop address of TargetAddress search range", metavar="INT"
    )
    target: str | None = Field(
        None,
        description="The more you give, the more automatic detection will be skipped: IP, Port, RoutingActivationType, SourceAddress",
        metavar="<DoIP URL target string>",
    )
    timeout: float | None = Field(
        None,
        description="This flag overrides the default timeout of DiagnosticMessages, which can be used to fine-tune classification of unresponsive ECUs or broadcast detection",
        metavar="SECONDS (FLOAT)",
    )
    tcp_connect_delay: float = Field(
        0.0,
        description="This flag delays subsequent TCP connect attempts during all enumerations. Useful if the DoIP entity requires some time before accepting new TCP requests.",
        metavar="SECONDS (FLOAT)",
    )


class DoIPDiscoverer(AsyncScript):
    """This script scans for active DoIP endpoints and automatically enumerates allowed
    RoutingActivationTypes and known SourceAddresses. Once valid endpoints are acquired,
    the script continues to discover valid TargetAddresses that are accepted and respond
    to UDS TesterPresent requests."""

    CONFIG_TYPE = DoIPDiscovererConfig
    SHORT_HELP = "zero-knowledge DoIP enumeration scanner"
    HAS_ARTIFACTS_DIR = True

    protocol_version = ProtocolVersions.ISO_13400_2_2019.value

    def __init__(self, config: DoIPDiscovererConfig):
        super().__init__(config)
        self.config: DoIPDiscovererConfig = config

    # This is an ugly hack to circumvent AsyncScript's shortcomings regarding return codes

    def run(self) -> int:
        return asyncio.run(self.main2())

    async def main(self) -> None:
        pass

    async def main2(self) -> int:
        logger.notice("[👋] Welcome to @realDoIP-Discovery powered by MoarMemes…")

        target = urlparse(self.config.target) if self.config.target is not None else None
        if target is not None and target.scheme != "doip":
            logger.error("[🫣] --target must be doip://…")
            return 2

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run("doip")
            except Exception as e:
                logger.warning(f"Could not write the discovery run to the database: {e!r}")

        # Set TCP connect delay for RoutingActivationType and SourceAddress enumeration
        tcp_connect_delay: float = self.config.tcp_connect_delay

        # Discover Hostname and Port
        tgt_hostname: str
        tgt_port: int
        if target is not None and target.hostname is not None and (target.port is not None):
            logger.notice("[📋] Skipping host/port discovery because given by --target")
            tgt_hostname = target.hostname
            tgt_port = target.port
        else:
            logger.notice("[🔍] Discovering Host and Port via UDP Broadcast")

            hosts = await self.run_udp_discovery()

            if len(hosts) != 1:
                logger.error("[🍃] Can only continue with a single DoIP host! Give me a --target!")
                return 11

            tgt_hostname, tgt_port = hosts[0]

        # Politely ask for more details via UDP
        await self.gather_doip_details(tgt_hostname, tgt_port)

        # Enumerate all valid RoutingActivationType/Source Address tuples, but only if required
        rat_not_unsupported: Iterable[int]
        rat_not_unknown: Iterable[int]
        if target is not None and "activation_type" in parse_qs(target.query):
            logger.notice("[📋] Skipping RoutingActivationType discovery because given by --target")
            rat_not_unsupported = [int(parse_qs(target.query)["activation_type"][0], 0)]
        else:
            rat_not_unsupported = range(0x100)
        if target is not None and "src_addr" in parse_qs(target.query):
            logger.notice("[📋] Skipping SourceAddress discovery because given by --target")
            rat_not_unknown = [int(parse_qs(target.query)["src_addr"][0], 0)]
        else:
            rat_not_unknown = range(0x10000)

        # We need to know whether the DoIP entity checks for RoutingActivationTypes or SourceAddresses first
        # By requesting a RoutingActivation with reserved RAT and reserved SrcAddr, we see it based on the error
        a, _, _ = await self.enumerate_routing_activation_requests(
            tgt_hostname, tgt_port, [0x02], [0x00], tcp_connect_delay
        )
        routing_activation_types_first = len(a) == 0

        if routing_activation_types_first is True and len(rat_not_unsupported) != 1:
            logger.notice("[🔍] Enumerating RoutingActivationTypes")
            rat_not_unsupported, _, _ = await self.enumerate_routing_activation_requests(
                tgt_hostname, tgt_port, range(0x100), [0x00], tcp_connect_delay
            )
            logger.notice(
                f"[💎] Look what promising RoutingActivationTypes I've found: {', '.join([f'{x:#x}' for x in rat_not_unsupported])}"
            )
        elif routing_activation_types_first is False and len(rat_not_unknown) != 1:
            logger.notice("[🔍] Enumerating SourceAddresses")
            _, rat_not_unknown, _ = await self.enumerate_routing_activation_requests(
                tgt_hostname, tgt_port, [0x02], range(0x10000), tcp_connect_delay
            )
            logger.notice(
                f"[💎] Look what promising SourceAddresses I've found: {', '.join([f'{x:#x}' for x in rat_not_unknown])}"
            )

        logger.notice("[🔍] Enumerating valid RoutingActivationType/SourceAddress tuples")
        _, _, targets = await self.enumerate_routing_activation_requests(
            tgt_hostname, tgt_port, rat_not_unsupported, rat_not_unknown, tcp_connect_delay
        )

        if len(targets) != 1:
            logger.error(
                f"[💣] I found {len(targets)} valid RoutingActivationType/SourceAddress tuples, but can only continue with exactly one; choose your weapon with --target!"
            )
            return 20

        # Enumerate valid TargetAddresses
        if target is not None and "target_addr" in parse_qs(target.query):
            logger.error(
                "[😵] Why do you give me a target_addr in --target? Am I useless to you??? GOODBYE!"
            )
            return 3

        logger.notice(
            f"[🔍] Enumerating all TargetAddresses from {self.config.start:#x} to {self.config.stop:#x}"
        )

        target = urlparse(targets[0])
        tgt_src = int(parse_qs(target.query)["src_addr"][0], 0)
        tgt_rat = int(parse_qs(target.query)["activation_type"][0], 0)

        await self.enumerate_target_addresses(
            tgt_hostname,
            tgt_port,
            tgt_rat,
            tgt_src,
            self.config.start,
            self.config.stop,
            tcp_connect_delay,
            self.config.timeout,
        )

        logger.notice("[🛩️] All done, thanks for flying with us!")
        return 0

    async def gather_doip_details(self, tgt_hostname: str, tgt_port: int) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setblocking(False)
        sock.bind(("0.0.0.0", 0))
        loop = asyncio.get_running_loop()

        # We send two packets: a VehicleIdentificationRequest and a DoIPEntityStatusRequest that
        # only differ in their response, so let's reuse code...
        for req_type in [
            PayloadTypes.VehicleIdentificationRequestMessage,
            PayloadTypes.DoIPEntityStatusRequest,
        ]:
            logger.info(f"[🥚] Sending {req_type.name}...")

            hdr = GenericHeader(
                ProtocolVersion=self.protocol_version
                if req_type == PayloadTypes.DoIPEntityStatusRequest
                else 0xFF,
                PayloadType=req_type,
                PayloadLength=0,
            )
            await loop.sock_sendto(sock, hdr.pack(), (tgt_hostname, tgt_port))

            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), 2)
            except TimeoutError:
                logger.info("[🐣] No response!")
                continue

            hdr = GenericHeader.unpack(data[:8])

            if hdr.PayloadType == PayloadTypes.VehicleAnnouncementMessage:
                logger.notice(
                    f"[👮] Identification please: {VehicleAnnouncementMessage.unpack(data[8:])}"
                )
                logger.info(f"[🎯] Setting protocol version to {hdr.ProtocolVersion}")
                self.protocol_version = hdr.ProtocolVersion
            elif hdr.PayloadType == PayloadTypes.DoIPEntityStatusResponse:
                status = DoIPEntityStatusResponse.unpack(data[8:])
                logger.notice(
                    f"[👏] This DoIP entity is a {status.NodeType.name} with {status.CurrentlyOpenTCP_DATASockets}/{status.MaximumConcurrentTCP_DATASockets} concurrent TCP sockets currently open and a maximum data size of {status.MaximumDataSize} ({status.MaximumDataSize:#0x})."
                )

        sock.close()

    async def enumerate_routing_activation_requests(
        self,
        tgt_hostname: str,
        tgt_port: int,
        routing_activation_types: Iterable[int],
        source_addresses: Iterable[int],
        tcp_connect_delay: float,
    ) -> tuple[list[int], list[int], list[str]]:  # noqa: PLR0913
        rat_not_unsupported: list[int] = []
        rat_not_unknown: list[int] = []
        targets: list[str] = []

        for routing_activation_type, source_address in product(
            routing_activation_types, source_addresses
        ):
            try:  # Dummy target address, never actually used
                # Ensure that connections do not remain in TIME_WAIT
                conn = await DoIPConnection.connect(
                    tgt_hostname,
                    tgt_port,
                    source_address,
                    0xAFFE,
                    so_linger=True,
                    protocol_version=self.protocol_version,
                )
            except OSError as e:
                logger.warning(
                    f"[🚨] J.A.R.V.I.S., recheck rat {routing_activation_type:#x} and src_addr {source_address:#x}; they failed with {e!r}"
                )
                continue

            try:
                await conn.write_routing_activation_request(routing_activation_type)
            except DoIPRoutingActivationDeniedError as e:
                logger.info(
                    f"[🌟] Brilliant, RoutingActivationType {routing_activation_type:#x} and SourceAddress {source_address:#x} yields {e.rac_code.name}"
                )

                if e.rac_code != RoutingActivationResponseCodes.UnsupportedActivationType:
                    rat_not_unsupported.append(routing_activation_type)
                if e.rac_code != RoutingActivationResponseCodes.UnknownSourceAddress:
                    rat_not_unknown.append(source_address)
                continue
            finally:
                await conn.close()
                await asyncio.sleep(tcp_connect_delay)

            targets.append(
                f"doip://{tgt_hostname}:{tgt_port}?protocol_version={self.protocol_version}&activation_type={routing_activation_type:#x}&src_addr={source_address:#x}"
            )
            logger.notice(f"[🤯] Holy moly, it actually worked: {targets[-1]}")

            with self.artifacts_dir.joinpath("1_valid_routing_activation_requests.txt").open(
                "a"
            ) as f:
                f.write(f"{targets[-1]}\n")

        if len(targets) > 0:
            logger.notice("[⚔️] It's dangerous to test alone, take one of these:")
            for item in targets:
                logger.notice(item)

        return (rat_not_unsupported, rat_not_unknown, targets)

    async def enumerate_target_addresses(
        self,
        tgt_hostname: str,
        tgt_port: int,
        correct_rat: int,
        correct_src: int,
        start: int,
        stop: int,
        tcp_connect_delay: float,
        timeout: None | float = None,
    ) -> None:  # noqa: PLR0913
        known_targets = []
        unreachable_targets = []
        search_space = range(start, stop + 1)

        target_template = f"doip://{tgt_hostname}:{tgt_port}?protocol_version={self.protocol_version}&activation_type={correct_rat:#x}&src_addr={correct_src:#x}&target_addr={{:#x}}"
        conn = await self.create_DoIP_conn(
            tgt_hostname, tgt_port, correct_rat, correct_src, 0xAFFE, fast_queue=True
        )
        reader_task = asyncio.create_task(self.task_read_diagnostic_messages(conn, target_template))

        for target_addr in search_space:
            logger.debug(f"[🚧] Attempting connection to {target_addr:#x}")

            conn.target_addr = target_addr
            current_target = target_template.format(target_addr)

            try:
                req = TesterPresentRequest(suppress_response=False)
                await conn.write_diag_request(req.pdu)

                # If we reach this, the request was not denied due to unknown TargetAddress or other DoIP errors
                known_targets.append(current_target)
                logger.notice(f"[🥈] HEUREKA: target address {target_addr:#x} is valid! ")
                with self.artifacts_dir.joinpath("3_valid_targets.txt").open("a") as f:
                    f.write(f"{current_target}\n")

                # Here is where "reader_task" comes into play, which monitors incoming DiagnosticMessage replies

            except DoIPNegativeAckError as e:
                if e.nack_code == DiagnosticMessageNegativeAckCodes.UnknownTargetAddress:
                    logger.info(f"[🫥] {target_addr:#x} is an unknown target address")
                    continue
                elif e.nack_code == DiagnosticMessageNegativeAckCodes.TargetUnreachable:
                    logger.info(f"[💤] {target_addr:#x} is (currently?) unreachable")
                    unreachable_targets.append(current_target)
                    with self.artifacts_dir.joinpath("5_unreachable_targets.txt").open("a") as f:
                        f.write(f"{current_target}\n")
                    continue
                else:
                    logger.warning(
                        f"[🤷] {target_addr:#x} is behaving strangely: {e.nack_code.name}"
                    )
                    with self.artifacts_dir.joinpath("7_targets_with_errors.txt").open("a") as f:
                        f.write(f"{target_addr:#x}: {e.nack_code.name}\n")
                    continue

            except ConnectionError as e:
                # Whenever this triggers, but sometimes connections are closed not by us
                logger.warning(f"[🫦] Sexy, but unexpected: {target_addr:#x} triggered {e!r}")
                with self.artifacts_dir.joinpath("7_targets_with_errors.txt").open("a") as f:
                    f.write(f"{target_addr:#x}: {e}\n")
                # Re-establish DoIP connection
                await conn.close()
                await asyncio.sleep(tcp_connect_delay)

                conn = await self.create_DoIP_conn(
                    tgt_hostname, tgt_port, correct_rat, correct_src, 0xAFFE
                )
                continue

        logger.notice(
            f"[⚔️] It's dangerous to test alone, take one of these {len(known_targets)} known targets:"
        )
        if len(known_targets) > 100:
            logger.notice("[💯] Too many to print, check the artifacts instead!")
        else:
            for item in known_targets:
                logger.notice(item)

        logger.notice(
            f"[❓] Those {len(unreachable_targets)} targets were unreachable by the gateway (could be just temporary):"
        )
        for item in unreachable_targets:
            logger.notice(item)

        logger.info("[😴] Giving all ECUs a chance to reply...")
        await asyncio.sleep(TimingAndCommunicationParameters.DiagnosticMessageMessageTimeout / 1000)
        reader_task.cancel()
        await reader_task
        await conn.close()

        logger.notice(
            f"[🧭] Check out the content of the log files at {self.artifacts_dir} as well!"
        )

    async def task_read_diagnostic_messages(
        self, conn: DoIPConnection, target_template: str
    ) -> None:
        responsive_targets = []
        potential_broadcasts = []
        try:
            while True:
                _, payload = await conn.read_diag_request_raw()
                (source_address, data) = (payload.SourceAddress, payload.UserData)
                current_target = target_template.format(source_address)

                resp = TesterPresentResponse.parse_static(data)
                logger.notice(f"[🥇] It cannot get nicer: {source_address:#x} responded: {resp}")

                if current_target not in responsive_targets:
                    responsive_targets.append(current_target)
                    with self.artifacts_dir.joinpath("4_responsive_targets.txt").open("a") as f:
                        f.write(f"{current_target}\n")
                    if self.db_handler is not None:
                        await self.db_handler.insert_discovery_result(current_target)

                if (
                    abs(source_address - conn.target_addr) > 10
                    and conn.target_addr not in potential_broadcasts
                ):
                    potential_broadcasts.append(conn.target_addr)

        except asyncio.CancelledError:
            logger.debug("Diagnostic Message reader got cancelled")
        except Exception as e:
            logger.error(f"Diagnostic Message reader died with {e!r}")

        finally:
            logger.notice(
                f"[💰] For even more profit, try one of the {len(responsive_targets)} targets that actually responded:"
            )
            for item in responsive_targets:
                logger.notice(item)

            # TODO: the discoverer could be extended to search for and validate the broadcast address(es) automatically
            if len(potential_broadcasts) > 0:
                logger.notice(
                    "[🕵️] You could also investigate these target addresses that appear to be near broadcasts:"
                )
            for target_addr in potential_broadcasts:
                logger.notice(f"[🤑] B-B-B-B-B-B-BROADCAST around TargetAddress {target_addr:#x}!")

    async def create_DoIP_conn(
        self,
        hostname: str,
        port: int,
        routing_activation_type: int,
        src_addr: int,
        target_addr: int,
        fast_queue: bool = False,
    ) -> DoIPConnection:  # noqa: PLR0913
        while True:
            try:  # Ensure that connections do not remain in TIME_WAIT
                conn = await DoIPConnection.connect(
                    hostname,
                    port,
                    src_addr,
                    target_addr,
                    so_linger=True,
                    protocol_version=self.protocol_version,
                    separate_diagnostic_message_queue=fast_queue,
                )
                logger.info("[📫] Sending RoutingActivationRequest")
                await conn.write_routing_activation_request(
                    RoutingActivationRequestTypes(routing_activation_type)
                )
            except Exception as e:  # TODO: this probably is too broad
                logger.warning(
                    f"[🫨] Got me some good errors when it should be working (dis an infinite loop): {e!r}"
                )
                continue
            return conn

    async def run_udp_discovery(self) -> list[tuple[str, int]]:
        addrs = net_if_broadcast_addrs()
        found = []

        for addr in addrs:
            logger.info(f"[💌] Sending DoIP VehicleIdentificationRequest to {addr.broadcast}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((str(addr.local), 0))
            loop = asyncio.get_running_loop()

            hdr = GenericHeader(0xFF, PayloadTypes.VehicleIdentificationRequestMessage, 0x00)
            await loop.sock_sendto(sock, hdr.pack(), (str(addr.broadcast), 13400))
            try:
                while True:
                    data, from_addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), 2)
                    info = VehicleAnnouncementMessage.unpack(data[8:])
                    logger.notice(f"[💝]: {addr} responded: {info}")
                    found.append(from_addr)
            except TimeoutError:
                logger.info("[💔] Reached timeout...")
                continue
            finally:
                sock.close()

        if len(found) > 0:
            logger.notice("[💎] Look what valid hosts I've found:")
            for item in found:
                url = f"doip://{item[0]}:{item[1]}"
                logger.notice(url)
                with self.artifacts_dir.joinpath("0_valid_hosts.txt").open("a") as f:
                    f.write(f"{url}\n")
        else:
            logger.notice(
                "[👸] Your princess is in another castle: no DoIP endpoints here it seems..."
            )

        return found
