# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import socket
from argparse import Namespace
from collections.abc import Iterable
from itertools import chain, product
from urllib.parse import parse_qs, urlparse

import aiofiles
import psutil

from gallia.command import AsyncScript
from gallia.log import get_logger
from gallia.services.uds.core.service import (
    TesterPresentRequest,
    TesterPresentResponse,
)
from gallia.transports.doip import (
    DiagnosticMessage,
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

logger = get_logger("gallia.discover.doip")


class DoIPDiscoverer(AsyncScript):
    """This script scans for active DoIP endpoints and automatically enumerates allowed
    RoutingActivationTypes and known SourceAddresses. Once valid endpoints are acquired,
    the script continues to discover valid TargetAddresses that are accepted and respond
    to UDS TesterPresent requests."""

    GROUP = "discover"
    COMMAND = "doip"
    SHORT_HELP = "zero-knowledge DoIP enumeration scanner"
    HAS_ARTIFACTS_DIR = True

    protocol_version = ProtocolVersions.ISO_13400_2_2019.value

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=lambda x: int(x, 0),
            default=0x00,
            help="Set start address of TargetAddress search range",
        )
        self.parser.add_argument(
            "--stop",
            metavar="INT",
            type=lambda x: int(x, 0),
            default=0xFFFF,
            help="Set stop address of TargetAddress search range",
        )
        self.parser.add_argument(
            "--target",
            metavar="<DoIP URL target string>",
            type=str,
            default=None,
            help="The more you give, the more automatic detection will be skipped: IP, Port, RoutingActivationType, SourceAddress",
        )
        self.parser.add_argument(
            "--timeout",
            metavar="SECONDS (FLOAT)",
            type=float,
            default=None,
            help="This flag overrides the default timeout of DiagnosticMessages, which can be used to fine-tune classification of unresponsive ECUs or broadcast detection",
        )

    # This is an ugly hack to circumvent AsyncScript's shortcomings regarding return codes
    def run(self, args: Namespace) -> int:
        return asyncio.run(self.main2(args))

    async def main(self, args: Namespace) -> None:
        pass

    async def main2(self, args: Namespace) -> int:
        logger.notice("[👋] Welcome to @realDoIP-Discovery powered by MoarMemes…")

        target = urlparse(args.target) if args.target is not None else None
        if target is not None and target.scheme != "doip":
            logger.error("[🫣] --target must be doip://…")
            return 2

        if self.db_handler is not None:
            try:
                await self.db_handler.insert_discovery_run("doip")
            except Exception as e:
                logger.warning(f"Could not write the discovery run to the database: {e!r}")

        # Discover Hostname and Port
        tgt_hostname: str
        tgt_port: int
        if target is not None and target.hostname is not None and target.port is not None:
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

        # Find correct RoutingActivationType
        rat_success: list[int] = []
        rat_wrong_source: list[int] = []
        if target is not None and "activation_type" in parse_qs(target.query):
            logger.notice("[📋] Skipping RoutingActivationType discovery because given by --target")
            rat_success = [int(parse_qs(target.query)["activation_type"][0], 0)]
        else:
            logger.notice("[🔍] Enumerating RoutingActivationTypes")

            (
                rat_success,
                rat_wrong_source,
            ) = await self.enumerate_routing_activation_types(
                tgt_hostname,
                tgt_port,
                int(parse_qs(target.query)["src_addr"][0], 0)
                if target is not None and "src_addr" in parse_qs(target.query)
                else 0xE00,
            )

        if len(rat_success) == 0 and len(rat_wrong_source) == 0:
            logger.error(
                "[🥾] Damn son, didn't find a single RoutingActivationType with unknown source?! OUTTA HERE!"
            )
            return 10

        # Discovering correct source address for suitable RoutingActivationRequests
        if target is not None and "src_addr" in parse_qs(target.query):
            logger.notice("[📋] Skipping SourceAddress discovery because given by --target")
            targets = [
                f"doip://{tgt_hostname}:{tgt_port}?protocol_version={self.protocol_version}&activation_type={rat:#x}&src_addr={parse_qs(target.query)['src_addr'][0]}"
                for rat in rat_success
            ]

        else:
            logger.notice("[🔍] Enumerating SourceAddresses for all found RoutingActivationTypes")
            targets = await self.enumerate_source_addresses(
                tgt_hostname,
                tgt_port,
                chain(rat_success, rat_wrong_source),
            )

        if len(targets) != 1:
            logger.error(
                f"[💣] I found {len(targets)} valid RoutingActivationType/SourceAddress combos, but can only continue with exactly one; choose your weapon with --target!"
            )
            return 20

        # Enumerate valid TargetAddresses
        if target is not None and "target_addr" in parse_qs(target.query):
            logger.error(
                "[😵] Why do you give me a target_addr in --target? Am I useless to you??? GOODBYE!"
            )
            return 3

        logger.notice(
            f"[🔍] Enumerating all TargetAddresses from {args.start:#x} to {args.stop:#x}"
        )

        target = urlparse(targets[0])
        tgt_src = int(parse_qs(target.query)["src_addr"][0], 0)
        tgt_rat = int(parse_qs(target.query)["activation_type"][0], 0)

        await self.enumerate_target_addresses(
            tgt_hostname,
            tgt_port,
            tgt_rat,
            tgt_src,
            args.start,
            args.stop,
            args.timeout,
        )

        logger.notice("[🛩️] All done, thanks for flying with us!")
        return 0

    async def gather_doip_details(
        self,
        tgt_hostname: str,
        tgt_port: int,
    ) -> None:
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
                    f"[👏] This DoIP entity is a {status.NodeType.name} with "
                    f"{status.CurrentlyOpenTCP_DATASockets}/{status.MaximumConcurrentTCP_DATASockets} "
                    f"concurrent TCP sockets currently open and a maximum data size of {status.MaximumDataSize}."
                )

        sock.close()

    async def enumerate_routing_activation_types(
        self,
        tgt_hostname: str,
        tgt_port: int,
        src_addr: int,
    ) -> tuple[list[int], list[int]]:
        rat_not_unsupported: list[int] = []
        rat_success: list[int] = []
        rat_wrong_source: list[int] = []
        for routing_activation_type in range(0x100):
            try:
                conn = await DoIPConnection.connect(
                    tgt_hostname,
                    tgt_port,
                    src_addr,
                    0xAFFE,
                    so_linger=True,  # Ensure that connections do not remain in TIME_WAIT
                    protocol_version=self.protocol_version,
                )
            except OSError as e:
                logger.error(f"[🚨] Mr. Stark I don't feel so good: {e!r}")
                return rat_success, rat_wrong_source

            try:
                await conn.write_routing_activation_request(routing_activation_type)
                rat_success.append(routing_activation_type)
                logger.notice(
                    f"[🤯] Holy moly, it actually worked for activation_type {routing_activation_type:#x} and src_addr {src_addr:#x}!!!"
                )
            except DoIPRoutingActivationDeniedError as e:
                logger.info(f"[🌟] splendid, {routing_activation_type:#x} yields {e.rac_code.name}")

                if e.rac_code != RoutingActivationResponseCodes.UnsupportedActivationType:
                    rat_not_unsupported.append(routing_activation_type)

                if e.rac_code == RoutingActivationResponseCodes.UnknownSourceAddress:
                    rat_wrong_source.append(routing_activation_type)

            finally:
                await conn.close()

        if len(rat_not_unsupported) > 0:
            logger.notice(
                f"[💎] Look what RoutingActivationTypes I've found that are not 'unsupported': {', '.join([f'{x:#x}' for x in rat_not_unsupported])}"
            )
        else:
            logger.notice("[😿] Darn boi, all RoutingActivationTypes are unsupported!")
        return rat_success, rat_wrong_source

    async def enumerate_target_addresses(  # noqa: PLR0913
        self,
        tgt_hostname: str,
        tgt_port: int,
        correct_rat: int,
        correct_src: int,
        start: int,
        stop: int,
        timeout: None | float = None,
    ) -> None:
        known_targets = []
        unreachable_targets = []
        responsive_targets = []
        search_space = range(start, stop + 1)

        conn = await self.create_DoIP_conn(tgt_hostname, tgt_port, correct_rat, correct_src, 0xAFFE)

        for target_addr in search_space:
            logger.debug(f"[🚧] Attempting connection to {target_addr:#x}")

            conn.target_addr = target_addr
            current_target = f"doip://{tgt_hostname}:{tgt_port}?protocol_version={self.protocol_version}&activation_type={correct_rat:#x}&src_addr={correct_src:#x}&target_addr={target_addr:#x}"

            try:
                req = TesterPresentRequest(suppress_response=False)
                await conn.write_diag_request(req.pdu)

                # If we reach this, the request was not denied due to unknown TargetAddress
                known_targets.append(current_target)
                logger.notice(f"[🥇] HEUREKA: target address {target_addr:#x} is valid! ")
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("3_valid_targets.txt"), "a"
                ) as f:
                    await f.write(f"{current_target}\n")

                logger.info(f"[⏳] Waiting for reply of target {target_addr:#x}")
                # Hardcoded loop to detect potential broadcasts
                while True:
                    pot_broadcast, data = await asyncio.wait_for(
                        self.read_diag_request_custom(conn),
                        TimingAndCommunicationParameters.DiagnosticMessageMessageTimeout / 1000
                        if timeout is None
                        else timeout,
                    )
                    if pot_broadcast is None:
                        break

                    logger.notice(
                        f"[🤑] B-B-B-B-B-B-BROADCAST at TargetAddress {target_addr:#x}! Got reply from {pot_broadcast:#x}"
                    )
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("6_unsolicited_replies.txt"), "a"
                    ) as f:
                        await f.write(
                            f"target_addr={target_addr:#x} yielded reply from {pot_broadcast:#x}; could also be late answer triggered by previous address!\n"
                        )

                resp = TesterPresentResponse.parse_static(data)
                logger.notice(f"[🥳] It cannot get nicer: {target_addr:#x} responded: {resp}")
                responsive_targets.append(current_target)
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("4_responsive_targets.txt"), "a"
                ) as f:
                    await f.write(f"{current_target}\n")
                if self.db_handler is not None:
                    await self.db_handler.insert_discovery_result(current_target)

            except DoIPNegativeAckError as e:
                if e.nack_code == DiagnosticMessageNegativeAckCodes.UnknownTargetAddress:
                    logger.info(f"[🫥] {target_addr:#x} is an unknown target address")
                    continue
                elif e.nack_code == DiagnosticMessageNegativeAckCodes.TargetUnreachable:
                    logger.info(f"[💤] {target_addr:#x} is (currently?) unreachable")
                    unreachable_targets.append(current_target)
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("5_unreachable_targets.txt"), "a"
                    ) as f:
                        await f.write(f"{current_target}\n")
                    continue
                else:
                    logger.warning(
                        f"[🤷] {target_addr:#x} is behaving strangely: {e.nack_code.name}"
                    )
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("7_targets_with_errors.txt"), "a"
                    ) as f:
                        await f.write(f"{target_addr:#x}: {e.nack_code.name}\n")
                    continue

            except TimeoutError:  # This triggers when DoIP ACK but no UDS reply
                logger.info(f"[🙊] Presumably no active ECU on target address {target_addr:#x}")
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("5_unresponsive_targets.txt"), "a"
                ) as f:
                    await f.write(f"{current_target}\n")
                continue

            except ConnectionError as e:
                # Whenever this triggers, but sometimes connections are closed not by us
                logger.warn(f"[🫦] Sexy, but unexpected: {target_addr:#x} triggered {e!r}")
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("7_targets_with_errors.txt"), "a"
                ) as f:
                    await f.write(f"{target_addr:#x}: {e}\n")
                # Re-establish DoIP connection
                await conn.close()
                conn = await self.create_DoIP_conn(
                    tgt_hostname, tgt_port, correct_rat, correct_src, 0xAFFE
                )
                continue

        await conn.close()

        logger.notice(
            f"[⚔️] It's dangerous to test alone, take one of these {len(known_targets)} known targets:"
        )
        for item in known_targets:
            logger.notice(item)

        logger.notice(
            f"[❓] Those {len(unreachable_targets)} targets were unreachable by the gateway (could be just temporary):"
        )
        for item in unreachable_targets:
            logger.notice(item)

        logger.notice(
            f"[💰] For even more profit, try one of the {len(responsive_targets)} targets that actually responded:"
        )
        for item in responsive_targets:
            logger.notice(item)

        logger.notice(
            f"[🧭] Check out the content of the log files at {self.artifacts_dir} as well!"
        )

    async def create_DoIP_conn(  # noqa: PLR0913
        self,
        hostname: str,
        port: int,
        routing_activation_type: int,
        src_addr: int,
        target_addr: int,
    ) -> DoIPConnection:
        while True:
            try:
                conn = await DoIPConnection.connect(
                    hostname,
                    port,
                    src_addr,
                    target_addr,
                    so_linger=True,  # Ensure that connections do not remain in TIME_WAIT
                    protocol_version=self.protocol_version,
                )
                logger.info("[📫] Sending RoutingActivationRequest")
                await conn.write_routing_activation_request(
                    RoutingActivationRequestTypes(routing_activation_type)
                )
            except Exception as e:  # TODO this probably is too broad
                logger.warning(
                    f"[🫨] Got me some good errors when it should be working (dis an infinite loop): {e!r}"
                )
                continue
            return conn

    async def read_diag_request_custom(self, conn: DoIPConnection) -> tuple[int | None, bytes]:
        while True:
            hdr, payload = await conn.read_frame()
            if not isinstance(payload, DiagnosticMessage):
                logger.warning(f"[🧨] Unexpected DoIP message: {hdr} {payload}")
                return None, b""
            if payload.SourceAddress != conn.target_addr:
                return payload.SourceAddress, payload.UserData
            if payload.TargetAddress != conn.src_addr:
                logger.warning(
                    f"[🤌] You talking to me?! Unexpected DoIP target address: {payload.TargetAddress:#04x}"
                )
                continue
            return None, payload.UserData

    async def enumerate_source_addresses(
        self,
        tgt_hostname: str,
        tgt_port: int,
        valid_routing_activation_types: Iterable[int],
    ) -> list[str]:
        known_sourceAddresses: list[int] = []
        denied_sourceAddresses: list[int] = []
        targets: list[str] = []
        for routing_activation_type, source_address in product(
            valid_routing_activation_types, range(0x0000, 0x10000)
        ):
            try:
                conn = await DoIPConnection.connect(
                    tgt_hostname,
                    tgt_port,
                    source_address,
                    0xAFFE,
                    protocol_version=self.protocol_version,
                )
            except OSError as e:
                logger.error(f"[🚨] Mr. Stark I don't feel so good: {e!r}")
                return []

            try:
                await conn.write_routing_activation_request(routing_activation_type)
            except DoIPRoutingActivationDeniedError as e:
                logger.info(f"[🌟] splendid, {source_address:#x} yields {e.rac_code.name}")

                if e.rac_code != RoutingActivationResponseCodes.UnknownSourceAddress:
                    denied_sourceAddresses.append(source_address)
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("2_denied_src_addresses.txt"), "a"
                    ) as f:
                        await f.write(
                            f"activation_type={routing_activation_type:#x},src_addr={source_address:#x}: {e.rac_code.name}\n"
                        )

                continue

            finally:
                await conn.close()

            logger.notice(
                f"[🤯] Holy moly, it actually worked for activation_type {routing_activation_type:#x} and src_addr {source_address:#x}!!!"
            )
            known_sourceAddresses.append(source_address)
            targets.append(
                f"doip://{tgt_hostname}:{tgt_port}?protocol_version={self.protocol_version}&activation_type={routing_activation_type:#x}&src_addr={source_address:#x}"
            )
            async with aiofiles.open(
                self.artifacts_dir.joinpath("1_valid_src_addresses.txt"), "a"
            ) as f:
                await f.write(f"{targets[-1]}\n")

        # Print valid SourceAddresses and suitable target string for config
        if len(denied_sourceAddresses) > 0:
            logger.notice(
                f"[💀] Look what SourceAddresses got denied: {', '.join([f'{x:#x}' for x in denied_sourceAddresses])}"
            )
        if len(targets) > 0:
            logger.notice(
                f"[💎] Look what valid SourceAddresses I've found: {', '.join([f'{x:#x}' for x in known_sourceAddresses])}"
            )
            logger.notice("[⚔️] It's dangerous to test alone, take one of these:")
            for item in targets:
                logger.notice(item)
        else:
            logger.notice("[😭] Did not find any valid source address!")

        return targets

    async def run_udp_discovery(self) -> list[tuple[str, int]]:
        all_ips = []
        found = []

        for iface in psutil.net_if_addrs().values():
            for ip in iface:
                # we only work with broadcastable IPv4
                if ip.family != socket.AF_INET or ip.broadcast is None:
                    continue
                all_ips.append(ip)

        for ip in all_ips:
            logger.info(f"[💌] Sending DoIP VehicleIdentificationRequest to {ip.broadcast}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setblocking(False)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.bind((ip.address, 0))
            loop = asyncio.get_running_loop()

            hdr = GenericHeader(0xFF, PayloadTypes.VehicleIdentificationRequestMessage, 0x00)
            await loop.sock_sendto(sock, hdr.pack(), (ip.broadcast, 13400))
            try:
                while True:
                    data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), 2)
                    info = VehicleAnnouncementMessage.unpack(data[8:])
                    logger.notice(f"[💝]: {addr} responded: {info}")
                    found.append(addr)
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
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("0_valid_hosts.txt"), "a"
                ) as f:
                    await f.write(f"{url}\n")
        else:
            logger.notice(
                "[👸] Your princess is in another castle: no DoIP endpoints here it seems..."
            )

        return found
