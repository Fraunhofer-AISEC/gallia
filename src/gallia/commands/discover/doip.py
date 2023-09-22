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
from gallia.services.uds.core.service import (
    DiagnosticSessionControlRequest,
    DiagnosticSessionControlResponse,
)
from gallia.transports.doip import (
    DiagnosticMessage,
    DiagnosticMessageNegativeAckCodes,
    DoIPConnection,
    RoutingActivationRequestTypes,
    RoutingActivationResponseCodes,
    TimingAndCommunicationParameters,
)


class DoIPDiscoverer(AsyncScript):
    """This script scans for active DoIP endpoints and automatically enumerates allowed
    RoutingActivationTypes and known SourceAddresses. Once valid endpoints are acquired,
    the script continues to discover valid TargetAddresses that are accepted and respond
    to UDS DiagnosticSessionControl requests."""

    GROUP = "discover"
    COMMAND = "doip"
    SHORT_HELP = "zero-knowledge DoIP enumeration scanner"
    HAS_ARTIFACTS_DIR = True

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--start",
            metavar="INT",
            type=lambda x: int(x, 0),
            default=0x00,
            help="set start address of TargetAddress search range",
        )
        self.parser.add_argument(
            "--stop",
            metavar="INT",
            type=lambda x: int(x, 0),
            default=0xFFFF,
            help="set stop address of TargetAddress search range",
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
        self.logger.notice("[👋] Welcome to @realDoIP-Discovery powered by MoarMemes…")

        target = urlparse(args.target) if args.target is not None else None
        if target is not None and target.scheme != "doip":
            self.logger.error("[🫣] --target must be doip://…")
            return 2

        # Discover Hostname and Port
        tgt_hostname: str
        tgt_port: int
        if (
            target is not None
            and target.hostname is not None
            and target.port is not None
        ):
            self.logger.notice(
                "[📋] Skipping host/port discovery because given by --target"
            )
            tgt_hostname = target.hostname
            tgt_port = target.port
        else:
            self.logger.notice("[🔍] Discovering Host and Port via UDP Broadcast")

            hosts = await self.run_udp_discovery()

            if len(hosts) != 1:
                self.logger.error(
                    "[🍃] Can only continue with a single DoIP host! Give me a --target!"
                )
                return 11

            tgt_hostname, tgt_port = hosts[0]

        # Find correct RoutingActivationType
        rat_success: list[int] = []
        rat_wrong_source: list[int] = []
        if target is not None and "activation_type" in parse_qs(target.query):
            self.logger.notice(
                "[📋] Skipping RoutingActivationType discovery because given by --target"
            )
            rat_success = [int(parse_qs(target.query)["activation_type"][0], 0)]
        else:
            self.logger.notice("[🔍] Enumerating all RoutingActivationTypes")

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
            self.logger.error(
                "[🥾] Damn son, didn't find a single routing activation type with unknown source?! OUTTA HERE!"
            )
            return 10

        # Discovering correct source address for suitable RoutingActivationRequests
        if target is not None and "src_addr" in parse_qs(target.query):
            self.logger.notice(
                "[📋] Skipping SourceAddress discovery because given by --target"
            )
            targets = [
                f"doip://{tgt_hostname}:{tgt_port}?activation_type={rat:#x}&src_addr={parse_qs(target.query)['src_addr'][0]}"
                for rat in rat_success
            ]

        else:
            self.logger.notice("[🔍] Enumerating all SourceAddresses")
            targets = await self.enumerate_source_addresses(
                tgt_hostname,
                tgt_port,
                chain(rat_success, rat_wrong_source),
            )

        if len(targets) != 1:
            self.logger.error(
                f"[💣] I found {len(targets)} valid RoutingActivationType/SourceAddress combos, but can only continue with exactly one; choose your weapon with --target!"
            )
            return 20

        # Enumerate valid TargetAddresses
        if target is not None and "target_addr" in parse_qs(target.query):
            self.logger.error(
                "[😵] Why do you give me a target_addr in --target? Am I useless to you??? GOODBYE!"
            )
            return 3

        self.logger.notice(
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

        self.logger.notice("[🛩️] All done, thanks for flying with us!")
        return 0

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
                )
            except OSError as e:
                self.logger.error(f"[🚨] Mr. Stark I don't feel so good: {e}")
                return rat_success, rat_wrong_source

            try:
                await conn.write_routing_activation_request(routing_activation_type)
                rat_success.append(routing_activation_type)
                self.logger.info(
                    f"[🤯] Holy moly, it actually worked for activation_type {routing_activation_type:#x} and src_addr {src_addr:#x}!!!"
                )
            except ConnectionAbortedError as e:
                # Let's utilize Gallia's excellent error handling
                error = RoutingActivationResponseCodes[str(e).split(" ")[-1]]
                self.logger.info(
                    f"[🌟] splendid, {routing_activation_type:#x} yields a {error.name}"
                )

                if error != RoutingActivationResponseCodes.UnsupportedActivationType:
                    rat_not_unsupported.append(routing_activation_type)

                if error == RoutingActivationResponseCodes.UnknownSourceAddress:
                    rat_wrong_source.append(routing_activation_type)

            finally:
                await conn.close()

        self.logger.notice(
            f"[💎] Look what RoutingActivationTypes I've found that are not 'unsupported': {', '.join([f'{x:#x}' for x in rat_not_unsupported])}"
        )
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
        responsive_targets = []
        search_space = range(start, stop + 1)

        conn = await self.create_DoIP_conn(
            tgt_hostname, tgt_port, correct_rat, correct_src, 0xAFFE
        )

        for target_addr in search_space:
            self.logger.debug(f"[🚧] Attempting connection to {target_addr:#x}")

            conn.target_addr = target_addr

            try:
                req = DiagnosticSessionControlRequest(0x01)
                await conn.write_diag_request(req.pdu)

                # If we reach this, the request was not denied due to unknown TargetAddress
                known_targets.append(
                    f"doip://{tgt_hostname}:{tgt_port}?activation_type={correct_rat:#x}&src_addr={correct_src:#x}&target_addr={target_addr:#x}"
                )
                self.logger.notice(
                    f"[🥇] HEUREKA: target address {target_addr:#x} is valid! "
                )
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("3_valid_targets.txt"), "a"
                ) as f:
                    await f.write(f"{known_targets[-1]}\n")

                self.logger.info(f"[⏳] Waiting for reply of target {target_addr:#x}")
                # Hardcoded loop to detect potential broadcasts
                while True:
                    pot_broadcast, data = await asyncio.wait_for(
                        self.read_diag_request_custom(conn),
                        TimingAndCommunicationParameters.DiagnosticMessageMessageTimeout
                        / 1000
                        if timeout is None
                        else timeout,
                    )
                    if pot_broadcast is None:
                        break

                    self.logger.notice(
                        f"[🤑] B-B-B-B-B-B-BROADCAST at TargetAddress {target_addr:#x}! Got reply from {pot_broadcast:#x}"
                    )
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("6_unsolicited_replies.txt"), "a"
                    ) as f:
                        await f.write(
                            f"target_addr={target_addr:#x} yielded reply from {pot_broadcast:#x}; could also be late answer triggered by previous address!\n"
                        )

                resp = DiagnosticSessionControlResponse.parse_static(data)
                self.logger.notice(
                    f"[🥳] It cannot get nicer: {target_addr:#x} responded: {resp}"
                )
                responsive_targets.append(known_targets[-1])
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("4_responsive_targets.txt"), "a"
                ) as f:
                    await f.write(f"{known_targets[-1]}\n")

            except (
                BrokenPipeError
            ) as e:  # Though it's obvious: this error is raised when a DoIP NACK is received
                error = DiagnosticMessageNegativeAckCodes(int(str(e).split(" ")[-1], 0))
                if error == DiagnosticMessageNegativeAckCodes.UnknownTargetAddress:
                    self.logger.info(
                        f"[🫥] {target_addr:#x} is an unknown target address"
                    )
                    continue
                else:
                    self.logger.warning(
                        f"[🤷] {target_addr:#x} is behaving strangely: {error.name}"
                    )
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("7_targets_with_errors.txt"), "a"
                    ) as f:
                        await f.write(f"{target_addr:#x}: {error.name}\n")
                    continue

            except (
                asyncio.TimeoutError
            ):  # This triggers when no ACK is received, or ACK but no UDS reply
                self.logger.info(
                    f"[🙊] Presumably no active ECU on target address {target_addr:#x}"
                )
                async with aiofiles.open(
                    self.artifacts_dir.joinpath("5_unresponsive_targets.txt"), "a"
                ) as f:
                    await f.write(f"{known_targets[-1]}\n")
                continue

            except (ConnectionError, ConnectionResetError) as e:
                # Whenever this triggers, but sometimes connections are closed not by us
                self.logger.warn(
                    f"[🫦] Sexy, but unexpected: {target_addr:#x} triggered {e}"
                )
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

        self.logger.notice(
            "[⚔️] It's dangerous to test alone, take one of these known targets:"
        )
        for item in known_targets:
            self.logger.notice(item)

        self.logger.notice(
            "[💰] For even more profit, try targets that actually responded:"
        )
        for item in responsive_targets:
            self.logger.notice(item)

        self.logger.notice(
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
                )
                self.logger.info("[📫] Sending RoutingActivationRequest")
                await conn.write_routing_activation_request(
                    RoutingActivationRequestTypes(routing_activation_type)
                )
            except Exception as e:  # TODO this probably is too broad
                self.logger.warning(
                    f"[🫨] Got me some good errors when it should be working (dis an infinite loop): {e}"
                )
                continue
            return conn

    async def read_diag_request_custom(
        self, conn: DoIPConnection
    ) -> tuple[int | None, bytes]:
        while True:
            hdr, payload = await conn.read_frame()
            if not isinstance(payload, DiagnosticMessage):
                raise BrokenPipeError(f"[🧨] Unexpected DoIP message: {hdr} {payload}")
            if payload.SourceAddress != conn.target_addr:
                return payload.SourceAddress, payload.UserData
            if payload.TargetAddress != conn.src_addr:
                self.logger.warning(
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
                )
            except OSError as e:
                self.logger.error(f"[🚨] Mr. Stark I don't feel so good: {e}")
                return []

            try:
                await conn.write_routing_activation_request(routing_activation_type)
            except ConnectionAbortedError as e:
                # Let's utilize Gallia's excellent error handling
                error = RoutingActivationResponseCodes[str(e).split(" ")[-1]]
                self.logger.info(
                    f"[🌟] splendid, {source_address:#x} yields a {error.name}"
                )

                if error != RoutingActivationResponseCodes.UnknownSourceAddress:
                    denied_sourceAddresses.append(source_address)
                    async with aiofiles.open(
                        self.artifacts_dir.joinpath("2_denied_src_addresses.txt"), "a"
                    ) as f:
                        await f.write(
                            f"activation_type={routing_activation_type:#x},src_addr={source_address:#x}: {error.name}\n"
                        )

                continue

            finally:
                await conn.close()

            self.logger.info(
                f"[🤯] Holy moly, it actually worked for activation_type {routing_activation_type:#x} and src_addr {source_address:#x}!!!"
            )
            known_sourceAddresses.append(source_address)
            targets.append(
                f"doip://{tgt_hostname}:{tgt_port}?activation_type={routing_activation_type:#x}&src_addr={source_address:#x}"
            )
            async with aiofiles.open(
                self.artifacts_dir.joinpath("1_valid_src_addresses.txt"), "a"
            ) as f:
                await f.write(f"{targets[-1]}\n")

        # Print valid SourceAddresses and suitable target string for config
        self.logger.notice(
            f"[💀] Look what SourceAddresses got denied: {', '.join([f'{x:#x}' for x in denied_sourceAddresses])}"
        )
        self.logger.notice(
            f"[💎] Look what valid SourceAddresses I've found: {', '.join([f'{x:#x}' for x in known_sourceAddresses])}"
        )
        self.logger.notice("[⚔️] It's dangerous to test alone, take one of these:")
        for item in targets:
            self.logger.notice(item)
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
            self.logger.info(
                f"[💌] Sending DoIP VehicleIdentificationRequest to {ip.broadcast}"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(2)
            sock.bind((ip.address, 0))

            sock.sendto(b"\xff\x00\x00\x01\x00\x00\x00\x00", (ip.broadcast, 13400))
            try:
                data, addr = sock.recvfrom(1024)
            except TimeoutError:
                self.logger.info("[💔] no response")
                continue
            finally:
                sock.close()

            # Hardcoded slices
            vin = data[8 : 8 + 17]
            target_addr = int.from_bytes(data[25:27], "big")
            self.logger.notice(
                f"[💝]: {addr} responded with VIN {vin.decode('ascii')} and target_addr {target_addr:#x}"
            )
            found.append(addr)

        self.logger.notice("[💎] Look what valid hosts I've found:")
        for item in found:
            url = f"doip://{item[0]}:{item[1]}"
            self.logger.notice(url)
            async with aiofiles.open(
                self.artifacts_dir.joinpath("0_valid_hosts.txt"), "a"
            ) as f:
                await f.write(f"{url}\n")

        return found
