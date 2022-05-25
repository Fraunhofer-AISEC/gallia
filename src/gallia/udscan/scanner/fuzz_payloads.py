# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import random
from argparse import Namespace

from gallia.transports.base import TargetURI
from gallia.transports.can import RawCANTransport
from gallia.uds.core.client import UDSErrorCodes, UDSRequestConfig
from gallia.uds.core.exception import IllegalResponse
from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.uds.helpers import suggests_identifier_not_supported
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int
from gallia.uds.core.constants import UDSIsoServices


class FuzzPayloads(UDSScanner):
    def __init__(self) -> None:
        super().__init__()
        self.can_recv_event = asyncio.Event()

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            type=auto_int,
            default=[1],
            nargs="*",
            help="Set list of sessions to be tested; 0x01 if None",
        )
        self.parser.add_argument(
            "--serviceid",
            type=auto_int,
            default=0x2E,
            choices=[0x2E, 0x31],
            help="""
            Service ID to create payload for; defaults to 0x2e WriteDataByIdentifier;
            currently supported:
            0x2e WriteDataByIdentifier, 0x31 RoutineControl (startRoutine)
            """,
        )
        self.parser.add_argument(
            "--max-length",
            type=auto_int,
            default=42,
            help="maximum length of the payload",
        )
        self.parser.add_argument(
            "--min-length",
            type=auto_int,
            default=1,
            help="minimum length of the payload",
        )
        self.parser.add_argument(
            "-i",
            "--iterations",
            type=auto_int,
            default=1,
            help="number of iterations",
        )
        self.parser.add_argument(
            "--dids",
            type=auto_int,
            nargs="*",
            required=True,
            help="data identifiers to fuzz",
        )
        self.parser.add_argument(
            "--prefixed-payload",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="static payload, which precedes the fuzzed payload",
        )
        self.parser.add_argument(
            "--observe-can-ids",
            type=auto_int,
            default=[],
            nargs="*",
            help="can ids to observe while fuzzing",
        )

    def generate_payload(self, args: Namespace) -> bytes:
        return random.randbytes(random.randint(args.min_length, args.max_length))

    async def observe_can_messages(self, can_ids: list[int], args: Namespace) -> None:

        can_url = args.target.url._replace(scheme=RawCANTransport.SCHEME)
        transport = RawCANTransport(TargetURI(can_url.geturl()))
        await transport.connect()
        transport.set_filter(can_ids, inv_filter=False)

        self.can_recv_event.set()

        try:
            can_msgs: dict[int, bytes] = {}
            self.logger.log_debug("Started observe messages task")
            while True:
                try:
                    can_id, msg = await transport.recvfrom(timeout=1)
                    if can_id in can_msgs:
                        if msg != can_msgs[can_id]:
                            self.logger.log_summary(
                                f"Message for {can_id:03x} changed to {msg.hex()}"
                            )
                            can_msgs[can_id] = msg
                    else:
                        can_msgs[can_id] = msg
                        self.logger.log_summary(
                            f"Observed new message from {can_id:03x}: {msg.hex()}"
                        )
                except asyncio.TimeoutError:
                    continue

        except asyncio.CancelledError:
            self.logger.log_debug("Can message observer task cancelled")

    async def main(self, args: Namespace) -> None:
        if args.observe_can_ids:
            recv_task = asyncio.create_task(
                self.observe_can_messages(args.observe_can_ids, args)
            )

        self.logger.log_info(f"testing sessions {args.sessions}")

        for did in args.dids:
            if args.serviceid == UDSIsoServices.RoutineControl:
                pdu = bytes([args.serviceid, 0x01, did >> 8, did & 0xFF])
            elif args.serviceid == UDSIsoServices.WriteDataByIdentifier:
                pdu = bytes([args.serviceid, did >> 8, did & 0xFF])
            for session in args.sessions:
                self.logger.log_notice(f"Switching to session 0x{session:02x}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    self.logger.log_warning(
                        f"Switching to session 0x{session:02x} failed: {resp}"
                    )
                    continue

                self.logger.log_summary(f"Starting scan in session: 0x{session:02x}")
                positive_DIDs = 0
                negative_responses: dict[UDSErrorCodes, int] = {}
                timeout_DIDs = 0
                illegal_resp = 0
                flow_control_miss = 0

                for _ in range(args.iterations):
                    payload = args.prefixed_payload + self.generate_payload(args)
                    try:
                        resp = await self.ecu.send_raw(
                            pdu + payload,
                            config=UDSRequestConfig(tags=["ANALYZE"], max_retry=3),
                        )

                        if isinstance(resp, NegativeResponse):
                            if not suggests_identifier_not_supported(resp):
                                self.logger.log_summary(f"0x{did:0x}: {resp}")

                            else:
                                self.logger.log_info(f"0x{did:0x}: {resp}")
                            if resp.response_code in negative_responses:
                                negative_responses[resp.response_code] += 1
                            else:
                                negative_responses[resp.response_code] = 1
                        else:
                            self.logger.log_summary(f"0x{did:0x}: {resp}")
                            positive_DIDs += 1

                    except asyncio.TimeoutError:
                        self.logger.log_warning(f"0x{did :0x}: Retries exceeded")
                        timeout_DIDs += 1
                    except IllegalResponse as e:
                        self.logger.log_warning(f"{repr(e)}")
                        illegal_resp += 1
                    # Temporary patch: Exception handler is deleted when it goes productive
                    except BrokenPipeError:
                        self.logger.log_warning(
                            "isotp flow control frame missing. Reconnecting…"
                        )
                        flow_control_miss += 1
                        await self.ecu.reconnect()

                self.logger.log_summary(f"Scan in session 0x{session:0x} is complete!")

                for k, v in negative_responses.items():
                    self.logger.log_summary(f"{k.name}: {v}")

                self.logger.log_summary(f"Positive replies: {positive_DIDs}")

                self.logger.log_summary(f"Timeouts: {timeout_DIDs}")
                self.logger.log_summary(f"Illegal replies: {illegal_resp}")
                self.logger.log_summary(
                    f"Flow control frames missing: {flow_control_miss}"
                )

                self.logger.log_info(f"Leaving session 0x{session:02x} via hook")
                await self.ecu.leave_session(session)

        if args.observe_can_ids:
            recv_task.cancel()
            await recv_task
