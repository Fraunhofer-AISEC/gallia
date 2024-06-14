# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import random
import sys
from argparse import Namespace

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds.core.client import UDSRequestConfig
from gallia.services.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import IllegalResponse
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.helpers import suggests_identifier_not_supported
from gallia.transports import RawCANTransport, TargetURI
from gallia.utils import auto_int, handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


class PDUFuzzer(UDSScanner):
    """Payload fuzzer"""

    GROUP = "fuzz"
    COMMAND = "pdu"
    SHORT_HELP = "fuzz the UDS pdu of selected services"

    def configure_parser(self) -> None:
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
            help="\n            Service ID to create payload for; defaults to 0x2e WriteDataByIdentifier;\n            currently supported:\n            0x2e WriteDataByIdentifier, 0x31 RoutineControl (startRoutine)\n            ",
        )
        self.parser.add_argument(
            "--max-length", type=auto_int, default=42, help="maximum length of the payload"
        )
        self.parser.add_argument(
            "--min-length", type=auto_int, default=1, help="minimum length of the payload"
        )
        self.parser.add_argument(
            "-i", "--iterations", type=auto_int, default=1, help="number of iterations"
        )
        self.parser.add_argument(
            "--dids", type=auto_int, nargs="*", required=True, help="data identifiers to fuzz"
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
        transport = await RawCANTransport.connect(TargetURI(can_url.geturl()))
        transport.set_filter(can_ids, inv_filter=False)

        try:
            can_msgs: dict[int, bytes] = {}
            logger.debug("Started observe messages task")
            while True:
                try:
                    can_id, msg = await transport.recvfrom(timeout=1)
                    if can_id in can_msgs:
                        if msg != can_msgs[can_id]:
                            logger.result(f"Message for {can_id:03x} changed to {msg.hex()}")
                            can_msgs[can_id] = msg
                    else:
                        can_msgs[can_id] = msg
                        logger.result(f"Observed new message from {can_id:03x}: {msg.hex()}")
                except TimeoutError:
                    continue

        except asyncio.CancelledError:
            logger.debug("Can message observer task cancelled")

    async def main(self, args: Namespace) -> None:
        if args.observe_can_ids:
            recv_task = asyncio.create_task(self.observe_can_messages(args.observe_can_ids, args))
            recv_task.add_done_callback(
                handle_task_error,
                context=set_task_handler_ctx_variable(__name__, "ReceiveTask"),
            )

        logger.info(f"testing sessions {args.sessions}")

        for did in args.dids:
            if args.serviceid == UDSIsoServices.RoutineControl:
                pdu = bytes([args.serviceid, 0x01, did >> 8, did & 0xFF])
            elif args.serviceid == UDSIsoServices.WriteDataByIdentifier:
                pdu = bytes([args.serviceid, did >> 8, did & 0xFF])
            for session in args.sessions:
                logger.notice(f"Switching to session 0x{session:02x}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"Switching to session 0x{session:02x} failed: {resp}")
                    continue

                logger.result(f"Starting scan in session: 0x{session:02x}")
                positive_DIDs = 0
                negative_responses: dict[UDSErrorCodes, int] = {}
                timeout_DIDs = 0
                illegal_resp = 0
                flow_control_miss = 0

                for _ in range(args.iterations):
                    payload = args.prefixed_payload + self.generate_payload(args)
                    try:
                        resp = await self.ecu.send_raw(
                            pdu + payload, config=UDSRequestConfig(tags=["ANALYZE"], max_retry=3)
                        )

                        if isinstance(resp, NegativeResponse):
                            if not suggests_identifier_not_supported(resp):
                                logger.result(f"0x{did:0x}: {resp}")
                            else:
                                logger.info(f"0x{did:0x}: {resp}")
                            if resp.response_code in negative_responses:
                                negative_responses[resp.response_code] += 1
                            else:
                                negative_responses[resp.response_code] = 1
                        else:
                            logger.result(f"0x{did:0x}: {resp}")
                            positive_DIDs += 1

                    except TimeoutError:
                        logger.warning(f"0x{did:0x}: Retries exceeded")
                        timeout_DIDs += 1
                    except IllegalResponse as e:
                        logger.warning(f"{repr(e)}")
                        illegal_resp += 1
                    # Temporary patch: Exception handler is deleted when it goes productive
                    except ConnectionError:
                        logger.warning("isotp flow control frame missing. Reconnecting…")
                        flow_control_miss += 1
                        await self.ecu.reconnect()

                logger.result(f"Scan in session 0x{session:0x} is complete!")

                for k, v in negative_responses.items():
                    logger.result(f"{k.name}: {v}")

                logger.result(f"Positive replies: {positive_DIDs}")

                logger.result(f"Timeouts: {timeout_DIDs}")
                logger.result(f"Illegal replies: {illegal_resp}")
                logger.result(f"Flow control frames missing: {flow_control_miss}")

                logger.info(f"Leaving session 0x{session:02x} via hook")
                await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)

        if args.observe_can_ids:
            recv_task.cancel()
            await recv_task
