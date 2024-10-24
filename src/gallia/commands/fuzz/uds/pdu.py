# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import random
import sys
from typing import Literal

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, AutoLiteral, Field, HexBytes, Ranges
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.client import UDSRequestConfig
from gallia.services.uds.core.constants import UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import IllegalResponse
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.helpers import suggests_identifier_not_supported
from gallia.transports import RawCANTransport, TargetURI
from gallia.utils import handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


class PDUFuzzerConfig(UDSScannerConfig):
    sessions: Ranges = Field([1], description="Set list of sessions to be tested; 0x01 if None")
    service: AutoLiteral[
        Literal[UDSIsoServices.WriteDataByIdentifier, UDSIsoServices.RoutineControl]
    ] = Field(
        UDSIsoServices.WriteDataByIdentifier,
        description="Service ID to create payload for; defaults to 0x2e WriteDataByIdentifier;\ncurrently supported:\n0x2e WriteDataByIdentifier, 0x31 RoutineControl (startRoutine)\n",
    )
    max_length: AutoInt = Field(42, description="maximum length of the payload")
    min_length: AutoInt = Field(1, description="minimum length of the payload")
    iterations: AutoInt = Field(1, description="number of iterations", short="i")
    dids: Ranges = Field(description="data identifiers to fuzz")
    prefixed_payload: HexBytes = Field(
        b"", description="static payload, which precedes the fuzzed payload", metavar="HEXSTRING"
    )
    observe_can_ids: Ranges = Field([], description="can ids to observe while fuzzing")


class PDUFuzzer(UDSScanner):
    """Payload fuzzer"""

    CONFIG_TYPE = PDUFuzzerConfig
    SHORT_HELP = "fuzz the UDS pdu of selected services"

    def __init__(self, config: PDUFuzzerConfig):
        super().__init__(config)
        self.config: PDUFuzzerConfig = config

    def generate_payload(self) -> bytes:
        return random.randbytes(random.randint(self.config.min_length, self.config.max_length))

    async def observe_can_messages(self, can_ids: list[int]) -> None:
        can_url = self.config.target.url._replace(scheme=RawCANTransport.SCHEME)
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

    async def main(self) -> None:
        if len(self.config.observe_can_ids) > 0:
            recv_task = asyncio.create_task(self.observe_can_messages(self.config.observe_can_ids))
            recv_task.add_done_callback(
                handle_task_error,
                context=set_task_handler_ctx_variable(__name__, "ReceiveTask"),
            )

        logger.info(f"testing sessions {self.config.sessions}")

        for did in self.config.dids:
            if self.config.service == UDSIsoServices.RoutineControl:
                pdu = bytes([self.config.service.value, 0x01, did >> 8, did & 0xFF])
            elif self.config.service == UDSIsoServices.WriteDataByIdentifier:
                pdu = bytes([self.config.service.value, did >> 8, did & 0xFF])
            for session in self.config.sessions:
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

                for _ in range(self.config.iterations):
                    payload = self.config.prefixed_payload + self.generate_payload()
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
                await self.ecu.leave_session(session, sleep=self.config.power_cycle_sleep)

        if len(self.config.observe_can_ids) > 0:
            recv_task.cancel()
            await recv_task
