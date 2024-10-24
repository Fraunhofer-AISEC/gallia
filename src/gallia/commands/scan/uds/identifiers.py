# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import reprlib
from itertools import product

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, EnumArg, Field, HexBytes, Ranges, Ranges2D
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds.core.client import UDSRequestConfig
from gallia.services.uds.core.constants import RoutineControlSubFuncs, UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import IllegalResponse
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.core.utils import g_repr, service_repr
from gallia.services.uds.helpers import suggests_service_not_supported

logger = get_logger(__name__)


class ScanIdentifiersConfig(UDSScannerConfig):
    sessions: Ranges | None = Field(
        None, description="Set list of sessions to be tested; all if None", metavar="SESSION_ID"
    )
    start: AutoInt = Field(0, description="start scan at this dataIdentifier")
    end: AutoInt = Field(0xFFFF, description="end scan at this dataIdentifier")
    payload: HexBytes | None = Field(
        None, description="Payload which will be appended for each request as hex string"
    )
    service: EnumArg[UDSIsoServices] = Field(
        UDSIsoServices.ReadDataByIdentifier,
        description="Service (ID) to scan; defaults to ReadDataByIdentifier;\ncurrently supported:\n0x27 Security Access;\n0x22 Read Data By Identifier;\n0x2e Write Data By Identifier;\n0x31 Routine Control;\n",
    )
    check_session: int | None = Field(
        None,
        description="Check current session via read DID [for every nth DataIdentifier] and try to recover session; only takes affect if --sessions is given",
        const=1,
    )
    skip: Ranges2D = Field(
        {},
        metavar="SESSION_ID:ID",
        description="The data identifiers to be skipped per session.\nA session specific skip is given by <session_id>:<identifiers>\nwhere <identifiers> is a comma separated list of single ids or id ranges using a dash.\nExamples:\n - 0x01:0xf3\n - 0x10-0x2f\n - 0x01:0xf3,0x10-0x2f\nMultiple session specific skips are separated by space.\nOnly takes affect if --sessions is given.\n",
    )
    skip_not_supported: bool = Field(
        False, description="Stop scanning in session if service seems to be not available"
    )


class ScanIdentifiers(UDSScanner):
    """This scanner scans DataIdentifiers of various
    services. Specific requirements such as for RoutineControl or SecurityAccess
    are considered and implemented in the script.
    """

    CONFIG_TYPE = ScanIdentifiersConfig
    SHORT_HELP = "identifier scan of a UDS service"

    def __init__(self, config: ScanIdentifiersConfig):
        super().__init__(config)
        self.config: ScanIdentifiersConfig = config

    async def main(self) -> None:
        if self.config.sessions is None:
            logger.notice("Performing scan in current session")
            await self.perform_scan()
        else:
            sessions: list[int] = [
                s
                for s in self.config.sessions
                if s not in self.config.skip or self.config.skip[s] is not None
            ]
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(self.config.skip)}")

            for session in sessions:
                logger.notice(f"Switching to session {g_repr(session)}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"Switching to session {g_repr(session)} failed: {resp}")
                    continue

                logger.result(f"Starting scan in session: {g_repr(session)}")

                await self.perform_scan(session)

                logger.result(f"Scan in session {g_repr(session)} is complete!")
                logger.info(f"Leaving session {g_repr(session)} via hook")
                await self.ecu.leave_session(session, sleep=self.config.power_cycle_sleep)

    async def perform_scan(self, session: None | int = None) -> None:
        positive_DIDs = 0
        abnormal_DIDs = 0
        timeout_DIDs = 0
        sub_functions = [0x00]

        if self.config.service == UDSIsoServices.RoutineControl:
            if not self.config.payload:
                logger.warning(
                    "Scanning RoutineControl with empty payload can successfully execute some "
                    + "routines that might have irreversible effects without elevated privileges"
                )

            # Scan all three subfunctions (startRoutine, stopRoutine, requestRoutineResults)
            sub_functions = list(map(int, RoutineControlSubFuncs))

        if self.config.service == UDSIsoServices.SecurityAccess and self.config.end > 0xFF:
            logger.warning(
                "Service 0x27 SecurityAccess only accepts subFunctions (1-byte identifiers); "
                + f"limiting END to {g_repr(0xff)} instead of {g_repr(self.config.end)}"
            )
            self.config.end = 0xFF

        for DID, sub_function in product(
            range(self.config.start, self.config.end + 1), sub_functions
        ):
            if session in self.config.skip and (
                (session_skip := self.config.skip[session]) is None or DID in session_skip
            ):
                logger.info(f"{g_repr(DID)}: skipped")
                continue

            if (
                session is not None
                and self.config.check_session
                and (DID % self.config.check_session == 0)
            ):
                # Check session and try to recover from wrong session (max 3 times), else skip session
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current DID was {g_repr(DID)}"
                    )
                    break

            if self.config.service == UDSIsoServices.SecurityAccess:
                if DID & 128:
                    logger.info(
                        "Keep in mind that you set the SuppressResponse Bit (8th bit): "
                        + f"{g_repr(DID)} = 0b{DID:b}"
                    )
                pdu = bytes([self.config.service, DID])

            elif self.config.service == UDSIsoServices.RoutineControl:
                pdu = bytes(
                    [self.config.service, sub_function, DID >> 8, DID & 0xFF]
                )  # Needs extra byte for sub function
            else:
                # DefaultBehavior, e.g. for ReadDataByIdentifier/WriteDataByIdentifier
                pdu = bytes([self.config.service, DID >> 8, DID & 0xFF])

            if self.config.payload:
                pdu += self.config.payload

            try:
                resp = await self.ecu.send_raw(
                    pdu, config=UDSRequestConfig(tags=["ANALYZE"], max_retry=3)
                )
            except TimeoutError:
                logger.result(f"{g_repr(DID)}: Retries exceeded")
                timeout_DIDs += 1
                continue
            except IllegalResponse as e:
                logger.warning(g_repr(e))
                continue

            if isinstance(resp, NegativeResponse):
                if suggests_service_not_supported(resp):
                    logger.info(
                        f"{g_repr(DID)}: {resp}; does session {g_repr(session)} support service {service_repr(self.config.service)}?"
                    )

                    if self.config.skip_not_supported:
                        break

                # RequestOutOfRange is a common reply for invalid/unknown DataIdentifiers
                # SubFunctionNotSupported is also not worth to be logged as result
                elif resp.response_code in (
                    UDSErrorCodes.requestOutOfRange,
                    UDSErrorCodes.subFunctionNotSupported,
                ):
                    logger.info(f"{g_repr(DID)}: {resp}")
                else:
                    logger.result(f"{g_repr(DID)}: {resp}")
                    abnormal_DIDs += 1
            else:
                logger.result(f"{g_repr(DID)}: {resp}")
                positive_DIDs += 1

        logger.result(f"Positive replies: {positive_DIDs}")
        logger.result(f"Abnormal replies: {abnormal_DIDs}")
        logger.result(f"Timeouts: {timeout_DIDs}")
