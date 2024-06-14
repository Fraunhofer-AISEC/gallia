# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import binascii
import reprlib
from argparse import Namespace
from itertools import product

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds.core.client import UDSRequestConfig
from gallia.services.uds.core.constants import RoutineControlSubFuncs, UDSErrorCodes, UDSIsoServices
from gallia.services.uds.core.exception import IllegalResponse
from gallia.services.uds.core.service import NegativeResponse, UDSResponse
from gallia.services.uds.core.utils import g_repr, service_repr
from gallia.services.uds.helpers import suggests_service_not_supported
from gallia.utils import ParseSkips, auto_int

logger = get_logger(__name__)


class ScanIdentifiers(UDSScanner):
    """This scanner scans DataIdentifiers of various
    services. Specific requirements such as for RoutineControl or SecurityAccess
    are considered and implemented in the script.
    """

    COMMAND = "identifiers"
    SHORT_HELP = "identifier scan of a UDS service"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            type=auto_int,
            nargs="*",
            help="Set list of sessions to be tested; all if None",
        )
        self.parser.add_argument(
            "--start",
            type=auto_int,
            default=0,
            help="start scan at this dataIdentifier (default: 0x%(default)x)",
        )
        self.parser.add_argument(
            "--end",
            type=auto_int,
            default=0xFFFF,
            help="end scan at this dataIdentifier (default: 0x%(default)x)",
        )
        self.parser.add_argument(
            "--payload",
            default=None,
            type=binascii.unhexlify,
            help="Payload which will be appended for each request as hex string",
        )
        self.parser.add_argument(
            "--sid",
            type=auto_int,
            default=0x22,
            help="\n            Service ID to scan; defaults to ReadDataByIdentifier (default: 0x%(default)x);\n            currently supported:\n            0x27 Security Access;\n            0x22 Read Data By Identifier;\n            0x2e Write Data By Identifier;\n            0x31 Routine Control;\n            ",
        )
        self.parser.add_argument(
            "--check-session",
            nargs="?",
            const=1,
            type=int,
            help="Check current session via read DID [for every nth DataIdentifier] and try to recover session; only takes affect if --sessions is given",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="\n                 The data identifiers to be skipped per session.\n                 A session specific skip is given by <session_id>:<identifiers>\n                 where <identifiers> is a comma separated list of single ids or id ranges using a dash.\n                 Examples:\n                  - 0x01:0xf3\n                  - 0x10-0x2f\n                  - 0x01:0xf3,0x10-0x2f\n                 Multiple session specific skips are separated by space.\n                 Only takes affect if --sessions is given.\n                 ",
        )
        self.parser.add_argument(
            "--skip-not-supported",
            action="store_true",
            help="Stop scanning in session if service seems to be not available",
        )

    async def main(self, args: Namespace) -> None:
        if args.sessions is None:
            logger.notice("Performing scan in current session")
            await self.perform_scan(args)
        else:
            sessions: list[int] = [
                s for s in args.sessions if s not in args.skip or args.skip[s] is not None
            ]
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(args.skip)}")

            for session in sessions:
                logger.notice(f"Switching to session {g_repr(session)}")
                resp: UDSResponse = await self.ecu.set_session(session)
                if isinstance(resp, NegativeResponse):
                    logger.warning(f"Switching to session {g_repr(session)} failed: {resp}")
                    continue

                logger.result(f"Starting scan in session: {g_repr(session)}")

                await self.perform_scan(args, session)

                logger.result(f"Scan in session {g_repr(session)} is complete!")
                logger.info(f"Leaving session {g_repr(session)} via hook")
                await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)

    async def perform_scan(self, args: Namespace, session: None | int = None) -> None:
        positive_DIDs = 0
        abnormal_DIDs = 0
        timeout_DIDs = 0
        sub_functions = [0x00]

        if args.sid == UDSIsoServices.RoutineControl:
            if not args.payload:
                logger.warning(
                    "Scanning RoutineControl with empty payload can successfully execute some "
                    + "routines that might have irreversible effects without elevated privileges"
                )

            # Scan all three subfunctions (startRoutine, stopRoutine, requestRoutineResults)
            sub_functions = list(map(int, RoutineControlSubFuncs))

        if args.sid == UDSIsoServices.SecurityAccess and args.end > 0xFF:
            logger.warning(
                "Service 0x27 SecurityAccess only accepts subFunctions (1-byte identifiers); "
                + f"limiting END to {g_repr(0xff)} instead of {g_repr(args.end)}"
            )
            args.end = 0xFF

        for DID, sub_function in product(range(args.start, args.end + 1), sub_functions):
            if session in args.skip and DID in args.skip[session]:
                logger.info(f"{g_repr(DID)}: skipped")
                continue

            if session is not None and args.check_session and (DID % args.check_session == 0):
                # Check session and try to recover from wrong session (max 3 times), else skip session
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current DID was {g_repr(DID)}"
                    )
                    break

            if args.sid == UDSIsoServices.SecurityAccess:
                if DID & 128:
                    logger.info(
                        "Keep in mind that you set the SuppressResponse Bit (8th bit): "
                        + f"{g_repr(DID)} = 0b{DID:b}"
                    )
                pdu = bytes([args.sid, DID])

            elif args.sid == UDSIsoServices.RoutineControl:
                pdu = bytes(
                    [args.sid, sub_function, DID >> 8, DID & 0xFF]
                )  # Needs extra byte for sub function
            else:
                # DefaultBehavior, e.g. for ReadDataByIdentifier/WriteDataByIdentifier
                pdu = bytes([args.sid, DID >> 8, DID & 0xFF])

            if args.payload:
                pdu += args.payload

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
                        f"{g_repr(DID)}: {resp}; does session {g_repr(session)} support service {service_repr(args.sid)}?"
                    )

                    if args.skip_not_supported:
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
