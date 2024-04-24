# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import reprlib
from argparse import BooleanOptionalAction, Namespace
from typing import Any

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import (
    NegativeResponse,
    UDSErrorCodes,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.exception import MalformedResponse, UDSException
from gallia.services.uds.core.utils import g_repr
from gallia.utils import ParseSkips, auto_int

logger = get_logger("gallia.scan.sa_levels")


class SALevelScanner(UDSScanner):
    """
    This class implements a scanner for Security Access Levels (SA Levels) within the Unified Diagnostic Service (UDS) protocol.

    It allows scanning for available security access levels on a UDS Server in specified sessions.

    **Methods:**

    * `main(self, args: Namespace) -> None` (async):
        * The main entry point for the security access level scan.
        * See docstring for details.
    * `perform_scan(self, args: Namespace, session: int | None = None) -> dict[int, Any]` (async):
        * Performs a security access level scan for a specific session and returns the results.
        * See docstring for details.
    """

    COMMAND = "security-access"
    SHORT_HELP = "scan available security access levels"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#security-access-scan"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            nargs="*",
            type=auto_int,
            default=None,
            help="Set list of sessions to be tested; current if None",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="check current session; only takes affect if --sessions is given",
        )
        self.parser.add_argument(
            "--scan-response-ids",
            default=False,
            action=BooleanOptionalAction,
            help="Include IDs in scan with reply flag set",
        )
        self.parser.add_argument(
            "--auto-reset",
            action="store_true",
            default=False,
            help="Reset ECU with UDS ECU Reset before every request",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="""
                 The subfunctions to be skipped per session.
                 A session specific skip is given by <session id>:<subfunctions>
                 where <subfunctions> is a comma separated list of single subfunctions or subfunction ranges using a dash.
                 Examples:
                  - 0x01:0xf3
                  - 0x10-0x2f
                  - 0x01:0xf3,0x10-0x2f
                 Multiple session specific skips are separated by space.
                 Only takes affect if --sessions is given.
                 """,
        )

    async def main(self, args: Namespace) -> None: # TODO: method identical to services_scan, unify?
        """
        The main entry point for the security access level scan.

        Performs the following steps:
        * Parses command-line arguments.
        * Iterates through specified sessions or the default session (0).
        * For each session:
            * Attempts to change to the session.
            * Performs a security access level scan for all subfunctions.
            * Leaves the session.
        * Logs the scan results.

        Args:
            args (Namespace): The parsed command-line arguments.
        """

        self.result: list[tuple[int, int]] = []
        self.ecu.max_retry = 1
        found: dict[int, dict[int, Any]] = {}

        if args.sessions is None:
            found[0] = await self.perform_scan(args)
        else:
            sessions = [s for s in args.sessions if s not in args.skip or args.skip[s] is not None]
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping subfunctions {reprlib.repr(args.skip)}")

            for session in sessions:
                logger.info(f"Changing to session {g_repr(session)}")
                try:
                    resp: UDSResponse = await self.ecu.set_session(
                        session, UDSRequestConfig(tags=["preparation"])
                    )
                except (
                    UDSException,
                    RuntimeError,
                ) as e:  # FIXME why catch RuntimeError?
                    logger.warning(
                        f"Could not complete session change to {g_repr(session)}: {g_repr(e)}; skipping session"
                    )
                    continue
                if isinstance(resp, NegativeResponse):
                    logger.warning(
                        f"Could not complete session change to {g_repr(session)}: {resp}; skipping session"
                    )
                    continue

                logger.result(f"scanning in session {g_repr(session)}")

                found[session] = await self.perform_scan(args, session)

                await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)

        for key, value in found.items():
            logger.result(f"Available SA levels in session 0x{key:02X}:")
            for subfunc, response in value.items():
                self.result.append((key, subfunc))
                logger.result(f" SA Level [{g_repr(subfunc)}]: {response}")

    async def perform_scan(self, args: Namespace, session: None | int = None) -> dict[int, Any]:
        """
        Performs a security access level scan for a specific session and returns the results.

        Scans all subfunctions (except explicitly skipped ones) with different payload lengths
        to test ECU behavior.

        Args:
            args (Namespace): The parsed command-line arguments.
            session (int, optional): The session to scan. Defaults to None (default session).

        Returns:
            dict[int, Any]: A dictionary containing the scan results for each subfunction.
                Keys are subfunction IDs, values are the corresponding UDSResponse objects.
        """

        result: dict[int, Any] = {}

        # First subfunction is 0x01
        subfunc = 0x00
        while subfunc < 0x7F:
            subfunc += 1 
            if subfunc % 2 == 0: # Scanning only odd subfunctions (requests), even are responses
                continue

            if subfunc & 0x40 and not args.scan_response_ids:
                continue

            if session in args.skip and subfunc in args.skip[session]:
                logger.info(f"{g_repr(subfunc)}: skipped")
                continue

            if session is not None and args.check_session:
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current subfunc was {g_repr(subfunc)}"
                    )
                    break

            for length_payload in [0, 1, 2, 3, 5]:
                try:
                    resp = await self.ecu.security_access_request_seed(security_access_type = subfunc, security_access_data_record = bytes(length_payload), suppress_response = False, config=UDSRequestConfig(tags=["ANALYZE"]))
                except TimeoutError:
                    logger.info(f"{g_repr(subfunc)}: timeout")
                    continue
                except MalformedResponse as e:
                    logger.warning(f"{g_repr(subfunc)}: {e!r} occurred, this needs to be investigated!")
                    continue

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.serviceNotSupported,
                    UDSErrorCodes.serviceNotSupportedInActiveSession,
                ]:
                    logger.info(f"{g_repr(subfunc)}: not supported [{resp}]")
                    break

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.incorrectMessageLengthOrInvalidFormat,
                    UDSErrorCodes.subFunctionNotSupported,
                    UDSErrorCodes.subFunctionNotSupportedInActiveSession,
                ]:
                    continue

                logger.result(f"SA Level {g_repr(subfunc)}: available in session {g_repr(session)}: {resp}")
                result[subfunc] = resp
                break

        return result
