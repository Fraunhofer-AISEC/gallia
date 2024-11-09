# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Module for scanning available UDS services."""

import reprlib
from argparse import BooleanOptionalAction, Namespace
from typing import Any

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import (
    NegativeResponse,
    UDSErrorCodes,
    UDSIsoServices,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.exception import MalformedResponse, UDSException
from gallia.services.uds.core.utils import g_repr
from gallia.utils import ParseSkips, auto_int

logger = get_logger(__name__)


class ServicesScanner(UDSScanner):
    """
    Scans for available UDS services on an ECU.

    This scanner iterates through UDS sessions (optional) and service IDs to determine which services are supported by the ECU.
    It handles responses, errors, and session management for efficient service discovery.
    """

    COMMAND = "services"
    SHORT_HELP = "service scan on an ECU"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#service-scan"

    def configure_parser(self) -> None:
        """Configures command-line arguments for the service scan."""

        self.parser.add_argument(
            "--sessions",
            nargs="*",
            type=auto_int,
            default=None,
            metavar="SESSION_ID",
            help="List of session IDs to scan (e.g., 1 3). Scans all sessions if not specified.",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="Verify the current session before each request (only if --sessions is used).",
        )
        self.parser.add_argument(
            "--scan-response-ids",
            default=False,
            action=BooleanOptionalAction,
            help="Include service IDs with the 'SuppressPositiveResponse' bit set.",
        )
        self.parser.add_argument(
            "--auto-reset",
            action="store_true",
            default=False,
            help="Reset the ECU with UDS ECU Reset before each request.",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="""
                Skip specific services within sessions. Format: SESSION_ID:SERVICES 

                SESSION_ID: ID of the session (integer)
                SERVICES: Comma-separated list of:
                    - Single service IDs (e.g., 0x22)
                    - Service ID ranges (e.g., 0x10-0x1F)

                Examples:
                - '0x01:0x22' (Skips service 0x22 in session 0x01)
                - '0x10-0x1F' (Skips services 0x10 to 0x1F in all sessions)
                - '0x01:0xf3,0x10-0x2f' (Multiple skips in session 0x01)

                Multiple session-specific skips can be provided, separated by spaces.
                Only applicable if --sessions is used.
                """,
        )

    async def main(self, args: Namespace) -> None:
        """
        Main execution function for the service scan.

        Organizes the scan process, handling session switching (if enabled) and calling `perform_scan` for each session.
        Aggregates and logs results across sessions.
        """

        self.result: list[tuple[int, int]] = []
        self.ecu.max_retry = 0
        found: dict[int, dict[int, Any]] = {}

        if args.sessions is None:
            found[0] = await self.perform_scan(args)
        else:
            sessions = [s for s in args.sessions if s not in args.skip or args.skip[s] is not None]
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(args.skip)}")

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
            logger.result(f"findings in session 0x{key:02X}:")
            for sid, data in value.items():
                self.result.append((key, sid))
                try:
                    logger.result(f"  [{g_repr(sid)}] {UDSIsoServices(sid).name}: {data}")
                except Exception:
                    logger.result(f"  [{g_repr(sid)}] vendor specific sid: {data}")

    async def perform_scan(self, args: Namespace, session: None | int = None) -> dict[int, Any]:
        """
        Performs the scan for supported services within a specific session.

        Iterates through service IDs, sending requests with varying payloads to determine service availability.
        Handles timeouts, malformed responses, and negative responses from the ECU.
        Returns a dictionary of found services and their responses.
        """
        
        result: dict[int, Any] = {}

        # Starts at 0x00, see first loop iteration.
        sid = -1
        while sid < 0xFF:
            sid += 1
            if sid & 0x40 and not args.scan_response_ids:
                continue

            if session in args.skip and sid in args.skip[session]:
                logger.info(f"{g_repr(sid)}: skipped")
                continue

            if session is not None and args.check_session:
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current SID was {g_repr(sid)}"
                    )
                    break

            for length_payload in [1, 2, 3, 5]:
                pdu = bytes([sid]) + bytes(length_payload)
                try:
                    resp = await self.ecu.send_raw(pdu, config=UDSRequestConfig(tags=["ANALYZE"]))
                except TimeoutError:
                    logger.info(f"{g_repr(sid)}: timeout")
                    continue
                except MalformedResponse as e:
                    logger.warning(f"{g_repr(sid)}: {e!r} occurred, this needs to be investigated!")
                    continue

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.serviceNotSupported,
                    UDSErrorCodes.serviceNotSupportedInActiveSession,
                ]:
                    logger.info(f"{g_repr(sid)}: not supported [{resp}]")
                    break

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.incorrectMessageLengthOrInvalidFormat,
                ]:
                    continue

                logger.result(f"{g_repr(sid)}: available in session {g_repr(session)}: {resp}")
                result[sid] = resp
                break

        return result
