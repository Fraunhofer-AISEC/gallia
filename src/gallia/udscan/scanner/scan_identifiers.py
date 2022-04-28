import asyncio
import binascii
import reprlib
from argparse import Namespace
from itertools import product

from gallia.uds.core.constants import UDSErrorCodes, RCSubFuncs, UDSIsoServices
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.exception import IllegalResponse
from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.uds.helpers import suggests_service_not_supported
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import (
    auto_int,
    find_sessions,
    check_and_set_session,
    ParseSkips,
)


class ScanIdentifiers(UDSScanner):
    """This scanner scans DataIdentifiers of various
    services. Specific requirements such as for RoutineControl or SecurityAccess
    are considered and implemented in the script.
    """

    def add_parser(self) -> None:
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
            help="""
            Service ID to scan; defaults to ReadDataByIdentifier (default: 0x%(default)x);
            currently supported:
            0x27 Security Access;
            0x22 Read Data By Identifier;
            0x2e Write Data By Identifier;
            0x31 Routine Control;
            """,
        )
        self.parser.add_argument(
            "--check-session",
            nargs="?",
            const=1,
            type=int,
            help="Check current session via read DID [for every nth DataIdentifier] and try to recover session",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="""
                 The data identifiers to be skipped per session.
                 A session specific skip is given by <session_id>:<identifiers>
                 where <identifiers> is a comma separated list of single ids or id ranges using a dash.
                 Examples:
                  - 0x01:0xf3
                  - 0x10-0x2f
                  - 0x01:0xf3,0x10-0x2f
                 Multiple session specific skips are separated by space.
                 """,
        )

    async def main(self, args: Namespace) -> None:
        if args.sessions is None:
            self.logger.log_info("No sessions specified, starting with session scan")
            # Only until 0x80 because the eight bit is "SuppressResponse"
            sessions = list(
                s
                for s in range(1, 0x80)
                if s not in args.skip or args.skip[s] is not None
            )
            sessions = await find_sessions(self.ecu, sessions)
            self.logger.log_summary(
                f'Found {len(sessions)} sessions: {" ".join([hex(i) for i in sessions])}'
            )
        else:
            sessions = list(
                s
                for s in args.sessions
                if s not in args.skip or args.skip[s] is not None
            )

        self.logger.log_info(f"testing sessions {sessions}")
        self.logger.log_info(f"skipping identifiers {reprlib.repr(args.skip)}")

        for session in sessions:
            self.logger.log_notice(f"Switching to session 0x{session:02x}")
            resp: UDSResponse = await self.ecu.set_session(session)
            if isinstance(resp, NegativeResponse):
                self.logger.log_warning(
                    f"Switching to session 0x{session:02x} failed: {resp}"
                )
                continue

            self.logger.log_summary(f"Starting scan in session: 0x{session:02x}")
            positive_DIDs = 0
            abnormal_DIDs = 0
            timeout_DIDs = 0
            sub_functions = [0x00]

            if args.sid == UDSIsoServices.RoutineControl:
                if not args.payload:
                    self.logger.log_warning(
                        "Scanning RoutineControl with empty payload might start some routines "
                        "and change the state of the ECU!"
                    )

                # Scan all three subfunctions (startRoutine, stopRoutine, requestRoutineResults)
                sub_functions = list(map(int, RCSubFuncs))

            if args.sid == UDSIsoServices.SecurityAccess:
                if args.end > 0xFF:
                    self.logger.log_warning(
                        "Service 0x27 SecurityAccess only accepts 1-byte identifiers; "
                        + f"limiting END to 0xff instead of 0x{args.end:0x}"
                    )
                    args.end = 0xFF

            for (DID, sub_function) in product(
                range(args.start, args.end + 1), sub_functions
            ):
                if session in args.skip and DID in args.skip[session]:
                    self.logger.log_info(f"0x{DID:0x}: skipped")
                    continue

                if args.check_session and DID % args.check_session == 0:
                    # Check session and try to recover from wrong session (max 3 times), else skip session
                    if not await check_and_set_session(self.ecu, session):
                        self.logger.log_error(
                            f"Aborting scan on session 0x{session:02x}; current DID was 0x{DID:0x}"
                        )
                        break

                if args.sid == UDSIsoServices.SecurityAccess:
                    if DID & 0b10000000:
                        self.logger.log_info(
                            "Keep in mind that you set the SuppressResponse Bit (8th bit): "
                            + f"0x{DID:0x} = 0b{DID:b}"
                        )
                    pdu = bytes([args.sid, DID])

                elif args.sid == UDSIsoServices.RoutineControl:
                    pdu = bytes(
                        [args.sid, sub_function, DID >> 8, DID & 0xFF]
                    )  # Needs extra byte for sub function

                # DefaultBehaviour, e.g. for ReadDataByIdentifier/WriteDataByIdentifier
                else:
                    pdu = bytes([args.sid, DID >> 8, DID & 0xFF])

                if args.payload:
                    pdu += args.payload

                try:
                    resp = await self.ecu.send_raw(
                        pdu, config=UDSRequestConfig(tags=["ANALYZE"], max_retry=3)
                    )
                except asyncio.TimeoutError:
                    self.logger.log_summary(f"0x{DID:0x}: Retries exceeded")
                    timeout_DIDs += 1
                    continue
                except IllegalResponse as e:
                    self.logger.log_warning(f"{repr(e)}")

                if isinstance(resp, NegativeResponse):
                    if suggests_service_not_supported(resp):
                        self.logger.log_info(
                            f"0x{DID:0x}: {resp}; does session 0x{session:02x} "
                            f"support service 0x{args.sid:02x}?"
                        )

                    # RequestOutOfRange is a common reply for invalid DataIdentifiers
                    elif resp.response_code == UDSErrorCodes.requestOutOfRange:
                        self.logger.log_info(f"0x{DID:0x}: {resp}")

                    else:
                        self.logger.log_summary(f"0x{DID:0x}: {resp}")
                        abnormal_DIDs += 1
                else:
                    self.logger.log_summary(f"0x{DID:0x}: {resp}")
                    positive_DIDs += 1

            self.logger.log_summary(f"Scan in session 0x{session:0x} is complete!")
            self.logger.log_summary(f"Positive replies: {positive_DIDs}")
            self.logger.log_summary(f"Abnormal replies: {abnormal_DIDs}")
            self.logger.log_summary(f"Timeouts: {timeout_DIDs}")

            self.logger.log_info(f"Leaving session 0x{session:02x} via hook")
            await self.ecu.leave_session(session)
