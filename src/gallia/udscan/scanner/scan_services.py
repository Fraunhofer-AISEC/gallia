import asyncio
import reprlib
from argparse import Namespace, BooleanOptionalAction
from binascii import unhexlify
from typing import Any

from gallia.uds.core.exception import UDSException
from gallia.uds.core.constants import UDSIsoServices
from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.service import NegativeResponse, UDSResponse
from gallia.uds.helpers import suggests_service_not_supported
from gallia.udscan.core import UDSScanner
from gallia.udscan.utils import (
    auto_int,
    check_and_set_session,
    find_sessions,
    ParseSkips,
)


class ScanServices(UDSScanner):
    """Iterate sessions and services and find endpoints"""

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--sessions",
            nargs="*",
            type=auto_int,
            default=None,
            help="Set list of sessions to be tested; all if None",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="check current session with read DID",
        )
        self.parser.add_argument(
            "--scan-response-ids",
            default=False,
            action=BooleanOptionalAction,
            help="Do not scan reply flag in SID",
        )
        self.parser.add_argument(
            "--auto-reset",
            action="store_true",
            default=False,
            help="Reset ECU with UDS ECU Reset before every request",
        )
        self.parser.add_argument(
            "--payload",
            default=None,
            type=unhexlify,
            help="Payload which will be appended for each request as hex string",
        )
        self.parser.add_argument(
            "--skip",
            nargs="+",
            default={},
            type=str,
            action=ParseSkips,
            help="""
                 The service IDs to be skipped per session.
                 A session specific skip is given by <session id>:<service ids>
                 where <service ids> is a comma separated list of single ids or id ranges using a dash.
                 Examples:
                  - 0x01:0xf3
                  - 0x10-0x2f
                  - 0x01:0xf3,0x10-0x2f
                 Multiple session specific skips are separated by space.
                 """,
        )

    async def main(self, args: Namespace) -> None:
        self.ecu.max_retry = 1
        found: dict[int, dict[int, Any]] = {}

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
            self.logger.log_info(f"Switching to session 0x{session:02X}")
            try:
                resp: UDSResponse = await self.ecu.set_session(
                    session, UDSRequestConfig(tags=["preparation"])
                )
            except (UDSException, RuntimeError) as e:
                self.logger.log_warning(f"session change: {session:x} reason: {e}")
                continue
            if isinstance(resp, NegativeResponse):
                self.logger.log_warning(f"session change: {session:x} reason: {resp}")
                continue

            found[session] = {}
            self.logger.log_summary(f"scanning in session 0x{session:02X}")

            # Starts at 0x00, see first loop iteration.
            sid = -1
            while sid < 0xFF:
                sid += 1
                if sid & 0x40 and not args.scan_response_ids:
                    continue

                if session in args.skip and sid in args.skip[session]:
                    self.logger.log_info(f"0x{sid:02X}: skipped")
                    continue

                if args.check_session:
                    if not await check_and_set_session(self.ecu, session):
                        self.logger.log_error(
                            f"Aborting scan on session 0x{session:02x}; current SID was 0x{sid:0x}"
                        )
                        break

                pdu = bytes([sid]) + args.payload if args.payload else bytes([sid])

                try:
                    resp = await self.ecu.send_raw(
                        pdu, config=UDSRequestConfig(tags=["ANALYZE"])
                    )
                except asyncio.TimeoutError:
                    self.logger.log_info(f"0x{sid:02X}: timeout")
                    continue
                except Exception as e:
                    self.logger.log_info(f"0x{sid:02X}: {type(e)} occurred")
                    await self.ecu.reconnect()
                    continue

                if suggests_service_not_supported(resp):
                    self.logger.log_info(f"0x{sid:02X}: not supported [{resp}]")
                    continue

                self.logger.log_summary(
                    f"0x{sid:02X}: available in session 0x{session:02X}: {resp}"
                )
                found[session][sid] = resp

            await self.ecu.leave_session(session)

        for key, value in found.items():
            self.logger.log_summary(f"findings in session 0x{key:02X}:")
            for sid, data in value.items():
                try:
                    self.logger.log_summary(
                        f"  [0x{sid:02X}] {UDSIsoServices(sid).name}: {data}"
                    )
                except Exception:
                    self.logger.log_summary(
                        f"  [0x{sid:02X}] vendor specific sid: {data}"
                    )
