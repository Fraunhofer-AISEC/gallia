# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import reprlib
import sys
from typing import Any

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, Ranges, Ranges2D
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import (
    NegativeResponse,
    UDSErrorCodes,
    UDSIsoServices,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.exception import (
    MalformedResponse,
    RequestResponseMismatch,
    UDSException,
)
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class ServicesScannerConfig(UDSScannerConfig):
    sessions: Ranges | None = Field(
        None,
        description="Set list of sessions to scan in; if None, services are scanned without session changes",
    )
    check_session: bool = Field(
        False, description="check current session; only takes effect if --sessions is given"
    )
    scan_response_ids: bool = Field(False, description="Include IDs in scan with reply flag set")
    reset: AutoInt | None = Field(
        None,
        description="Reset the ECU after every session with the optionally given reset level; only takes effect if --sessions is given",
        const=0x01,
    )
    skip: Ranges2D = Field(
        {},
        metavar="SESSION_ID:ID",
        description="\nThe service IDs to be skipped per session.\nA session specific skip is given by <session id>:<service ids>\nwhere <service ids> is a comma separated list of single ids or id ranges using a dash.\nExamples:\n - 0x01:0xf3\n - 0x10-0x2f\n - 0x01:0xf3,0x10-0x2f\nMultiple session specific skips are separated by space.\nOnly takes affect if --sessions is given.\n",
    )


class ServicesScanner(UDSScanner):
    """Iterate sessions and services and find endpoints"""

    CONFIG_TYPE = ServicesScannerConfig
    SHORT_HELP = "service scan on an ECU"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/scan_modes.html#service-scan"

    def __init__(self, config: ServicesScannerConfig):
        super().__init__(config)
        self.config: ServicesScannerConfig = config

        self.result: list[tuple[int, int]] = []

    async def main(self) -> None:
        self.ecu.max_retry = 0
        found: dict[int, dict[int, Any]] = {}
        clean_returns = True

        if self.config.sessions is None:
            # Attempt to read session once for state update
            try:
                current_session = await self.ecu.read_session(
                    UDSRequestConfig(
                        timeout=2,
                        max_retry=0,
                    )
                )
                logger.notice(f"Performing scan in current session, which is {current_session:#x}")
            except Exception as e:
                current_session = 0
                logger.notice(f"Performing scan in current (unknown) session: {e!r}")

            found[current_session], clean_returns = await self.perform_scan()

        else:
            sessions = [
                s
                for s in self.config.sessions
                if s not in self.config.skip or self.config.skip[s] is not None
            ]
            logger.info(f"testing sessions {g_repr(sessions)}")

            # TODO: Unified shortened output necessary here
            logger.info(f"skipping identifiers {reprlib.repr(self.config.skip)}")

            for session in sessions:
                logger.info(f"Changing to session {g_repr(session)}")
                try:
                    resp: UDSResponse = await self.ecu.set_session(
                        session, UDSRequestConfig(tags=["preparation"])
                    )
                except (UDSException, RuntimeError) as e:  # FIXME: why catch RuntimeError?
                    logger.warning(
                        f"Could not complete session change to {g_repr(session)}: {g_repr(e)}; skipping session"
                    )
                    clean_returns = False
                    continue
                if isinstance(resp, NegativeResponse):
                    logger.warning(
                        f"Could not complete session change to {g_repr(session)}: {resp}; skipping session"
                    )
                    clean_returns = False
                    continue

                logger.result(f"scanning in session {g_repr(session)}")

                found[session], ret = await self.perform_scan(session)
                clean_returns = clean_returns and ret

                if self.config.reset is not None:
                    try:
                        logger.info("Resetting the ECU as requested")
                        reset_resp = await self.ecu.ecu_reset(self.config.reset)

                        if isinstance(reset_resp, NegativeResponse):
                            logger.warning(
                                f"Could not reset ECU: {reset_resp}; continuing without reset"
                            )
                        else:
                            logger.info("Waiting for the ECU to recover…")
                            await self.ecu.wait_for_ecu()
                    except (TimeoutError, ConnectionError):
                        logger.warning(
                            "Lost connection to the ECU after performing a reset. Attempting to reconnect…"
                        )
                        await self.ecu.reconnect()

        for key, value in found.items():
            logger.result(f"findings in session 0x{key:02X}:")
            for sid, data in value.items():
                self.result.append((key, sid))
                try:
                    logger.result(f"  [{g_repr(sid)}] {UDSIsoServices(sid).name}: {data}")
                except Exception:
                    logger.result(f"  [{g_repr(sid)}] vendor specific sid: {data}")

        if not clean_returns:
            sys.exit(1)

    async def perform_scan(self, session: None | int = None) -> tuple[dict[int, Any], bool]:
        result: dict[int, Any] = {}
        clean_returns = True

        # Starts at 0x00, see first loop iteration.
        sid = -1
        while sid < 0xFF:
            sid += 1
            if sid & 0x40 and (not self.config.scan_response_ids):
                continue

            if session in self.config.skip and (
                (session_skip := self.config.skip[session]) is None or sid in session_skip
            ):
                logger.info(f"{g_repr(sid)}: skipped")
                continue

            if session is not None and self.config.check_session:
                if not await self.ecu.check_and_set_session(session):
                    logger.error(
                        f"Aborting scan on session {g_repr(session)}; current SID was {g_repr(sid)}"
                    )
                    return result, False

            for length_payload in [1, 2, 3, 5]:
                pdu = bytes([sid]) + bytes(length_payload)
                try:
                    resp = await self.ecu.send_raw(pdu, config=UDSRequestConfig(tags=["ANALYZE"]))
                except TimeoutError:
                    logger.info(f"{g_repr(sid)}: timeout")
                    continue
                except (MalformedResponse, RequestResponseMismatch) as e:
                    logger.warning(f"{g_repr(sid)}: {e!r} occurred, this needs to be investigated!")
                    clean_returns = False
                    continue

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.serviceNotSupported,
                    UDSErrorCodes.serviceNotSupportedInActiveSession,
                ]:
                    logger.info(f"{g_repr(sid)}: not supported [{resp}]")
                    break

                if isinstance(resp, NegativeResponse) and resp.response_code in [
                    UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
                ]:
                    continue

                logger.result(f"{g_repr(sid)}: available in session {g_repr(session)}: {resp}")
                result[sid] = resp
                break

        return result, clean_returns
