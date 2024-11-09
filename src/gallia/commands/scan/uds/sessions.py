# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

"""Module for scanning available UDS sessions and their transitions."""

import asyncio
import sys
from argparse import Namespace
from typing import Any

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import (
    NegativeResponse,
    UDSErrorCodes,
    UDSRequestConfig,
    UDSResponse,
)
from gallia.services.uds.core.constants import EcuResetSubFuncs
from gallia.services.uds.core.service import DiagnosticSessionControlResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger(__name__)


class SessionsScanner(UDSScanner):
    """
    Scans for available UDS diagnostic sessions and their transitions.
    
    Starts from the default session (0x01) and recursively explores other sessions, 
    handling session switching, potential errors, and ECU reset.
    """

    COMMAND = "sessions"
    SHORT_HELP = "session scan on an ECU"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--depth",
            type=auto_int,
            default=None,
            metavar="DEPTH",
            help="Maximum depth to explore for session transitions (default: unlimited).",
        )
        self.parser.add_argument(
            "--sleep",
            metavar="SECONDS",
            type=auto_int,
            default=0,
            help="Seconds to wait after switching to the DefaultSession (0x01).",
        )
        self.parser.add_argument(
            "--skip",
            metavar="SESSION_ID",
            type=auto_int,
            default=[],
            nargs="*",
            help="List of session IDs to skip during the scan (e.g., '1 3').",
        )
        self.parser.add_argument(
            "--with-hooks",
            action="store_true",
            help="Use diagnostic session control hooks to handle 'ConditionsNotCorrect' errors.",
        )
        self.parser.add_argument(
            "--reset",
            nargs="?",
            default=None,
            const=0x01, # Default reset level if --reset is provided without a value
            type=lambda x: int(x, 0),
            help="Reset the ECU after each iteration using the specified reset level (hex, e.g., '0x01').",
        )
        self.parser.add_argument(
            "--fast",
            action="store_true",
            help="Search for new sessions only once per session, ignoring alternative paths (faster, but less thorough).",
        )

    async def set_session_with_hooks_handling(
        self, session: int, use_hooks: bool
    ) -> NegativeResponse | DiagnosticSessionControlResponse:
        """
        Attempts to set the specified session, optionally using diagnostic session control hooks.

        Handles conditionsNotCorrect responses by retrying with hooks if enabled.
        """

        resp = await self.ecu.set_session(
            session, config=UDSRequestConfig(skip_hooks=True), use_db=False
        )

        if (
            isinstance(resp, NegativeResponse)
            and resp.response_code == UDSErrorCodes.conditionsNotCorrect
        ):
            logger.notice(f"Received conditionsNotCorrect for session {g_repr(session)}")
            if not use_hooks:
                logger.warning(
                    f"Session {g_repr(session)} is potentially available but could not be entered. "
                    f"Use --with-hooks to try to enter the session using hooks to scan for "
                    f"transitions available from that session."
                )
                return resp

            resp_ = await self.ecu.set_session(
                session, config=UDSRequestConfig(skip_hooks=False), use_db=False
            )

            if not isinstance(resp_, NegativeResponse):
                logger.notice(f"Successfully changed to session {g_repr(session)} with hooks")
                resp = resp_
            else:
                logger.notice(
                    f"Could not successfully change to session {g_repr(session)} even with hooks"
                )

        return resp

    async def recover_stack(self, stack: list[int], use_hooks: bool) -> bool:
        """
        Attempts to recover the session stack by sequentially setting sessions from the given stack.

        Returns True if the stack recovery was successful, False otherwise.
        """

        for session in stack:
            try:
                resp = await self.set_session_with_hooks_handling(session, use_hooks)

                if isinstance(resp, NegativeResponse):
                    logger.error(
                        f"Could not change to session {g_repr(session)} as part of stack: {resp}. "
                        f"Try with --reset to reset between each iteration."
                    )
                    return False
            except Exception as e:
                logger.error(
                    f"Could not change to session {g_repr(session)} as part of stack: {g_repr(e)}. "
                    f"Try with --reset to reset between each iteration."
                )
                return False
        return True

    async def main(self, args: Namespace) -> None:
        """
        Main execution of the session scan.

        Performs a depth-first search to discover session transitions, starting from the default session.
        Handles session skipping, ECU resets (if enabled), and logs the found sessions.
        """

        self.result: list[int] = []
        found: dict[int, list[list[int]]] = {0: [[0x01]]}
        positive_results: list[dict[str, Any]] = []
        negative_results: list[dict[str, Any]] = []
        activated_sessions: set[int] = set()
        search_sessions: list[int] = []

        sessions = list(range(1, 0x80))
        depth = 0

        while (args.depth is None or depth < args.depth) and len(found[depth]) > 0:
            depth += 1

            found[depth] = []
            logger.info(f"Depth: {depth}")

            for stack in found[depth - 1]:
                if args.fast and stack[-1] in search_sessions:
                    continue

                search_sessions.append(stack[-1])

                if stack:
                    logger.info(f"Starting from session: {g_repr(stack[-1])}")

                for session in sessions:
                    if session in args.skip:
                        logger.info(f"Skipping session {g_repr(session)} as requested")
                        continue

                    if args.reset:
                        try:
                            logger.info("Resetting the ECU")
                            resp: UDSResponse = await self.ecu.ecu_reset(args.reset)

                            if isinstance(resp, NegativeResponse):
                                logger.warning(
                                    f"Could not reset ECU with {EcuResetSubFuncs(args.reset).name if args.reset in iter(EcuResetSubFuncs) else args.reset}: {resp}"
                                    f"; continuing without reset"
                                )
                            else:
                                logger.info("Waiting for the ECU to recover…")
                                await self.ecu.wait_for_ecu(timeout=args.timeout)
                        except (TimeoutError, ConnectionError):
                            logger.warning(
                                "Lost connection to the ECU after performing a reset. "
                                "Attempting to reconnect…"
                            )
                            await self.ecu.reconnect()

                    try:
                        logger.debug("Changing session to DefaultSession")
                        resp = await self.ecu.set_session(0x01, use_db=False)
                        if isinstance(resp, NegativeResponse):
                            logger.error(f"Could not change to default session: {resp}")
                            sys.exit(1)
                    except Exception as e:
                        logger.error(f"Could not change to default session: {e!r}")
                        sys.exit(1)

                    logger.debug(f"Sleeping for {args.sleep}s after changing to DefaultSession")
                    await asyncio.sleep(args.sleep)

                    logger.debug("Recovering the current session stack")
                    if not await self.recover_stack(stack, args.with_hooks):
                        sys.exit(1)

                    try:
                        logger.debug(f"Attempting to change to session {session:#04x}")
                        resp = await self.set_session_with_hooks_handling(session, args.with_hooks)

                        # do not ignore NCR subFunctionNotSupportedInActiveSession in this case
                        if (
                            isinstance(resp, NegativeResponse)
                            and resp.response_code == UDSErrorCodes.subFunctionNotSupported
                        ):
                            logger.info(f"Could not change to session {g_repr(session)}: {resp}")
                            continue

                        logger.notice(
                            f"Found session: {g_repr(session)} via stack: {g_repr(stack)}; {resp}"
                        )

                        if not isinstance(resp, NegativeResponse):
                            # Reaching each session once is enough
                            if session not in stack:
                                found[depth].append(stack + [session])

                            activated_sessions.add(session)
                            positive_results.append(
                                {"session": session, "stack": stack, "error": None}
                            )
                        else:
                            negative_results.append(
                                {
                                    "session": session,
                                    "stack": stack,
                                    "error": resp.response_code,
                                }
                            )

                    except TimeoutError:
                        logger.warning(f"Could not change to session {g_repr(session)}: Timeout")
                        continue
                    except Exception as e:
                        logger.warning(f"Mamma mia: {repr(e)}")

        logger.result("Scan finished; Found the following sessions:")
        previous_session = 0

        for res in sorted(positive_results, key=lambda x: x["session"]):
            session = res["session"]

            if session != previous_session:
                previous_session = session
                self.result.append(int(session))
                logger.result(f"* Session {g_repr(session)} ")

                if self.db_handler is not None:
                    await self.db_handler.insert_session_transition(session, res["stack"])

            logger.result(f"\tvia stack: {'->'.join([f'{g_repr(i)}' for i in res['stack']])}")

        logger.result("The following sessions were identified but could not be activated:")
        previous_session = 0

        for res in sorted(negative_results, key=lambda x: x["session"]):
            session = res["session"]

            if (
                session not in activated_sessions
                and res["error"] != UDSErrorCodes.subFunctionNotSupportedInActiveSession
            ):
                if session != previous_session:
                    previous_session = session
                    logger.result(f"* Session {g_repr(session)} ")

                    if self.db_handler is not None:
                        await self.db_handler.insert_session_transition(session, res["stack"])

                logger.result(
                    f"\tvia stack: {'->'.join([f'{g_repr(i)}' for i in res['stack']])} "
                    f"(NRC: {res['error']})"
                )
