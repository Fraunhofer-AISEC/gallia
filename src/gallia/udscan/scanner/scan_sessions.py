# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from argparse import Namespace
from typing import Union

from gallia.uds.core.client import UDSRequestConfig
from gallia.uds.core.constants import UDSErrorCodes
from gallia.uds.core.service import (
    DiagnosticSessionControlResponse,
    NegativeResponse,
    UDSResponse,
)
from gallia.udscan.core import UDSScanner
from gallia.utils import auto_int, g_repr


class IterateSessions(UDSScanner):
    """Iterate Sessions"""

    def add_parser(self) -> None:
        self.parser.add_argument(
            "--depth", type=auto_int, default=None, help="Specify max scanning depth."
        )
        self.parser.add_argument(
            "--sleep",
            metavar="SECONDS",
            type=auto_int,
            default=0,
            help="Sleep this amount of seconds after changing to DefaultSession",
        )
        self.parser.add_argument(
            "--skip",
            metavar="SESSION_ID",
            type=auto_int,
            default=[],
            nargs="*",
            help="List with session IDs to skip while scanning",
        )
        self.parser.add_argument(
            "--with-hooks",
            action="store_true",
            help="Use hooks in case of a ConditionsNotCorrect error",
        )
        self.parser.add_argument(
            "--reset", action="store_true", help="Reset the ECU after each iteration"
        )

    async def set_session_with_hooks_handling(
        self, session: int, use_hooks: bool
    ) -> Union[NegativeResponse, DiagnosticSessionControlResponse]:
        resp = await self.ecu.set_session(
            session, config=UDSRequestConfig(skip_hooks=True)
        )

        if (
            isinstance(resp, NegativeResponse)
            and resp.response_code == UDSErrorCodes.conditionsNotCorrect
        ):
            if not use_hooks:
                self.logger.log_warning(
                    f"Session {g_repr(session)} is potentially available but could not be entered. "
                    f"Use --with-hooks to try to enter the session using hooks to scan for "
                    f"transitions available from that session."
                )
                return resp

            resp_ = await self.ecu.set_session(
                session, config=UDSRequestConfig(skip_hooks=False)
            )

            if isinstance(resp, NegativeResponse):
                self.logger.log_notice(
                    f"Received conditionsNotCorrect for session {g_repr(session)}. "
                    f"Successfully changed to the session with hooks."
                )
                resp = resp_

        return resp

    async def recover_stack(self, stack: list, use_hooks: bool) -> bool:
        for session in stack:
            try:
                resp = await self.set_session_with_hooks_handling(session, use_hooks)

                if isinstance(resp, NegativeResponse):
                    self.logger.log_error(
                        f"Could not change to session {g_repr(session)} as part of stack: {resp}. "
                        f"Try with --reset to reset between each iteration."
                    )
                    return False
            except Exception as e:
                self.logger.log_error(
                    f"Could not change to session {g_repr(session)} as part of stack: {g_repr(e)}. "
                    f"Try with --reset to reset between each iteration."
                )
                return False
        return True

    async def main(self, args: Namespace) -> None:
        found: dict[int, list[list[int]]] = {0: [[0x01]]}
        positive_results: list[dict] = []
        negative_results: list[dict] = []
        activated_sessions: set[int] = set()

        sessions = list(range(1, 0x80))
        depth = 0

        # pylint: disable=too-many-nested-blocks
        while (args.depth is None or depth < args.depth) and len(found[depth]) > 0:
            depth += 1

            found[depth] = []
            self.logger.log_summary(f"Depth: {depth}")

            for stack in found[depth - 1]:
                if stack:
                    self.logger.log_summary(
                        f"Starting from session: {g_repr(stack[-1])}"
                    )

                for session in sessions:
                    if session in args.skip:
                        self.logger.log_info(
                            f"Skipping session {g_repr(session)} as requested"
                        )
                        continue

                    if args.reset:
                        try:
                            self.logger.log_info("Resetting the ECU")
                            resp: UDSResponse = await self.ecu.ecu_reset(0x01)

                            if isinstance(resp, NegativeResponse):
                                self.logger.log_warning(
                                    f"Could not reset ECU: {resp}; "
                                    f"continue without reset"
                                )
                            else:
                                self.logger.log_info("Waiting for the ECU to recover…")
                                await self.ecu.wait_for_ecu()
                        except asyncio.TimeoutError:
                            self.logger.log_error(
                                "ECU did not respond after reset; exiting…"
                            )
                            sys.exit(1)
                        except ConnectionError:
                            self.logger.log_warning(
                                "Lost connection to the ECU after performing a reset. "
                                "Attempting to reconnect…"
                            )
                            await self.ecu.reconnect()

                    try:
                        resp = await self.ecu.set_session(0x01)
                        if isinstance(resp, NegativeResponse):
                            self.logger.log_error(
                                f"Could not change to default session: {resp}"
                            )
                            sys.exit(1)
                    except Exception as e:
                        self.logger.log_error(
                            f"Could not change to default session: {g_repr(e)}"
                        )
                        sys.exit(1)

                    self.logger.log_debug(
                        f"Sleeping for {args.sleep}s after changing to DefaultSession"
                    )
                    await asyncio.sleep(args.sleep)

                    if not await self.recover_stack(stack, args.with_hooks):
                        sys.exit(1)

                    try:
                        resp = await self.set_session_with_hooks_handling(
                            session, args.with_hooks
                        )

                        # do not ignore NCR subFunctionNotSupportedInActiveSession in this case
                        if (
                            isinstance(resp, NegativeResponse)
                            and resp.response_code
                            == UDSErrorCodes.subFunctionNotSupported
                        ):
                            self.logger.log_info(
                                f"Could not change to session {g_repr(session)}: {resp}"
                            )
                            continue

                        self.logger.log_summary(
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

                    except asyncio.TimeoutError:
                        self.logger.log_warning(
                            f"Could not change to session {g_repr(session)}: Timeout"
                        )
                        continue

        self.logger.log_summary("Scan finished; Found the following sessions:")
        previous_session = 0

        for res in sorted(positive_results, key=lambda x: x["session"]):
            session = res["session"]

            if session != previous_session:
                previous_session = session
                self.logger.log_summary(f"* Session {g_repr(session)} ")

            self.logger.log_summary(
                f"\tvia stack: {'->'.join([f'{g_repr(i)}' for i in res['stack']])}"
            )

        self.logger.log_summary(
            "The following sessions were identified but could not be activated:"
        )
        previous_session = 0

        for res in sorted(negative_results, key=lambda x: x["session"]):
            session = res["session"]

            if (
                session not in activated_sessions
                and res["error"] != UDSErrorCodes.subFunctionNotSupportedInActiveSession
            ):
                if session != previous_session:
                    previous_session = session
                    self.logger.log_summary(f"* Session {g_repr(session)} ")

                self.logger.log_summary(
                    f"\tvia stack: {'->'.join([f'{g_repr(i)}' for i in res['stack']])} "
                    f"(NRC: {res['error']})"
                )
