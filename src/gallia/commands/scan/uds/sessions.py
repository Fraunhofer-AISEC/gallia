# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
from typing import Any

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, Ranges
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSErrorCodes, UDSRequestConfig
from gallia.services.uds.core.constants import DiagnosticSessionControlSubFuncs, EcuResetSubFuncs
from gallia.services.uds.core.service import DiagnosticSessionControlResponse
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class SessionsScannerConfig(UDSScannerConfig):
    depth: AutoInt = Field(4, description="Specify max scanning depth.")
    sleep: AutoInt = Field(
        0,
        description="Sleep this amount of seconds after changing to DefaultSession",
        metavar="SECONDS",
    )
    skip: Ranges = Field(
        [], description="List with session IDs to skip while scanning", metavar="SESSION_ID"
    )
    with_hooks: bool = Field(False, description="Use hooks in case of a ConditionsNotCorrect error")
    reset: AutoInt | None = Field(
        None,
        description="Reset the ECU before each iteration with the optionally given reset level",
        const=0x01,
    )
    thorough: bool = Field(
        False,
        description="Perform a session scan for each 'stack' of a session instead of only once per session",
    )


class SessionsScanner(UDSScanner):
    """Iterate Sessions"""

    CONFIG_TYPE = SessionsScannerConfig
    SHORT_HELP = "session scan on an ECU"

    def __init__(self, config: SessionsScannerConfig):
        super().__init__(config)
        self.config: SessionsScannerConfig = config

        self.result: list[int] = []

    async def set_session_with_hooks_handling(
        self, session: int, use_hooks: bool
    ) -> NegativeResponse | DiagnosticSessionControlResponse:
        """This function attempts to set the session without hooks first and if unsuccessful due to NRC CnC
        it automatically attempts the session change with hooks, as long as `use_hooks` is True"""
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
                    f"Session {g_repr(session)} is potentially available but could not be entered. Use --with-hooks to try to enter the session using hooks to scan for transitions available from that session."
                )
                return resp

            logger.debug(f"Attempting to change to session {g_repr(session)} with hooks")
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

    async def _recover_stack(self, stack: list[int], use_hooks: bool) -> bool:
        logger.debug(f"Recovering the current session stack: {stack}")

        for session in stack:
            try:
                resp = await self.set_session_with_hooks_handling(session, use_hooks)

                if isinstance(resp, NegativeResponse):
                    logger.error(
                        f"Could not change to session {g_repr(session)} as part of stack: {resp}. Try with --reset to reset between each iteration."
                    )
                    return False

                if session == DiagnosticSessionControlSubFuncs.defaultSession:
                    logger.debug(
                        f"Sleeping for {self.config.sleep}s after changing to DefaultSession"
                    )
                    await asyncio.sleep(self.config.sleep)

            except Exception as e:
                logger.error(
                    f"Could not change to session {g_repr(session)} as part of stack: {g_repr(e)}. Try with --reset to reset between each iteration."
                )
                return False

        logger.info("Stack fully recovered!")
        return True

    async def main(self) -> None:
        found: dict[int, list[list[int]]] = {
            0: [[DiagnosticSessionControlSubFuncs.defaultSession]]
        }  # Content of this dict is just a filler to start the loop
        positive_results: list[dict[str, Any]] = []
        negative_results: list[dict[str, Any]] = []
        activated_sessions: set[int] = set()
        searched_sessions: list[int] = []

        sessions = list(range(1, 0x80))
        current_depth = 0

        while current_depth < self.config.depth and len(found[current_depth]) > 0:
            current_depth += 1

            found[current_depth] = []
            logger.notice(f"Enumerating at depth: {current_depth}")

            for stack in found[current_depth - 1]:
                if (not self.config.thorough) and stack[-1] in searched_sessions:
                    continue
                searched_sessions.append(stack[-1])

                if stack:
                    logger.info(f"Starting from session: {g_repr(stack[-1])}")

                # Recover stack in first loop iteration and afterwards only if needed
                recover_stack = True

                for session in sessions:
                    if session in self.config.skip:
                        logger.info(f"Skipping testing for session {g_repr(session)} as requested")
                        continue

                    if self.config.reset:
                        try:
                            logger.info("Resetting the ECU as requested")
                            reset_resp = await self.ecu.ecu_reset(self.config.reset)

                            if isinstance(reset_resp, NegativeResponse):
                                logger.warning(
                                    f"Could not reset ECU with {(EcuResetSubFuncs(self.config.reset).name if self.config.reset in iter(EcuResetSubFuncs) else self.config.reset)}: {reset_resp}; continuing without reset"  # type: ignore[operator]
                                )
                            else:
                                logger.info("Waiting for the ECU to recover…")
                                await self.ecu.wait_for_ecu(timeout=self.config.timeout)
                        except (TimeoutError, ConnectionError):
                            logger.warning(
                                "Lost connection to the ECU after performing a reset. Attempting to reconnect…"
                            )
                            await self.ecu.reconnect()
                        recover_stack = True

                    if recover_stack is True:
                        logger.info("Recovering the stack...")
                        if not await self._recover_stack(stack, self.config.with_hooks):
                            sys.exit(1)
                        recover_stack = False

                    logger.debug(f"Attempting to change to session {session:#04x}")
                    try:
                        resp = await self.set_session_with_hooks_handling(
                            session, self.config.with_hooks
                        )

                        # Do only ignore NCR subFunctionNotSupported
                        if (
                            isinstance(resp, NegativeResponse)
                            and resp.response_code == UDSErrorCodes.subFunctionNotSupported
                        ):
                            logger.info(f"Could not change to session {g_repr(session)}: {resp}")
                            # For this NRC, continue without recovering the stack
                            continue

                        logger.notice(
                            f"Found session: {g_repr(session)} via stack: {g_repr(stack)}; {resp}"
                        )

                        if isinstance(resp, NegativeResponse):
                            negative_results.append(
                                {"session": session, "stack": stack, "error": resp.response_code}
                            )
                            # Presumably we did not successfully leave the session, so no need to recover the stack
                            continue

                        # Do not track a session in "found" if it is already present on the stack unless 'thorough'
                        # This avoids looping through sessions, e.g. 0x01->0x02->0x01->0x02->...
                        if self.config.thorough or session not in stack:
                            found[current_depth].append(stack + [session])

                        activated_sessions.add(session)
                        positive_results.append({"session": session, "stack": stack, "error": None})
                    except TimeoutError:
                        logger.warning(f"Could not change to session {g_repr(session)}: Timeout")
                        # TODO: Is there a need to recover stack in this case?
                        continue
                    except Exception as e:
                        logger.warning(
                            f"Mamma mia: {repr(e)} for session {session:#04x} from stack {stack}"
                        )

                    # If the loop is not `continue`d early, recover stack, e.g. on successful session change
                    recover_stack = True

        if len(positive_results) > 0:
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
        else:
            logger.result("Could not successfully change to any session!")

        if len(negative_results) > 0:
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
                        f"\tvia stack: {'->'.join([f'{g_repr(i)}' for i in res['stack']])} (NRC: {res['error']})"
                    )
