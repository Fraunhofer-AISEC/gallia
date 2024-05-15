# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from argparse import Namespace

from gallia.command import UDSScanner
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger("gallia.primitive.reset")


class ECUResetPrimitive(UDSScanner):
    """Use the ECUReset UDS service to reset the ECU

    This class implements the ECU Reset functionality using the Unified Diagnostic Service (UDS)
    protocol. It leverages the UDSScanner class from the gallia.command module to execute
    the diagnostic communication.

    **Group:** 'primitive'
    **Command:** 'ecu-reset'
    **Short Help:** 'ECUReset'

    This class offers a way to reset the ECU through the UDS 0x11 service.

    **Key functionalities:**

    * Initiates a communication session with the ECU using the specified session ID (defaults to 0x01).
    * Transmits the ECU Reset request to the ECU with an optional sub-function parameter (defaults to 0x01).
    * Analyzes the ECU's response to determine the success or failure of the reset operation.
    * Logs informative messages throughout the process, including session changes, request attempts, and response outcomes.

    **Arguments:**

    * `--target` <TARGET_URI>: URI specifying the target ECU (required). Example: isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700 defines an ISO-TP connection on virtual CAN interface vcan0 (CAN FD disabled, standard frames, source address 0x701, destination address 0x700).
    * `--session` (int, optional): Diagnostic session to use during communication (default: 0x01).
    * `-f` or `--subfunc` (int, optional): Sub-function parameter for the ECU Reset request (default: 0x01).

    **Example Usage:**
    Reset the ECU using session 0x02 and sub-function 0x0A
    `gallia primitive uds ecu-reset --target "isotp://vcan0?is_fd=false&is_extended=false&src_addr=0x701&dst_addr=0x700" --session 0x02 -f 0x0A`

    This command initiates a reset operation on the ECU, targeting session 0x02 and employing sub-function 0x0A.

    **Output:**

    The class logs informative messages to the console, including:

    * Established session with the ECU (if successful).
    * Attempted ECU Reset with the provided sub-function.
    * Success or failure outcome of the ECU Reset operation.
    * Timeout errors in case of communication delays.
    * Connection errors if communication with the ECU is lost.
    """

    GROUP = "primitive"
    COMMAND = "ecu-reset"
    SHORT_HELP = "ECUReset"

    def configure_parser(self) -> None:
        """Configures the argument parser for the ECU Reset command.

        This method adds the following arguments to the parser:

        - `--session`: (int, optional) The diagnostic session to perform the test in.
          Defaults to 0x01.
        - `-f|--subfunc`: (int, optional) The subfunction of the ECU Reset service
          to execute. Defaults to 0x01.
        """

        self.parser.set_defaults(properties=False)

        self.parser.add_argument(
            "--session",
            type=auto_int,
            default=0x01,
            help="set session perform test in",
        )
        self.parser.add_argument(
            "-f",
            "--subfunc",
            type=auto_int,
            default=0x01,
            help="subfunc",
        )

    async def main(self, args: Namespace) -> None:
        """The main execution function for the ECU Reset command.

        This method performs the following steps:

        1. Sets the diagnostic session to the specified value using `ecu.set_session`.
        2. Sends the ECU Reset request with the provided subfunction using `ecu.ecu_reset`.
        3. Handles the response:
            - If successful, logs a message indicating success.
            - If a negative response is received, logs an error message.
            - In case of timeout or connection errors, logs the error and waits before returning.
        """

        resp: UDSResponse = await self.ecu.set_session(args.session)
        if isinstance(resp, NegativeResponse):
            logger.error(f"could not change to session: {g_repr(args.session)}")
            return

        try:
            logger.info(f"try sub-func: {g_repr(args.subfunc)}")
            resp = await self.ecu.ecu_reset(args.subfunc)
            if isinstance(resp, NegativeResponse):
                msg = f"ECU Reset {g_repr(args.subfunc)} failed in session: {g_repr(args.session)}: {resp}"
                logger.error(msg)
            else:
                logger.result(f"ECU Reset {g_repr(args.subfunc)} succeeded")
        except TimeoutError:
            logger.error("Timeout")
            await asyncio.sleep(10)
        except ConnectionError:
            msg = f"Lost connection to ECU, session: {g_repr(args.session)} subFunc: {g_repr(args.subfunc)}"
            logger.error(msg)
            return
