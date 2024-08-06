# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import sys
from argparse import ArgumentParser, Namespace

from gallia.command import UDSScanner
from gallia.config import Config
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequestConfig
from gallia.services.uds.core.constants import UDSErrorCodes
from gallia.services.uds.core.service import SecurityAccessResponse
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger(__name__)


class SAKeylenDetector(UDSScanner):
    """This scanner tries to determine the key length expected by SecurityAccess."""

    COMMAND = "key-length"
    SHORT_HELP = "determine key length expected by SecurityAccess"

    def __init__(self, parser: ArgumentParser, config: Config = Config()) -> None:
        super().__init__(parser, config)

        self.implicit_logging = False

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "--session",
            metavar="INT",
            type=auto_int,
            default=0x02,
            help="Set diagnostic session to perform test in",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="Check current session with read DID",
        )
        self.parser.add_argument(
            "--level",
            default=0x11,
            metavar="INT",
            type=auto_int,
            help="Set security access level for which the seed for calculating the key would be returned.",
        )
        self.parser.add_argument(
            "--request-seed",
            action="store_true",
            default=False,
            help="Request a seed before sending a key. The default is to just send the key.",
        )
        self.parser.add_argument(
            "--reset",
            nargs="?",
            const=1,
            default=None,
            type=int,
            help="Attempt to fool brute force protection by resetting the ECU after every nth sent key.",
        )
        self.parser.add_argument(
            "--max-length",
            default=1000,
            type=int,
            metavar="INT",
            help="Test key lengths from 1 up to N bytes. The default is N = 1000.",
        )
        self.parser.add_argument(
            "--data-record",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="Append an optional data record to seed requests. Only has an effect when combined with '--request-seed'.",
        )
        self.parser.add_argument(
            "--sleep",
            default=0,
            type=float,
            metavar="FLOAT",
            help="Attempt to fool brute force protection by sleeping for N seconds between sending keys.",
        )

    async def request_seed(self, level: int, data: bytes) -> bytes | None:
        resp = await self.ecu.security_access_request_seed(level, data)
        if isinstance(resp, NegativeResponse):
            logger.warning(f"Requesting seed failed with: {resp}")
            return None
        return resp.security_seed

    async def main(self, args: Namespace) -> None:
        session = args.session
        logger.info(f"scanning in session: {g_repr(session)}")

        sess_resp = await self.ecu.set_session(session)
        if isinstance(sess_resp, NegativeResponse):
            logger.critical(f"could not change to session: {sess_resp}")
            return

        key = bytes([0x00])
        reset = False
        runs_since_last_reset = 0
        length_identified = False

        while len(key) <= args.max_length:
            logger.info(f"Testing key length {len(key)}...")

            if args.check_session or reset:
                if not await self.ecu.check_and_set_session(args.session):
                    logger.error(f"ECU persistently lost session {g_repr(args.session)}")
                    sys.exit(1)

            reset = False

            if args.request_seed:
                try:
                    await self.request_seed(args.level, args.data_record)
                except Exception as e:
                    logger.critical(f"Error while requesting seed: {g_repr(e)}")
                    sys.exit(1)

            key_resp = await self.ecu.security_access_send_key(
                args.level + 1, key, config=UDSRequestConfig(tags=["ANALYZE"])
            )
            if isinstance(key_resp, SecurityAccessResponse):
                logger.result(
                    f"That's unexpected: Unlocked SA level {g_repr(args.level)} with all-zero key of length {len(key)}."
                )
                length_identified = True
                break
            elif isinstance(key_resp, NegativeResponse):
                if (
                    not args.request_seed
                    and key_resp.response_code == UDSErrorCodes.requestSequenceError
                ) or (
                    args.request_seed
                    and key_resp.response_code == UDSErrorCodes.conditionsNotCorrect
                ):
                    logger.result(f"The ECU seems to be expecting keys of length {len(key)}.")
                    length_identified = True
                    break

            key += bytes([0x00])

            runs_since_last_reset += 1

            if runs_since_last_reset == args.reset:
                reset = True
                runs_since_last_reset = 0

                try:
                    logger.info("Resetting the ECU")
                    await self.ecu.ecu_reset(0x01)
                    logger.info("Waiting for the ECU to recover…")
                    await self.ecu.wait_for_ecu()
                except TimeoutError:
                    logger.error("ECU did not respond after reset; exiting…")
                    sys.exit(1)
                except ConnectionError:
                    logger.warning(
                        "Lost connection to the ECU after performing a reset. "
                        "Attempting to reconnect…"
                    )
                    await self.ecu.reconnect()

                # Re-enter session. Checking/logging will be done at the beginning of next iteration
                await self.ecu.set_session(session)

            if args.sleep > 0:
                logger.info(f"Sleeping for {args.sleep} seconds between sending keys…")
                await asyncio.sleep(args.sleep)

        if not length_identified:
            logger.result(
                f"Unable to identify valid key length for SecurityAccess between 1 and {args.max_length}."
            )
        await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)
