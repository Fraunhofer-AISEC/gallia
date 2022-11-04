# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import os
import sys
import time
from argparse import ArgumentParser, Namespace
from pathlib import Path

import aiofiles

from gallia.command import UDSScanner
from gallia.config import Config
from gallia.services.uds import NegativeResponse, UDSRequestConfig
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int


class SASeedsDumper(UDSScanner):
    """This scanner tries to enable ProgrammingSession and dump seeds for 12h."""

    COMMAND = "dump-seeds"
    SHORT_HELP = "dump security access seeds"

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
            help="Set security access level to request seed from",
        )
        self.parser.add_argument(
            "--send-zero-key",
            metavar="BYTE_LENGTH",
            nargs="?",
            const=96,
            default=0,
            type=int,
            help="Attempt to fool brute force protection by pretending to send a key after requesting a seed "
            "(all zero bytes, length can be specified)",
        )
        self.parser.add_argument(
            "--reset",
            nargs="?",
            const=1,
            default=None,
            type=int,
            help="Attempt to fool brute force protection by resetting the ECU after every nth requested seed.",
        )
        self.parser.add_argument(
            "--duration",
            default=12 * 60,
            type=float,
            metavar="FLOAT",
            help="Run script for N minutes; zero or negative for infinite runtime",
        )
        self.parser.add_argument(
            "--data-record",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="Append an optional data record to each seed request",
        )

    async def request_seed(self, level: int, data: bytes) -> bytes | None:
        resp = await self.ecu.security_access_request_seed(
            level, data, config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if isinstance(resp, NegativeResponse):
            self.logger.warning(f"ECU replied with an error: {resp}")
            return None
        return resp.security_seed

    async def send_key(self, level: int, key: bytes) -> bool:
        resp = await self.ecu.security_access_send_key(
            level + 1, key, config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if isinstance(resp, NegativeResponse):
            self.logger.debug(f"Key was rejected: {resp}")
            return False
        self.logger.result(
            f'Unlocked SA level {g_repr(level)} with key "{key.hex()}"! resp: {resp}'
        )
        return True

    def log_size(self, path: os.PathLike[str], time_delta: float) -> None:
        size = os.path.getsize(path) / 1024
        size_unit = "KiB"
        rate = size / time_delta * 3600 if time_delta != 0 else 0
        rate_unit = "KiB"
        if rate > 1024:
            rate = rate / 1024
            rate_unit = "MiB"
        if size > 1024:
            size = size / 1024
            size_unit = "MiB"
        self.logger.notice(
            f"Dumping seeds with {rate:.2f}{rate_unit}/h: {size:.2f}{size_unit}"
        )

    async def main(self, args: Namespace) -> None:
        session = args.session
        self.logger.info(f"scanning in session: {g_repr(session)}")

        resp = await self.ecu.set_session(session)
        if isinstance(resp, NegativeResponse):
            self.logger.critical(f"could not change to session: {resp}")
            return

        i = -1
        seeds_file = Path.joinpath(self.artifacts_dir, "seeds.bin")
        file = await aiofiles.open(seeds_file, "wb", buffering=0)
        duration = args.duration * 60
        start_time = time.time()
        last_seed = b""
        reset = False
        runs_since_last_reset = 0
        print_speed = False

        while duration <= 0 or (time.time() - start_time) < duration:
            # Print information about current dump speed every `interval` seconds.
            # As request/response times can jitter a few seconds, we 'arm' the print
            # in one half and 'shoot' once in the other half.
            interval = 60
            i = int(time.time() - start_time) % interval
            if i >= (interval // 2):
                print_speed = True
            elif i < (interval // 2) and print_speed is True:
                self.log_size(seeds_file, time.time() - start_time)
                print_speed = False

            if args.check_session or reset:
                if not await self.ecu.check_and_set_session(args.session):
                    self.logger.error(
                        f"ECU persistently lost session {g_repr(args.session)}"
                    )
                    sys.exit(1)

            reset = False

            try:
                seed = await self.request_seed(args.level, args.data_record)
            except asyncio.TimeoutError:
                self.logger.error("Timeout while requesting seed")
                continue
            except Exception as e:
                self.logger.critical(f"Error while requesting seed: {g_repr(e)}")
                sys.exit(1)

            if seed is None:
                # Errors are already logged in .request_seed()
                continue

            await file.write(seed)
            if last_seed == seed:
                self.logger.warning("Received the same seed as before")

            last_seed = seed

            if args.send_zero_key > 0:
                try:
                    if await self.send_key(args.level, bytes(args.send_zero_key)):
                        break
                except asyncio.TimeoutError:
                    self.logger.warning("Timeout while sending key")
                    continue
                except Exception as e:
                    self.logger.critical(f"Error while sending key: {g_repr(e)}")
                    sys.exit(1)

            runs_since_last_reset += 1

            if runs_since_last_reset == args.reset:
                reset = True
                runs_since_last_reset = 0

                try:
                    self.logger.info("Resetting the ECU")
                    await self.ecu.ecu_reset(0x01)
                    self.logger.info("Waiting for the ECU to recover…")
                    await self.ecu.wait_for_ecu()
                except asyncio.TimeoutError:
                    self.logger.error("ECU did not respond after reset; exiting…")
                    sys.exit(1)
                except ConnectionError:
                    self.logger.warning(
                        "Lost connection to the ECU after performing a reset. "
                        "Attempting to reconnect…"
                    )
                    await self.ecu.reconnect()

                # Re-enter session. Checking/logging will be done at the beginning of next iteration
                await self.ecu.set_session(session)

        await file.close()
        self.log_size(seeds_file, time.time() - start_time)
        await self.ecu.leave_session(session)
