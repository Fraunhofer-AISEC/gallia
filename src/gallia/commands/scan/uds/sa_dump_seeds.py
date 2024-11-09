# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
import sys
import time
from argparse import ArgumentParser, Namespace
from pathlib import Path

import aiofiles

from gallia.command import UDSScanner
from gallia.config import Config
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSRequestConfig
from gallia.services.uds.core.utils import g_repr
from gallia.utils import auto_int

logger = get_logger(__name__)


class SASeedsDumper(UDSScanner):
    """
    This scanner attempts to switch to a specified Diagnostic Session
    and continuously dumps security access seeds from the ECU.
    """    

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
            help="Set diagnostic session to switch into before performing the seed dumping (default: 0x%(default)x)",
        )
        self.parser.add_argument(
            "--check-session",
            action="store_true",
            default=False,
            help="Verify the current session by reading DID `0xF186`.",
        )
        self.parser.add_argument(
            "--level",
            default=0x11,
            metavar="INT",
            type=auto_int,
            help="Set security access level to request seeds from (default: 0x%(default)x)",
        )
        self.parser.add_argument(
            "--send-zero-key",
            metavar="BYTE_LENGTH",
            nargs="?",
            const=96,
            default=0,
            type=int,
            help="Attempt to fool brute force protection by sending a zero-filled key after requesting a seed "
            "(specify key length in bytes). (default: 0 - disabled)",
        )
        self.parser.add_argument(
            "--reset",
            nargs="?",
            const=1,
            default=None,
            type=int,
            help="Attempt to fool brute force protection by resetting the ECU after every Nth requested seed (default: None - no reset).",
        )
        self.parser.add_argument(
            "--duration",
            default=0,
            type=float,
            metavar="FLOAT",
            help="Run the dumping for a specified number of minutes (0 or negative for infinite runtime). (default: 0 - infinite)",
        )
        self.parser.add_argument(
            "--data-record",
            metavar="HEXSTRING",
            type=binascii.unhexlify,
            default=b"",
            help="Optional data record to be appended to the seed request message (provide as hex string). (default: empty data)",
        )
        self.parser.add_argument(
            "--sleep",
            type=float,
            metavar="FLOAT",
            help="Attempt to fool brute force protection by sleeping for N seconds between seed requests.",
        )

    async def request_seed(self, level: int, data: bytes) -> bytes | None:
        """This coroutine requests a security access seed from the connected ECU.

            - Calls the `ecu.security_access_request_seed` method to send the seed request.
            - Handles potential `NegativeResponse` from the ECU, logging the error and returning None.
            - If the request is successful, extracts and returns the security seed from the response.

        :param level: The security access level to request the seed from.
        :type level: int
        :param data: Optional data to be included in the seed request message.
        :type data: bytes
        :return: The requested security access seed on success, None otherwise.
        :rtype: bytes | None
        """
        
        resp = await self.ecu.security_access_request_seed(
            level, data, config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if isinstance(resp, NegativeResponse):
            logger.warning(f"ECU replied with an error: {resp}")
            return None
        return resp.security_seed

    async def send_key(self, level: int, key: bytes) -> bool:
        resp = await self.ecu.security_access_send_key(
            level + 1, key, config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if isinstance(resp, NegativeResponse):
            logger.debug(f"Key was rejected: {resp}")
            return False
        logger.result(f'Unlocked SA level {g_repr(level)} with key "{key.hex()}"! resp: {resp}')
        return True

    def log_size(self, path: Path, time_delta: float) -> None:
        """This method calculates and displays the size and dump speed of captured data.

        **Details:**

        1. **Get File Size:**
        - Calls `path.stat().st_size` to get the size of the file pointed to by `path` in bytes.
        - Divides the file size by 1024 to convert it to KiB (Kilobytes).

        2. **Calculate Data Dump Speed:**
        - Checks if `time_delta` (elapsed time) is zero.
            - If zero, sets the dump speed (`rate`) to 0 as there's no time for calculation.
        - Otherwise, calculates the dump speed in KiB/h (Kilobytes per hour):
            - Divides the file size (`size`) by the elapsed time (`time_delta`) and multiplies by 3600 (conversion factor from seconds to hours).

        3. **Format Units (Size and Speed):**
        - Checks if the calculated `rate` is greater than 1024.
            - If so, converts `rate` to MiB (Megabytes) by dividing by 1024 and updates the unit (`rate_unit`).
        - Similarly, checks if the file `size` is greater than 1024.
            - If so, converts `size` to MiB and updates the unit (`size_unit`).

        4. **Log Information:**
        - Uses the logger object (`logger`) to log a message at the 'notice' level.
        - The message includes:
            - Dump speed (formatted with 2 decimal places) followed by the unit (KiB/h or MiB/h).
            - Captured data size (formatted with 2 decimal places) followed by the unit (KiB or MiB).

        :param path: Path object representing the file containing the captured data.
        :type path: Path
        :param time_delta: Time elapsed since the start of data capture in seconds.
        :type time_delta: float
        """

        size = path.stat().st_size / 1024
        size_unit = "KiB"
        rate = size / time_delta * 3600 if time_delta != 0 else 0
        rate_unit = "KiB"
        if rate > 1024:
            rate = rate / 1024
            rate_unit = "MiB"
        if size > 1024:
            size = size / 1024
            size_unit = "MiB"
        logger.notice(f"Dumping seeds with {rate:.2f}{rate_unit}/h: {size:.2f}{size_unit}")

    async def main(self, args: Namespace) -> None:
        """This coroutine is the main entry point for the SASeedsDumper scanner.

        **Functionality:**

        1. **Session Management:**
            - Attempts to switch to the diagnostic session specified by `args.session`.
            - Logs errors if the ECU fails to change sessions using `logger.critical()`.
            - Optionally verifies the current session before proceeding (`--check-session`).

        2. **Seed Dumping Loop:**
            - Opens a file named "seeds.bin" in the scanner's artifacts directory for writing seeds.
            - Enters a loop that continues for a user-defined duration (`--duration`) or indefinitely.
            - Within the loop:
                - Requests a security access seed from the ECU at the specified level (`--level`).
                - Handles potential timeouts and errors during seed requests with logging and termination.
                - Appends the received seed to the open file.
                - Optionally sends a zero-filled key after requesting a seed (`--send-zero-key`).
                    - Useful for bypassing certain ECU security mechanisms.
                - Optionally resets the ECU periodically (`--reset`).
                    - Aims to overcome seed rate limiting imposed by the ECU.
                    - Handles ECU recovery and reconnection after reset.

        3. **Cleanup:**
            - Closes the seed data file.
            - Logs the total size and dump speed of the captured seeds.
            - Leaves the current diagnostic session on the ECU (optional sleep after power cycle).

        :param args: Namespace object containing parsed command-line arguments.
        :type args: Namespace
        """
     
        session = args.session
        logger.info(f"scanning in session: {g_repr(session)}")

        resp = await self.ecu.set_session(session)
        if isinstance(resp, NegativeResponse):
            logger.critical(f"could not change to session: {resp}")
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
                    logger.error(f"ECU persistently lost session {g_repr(args.session)}")
                    sys.exit(1)

            reset = False

            try:
                seed = await self.request_seed(args.level, args.data_record)
            except TimeoutError:
                logger.error("Timeout while requesting seed")
                continue
            except Exception as e:
                logger.critical(f"Error while requesting seed: {g_repr(e)}")
                sys.exit(1)

            if seed is None:
                # Errors are already logged in .request_seed()
                continue

            logger.info(f"Received seed of length {len(seed)}")

            await file.write(seed)
            if last_seed == seed:
                logger.warning("Received the same seed as before")

            last_seed = seed

            if args.send_zero_key > 0:
                try:
                    if await self.send_key(args.level, bytes(args.send_zero_key)):
                        break
                except TimeoutError:
                    logger.warning("Timeout while sending key")
                    continue
                except Exception as e:
                    logger.critical(f"Error while sending key: {g_repr(e)}")
                    sys.exit(1)

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

            if args.sleep is not None:
                logger.info(f"Sleeping for {args.sleep} seconds between seed requests…")
                await asyncio.sleep(args.sleep)

        await file.close()
        self.log_size(seeds_file, time.time() - start_time)
        await self.ecu.leave_session(session, sleep=args.power_cycle_sleep)
