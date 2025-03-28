# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import sys
import time
from pathlib import Path

from gallia.command import UDSScanner
from gallia.command.config import AutoInt, Field, HexBytes
from gallia.command.uds import UDSScannerConfig
from gallia.log import get_logger
from gallia.services.uds import NegativeResponse, UDSErrorCodes, UDSRequestConfig
from gallia.services.uds.core.utils import g_repr

logger = get_logger(__name__)


class SASeedsDumperConfig(UDSScannerConfig):
    session: AutoInt = Field(
        0x02, description="Set diagnostic session to perform test in", metavar="INT"
    )
    check_session: bool = Field(False, description="Check current session with read DID")
    level: AutoInt = Field(
        0x11, description="Set security access level to request seed from", metavar="INT"
    )
    send_zero_key: int | None = Field(
        None,
        description="Attempt to fool brute force protection by sending an all-zero key after each seed request. The length of the key can be specified or will otherwise be automatically determined.",
        metavar="BYTE_LENGTH",
        const=0,
    )
    determine_key_size_max_length: int = Field(
        1024,
        description="When trying to automatically determine the key size expected by the ECU, test key lengths from 1 up to N bytes.",
        metavar="INT",
    )
    reset: int | None = Field(
        None,
        metavar="N",
        description="Attempt to fool brute force protection by resetting the ECU when needed or after every N-th requested seed.",
        const=0,
    )
    duration: float = Field(
        0,
        description="Run script for N minutes; zero or negative for infinite runtime (default)",
        metavar="FLOAT",
    )
    data_record: HexBytes = Field(
        b"", description="Append an optional data record to each seed request", metavar="HEXSTRING"
    )
    sleep: float | None = Field(
        None,
        description="Attempt to fool brute force protection by sleeping for N seconds between seed requests.",
    )


class SASeedsDumper(UDSScanner):
    """This scanner tries to enable ProgrammingSession and dump seeds for 12h."""

    CONFIG_TYPE = SASeedsDumperConfig
    SHORT_HELP = "dump security access seeds"

    attempt_reset: bool = False
    is_key_length_determined: bool = False
    key_length: int = 0

    def __init__(self, config: SASeedsDumperConfig):
        super().__init__(config)
        self.config: SASeedsDumperConfig = config
        self.implicit_logging = False

    async def request_seed(self, level: int, data: bytes) -> bytes | None:
        resp = await self.ecu.security_access_request_seed(
            level, data, config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if isinstance(resp, NegativeResponse):
            logger.warning(f"ECU replied with an error: {resp}")
            self.attempt_reset = True
            return None
        return resp.security_seed

    # TODO: Optimize by checking well-known lenghts first: 0x60, 125, 250, 512, 1024.
    async def send_key(self, level: int) -> bool:
        """Returns `True` when main loop should exit, e.g. on successful unlock or exhaustion of key length search space."""
        if (
            self.is_key_length_determined is False
            and self.key_length > self.config.determine_key_size_max_length
        ):
            logger.error(
                f"Unable to identify valid key length for SecurityAccess between 1 and {self.config.determine_key_size_max_length} bytes."
            )
            return True

        if not self.is_key_length_determined:
            logger.info(f"No key length given, testing key length {self.key_length}…")

        resp = await self.ecu.security_access_send_key(
            level + 1, bytes(self.key_length), config=UDSRequestConfig(tags=["ANALYZE"])
        )
        if not isinstance(resp, NegativeResponse):
            logger.result(
                f"That's unexpected: Unlocked SA level {g_repr(level)} with all-zero key of length {self.key_length}."
            )
            return True

        if (
            not self.is_key_length_determined
            and resp.response_code == UDSErrorCodes.incorrectMessageLengthOrInvalidFormat
        ):
            logger.debug(
                f"{self.key_length} does not seem to be the correct key length, incrementing."
            )
            self.key_length += 1
        elif not self.is_key_length_determined:
            logger.result(f"The ECU seems to be expecting keys of length {self.key_length}.")
            self.is_key_length_determined = True
        else:
            logger.debug(f"Key was rejected: {resp}")

        return False

    def log_size(self, path: Path, time_delta: float) -> None:
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

    async def main(self) -> None:
        session = self.config.session
        logger.info(f"scanning in session: {g_repr(session)}")

        resp = await self.ecu.set_session(session)
        if isinstance(resp, NegativeResponse):
            logger.critical(f"could not change to session: {resp}")
            return

        if self.artifacts_dir is None:
            logger.warning("No artifacts base folder given, saving seeds to current working dir!")
            seeds_file = Path.cwd().joinpath("seeds.bin")
        else:
            seeds_file = self.artifacts_dir.joinpath("seeds.bin")
        file = seeds_file.open("wb", buffering=0)
        duration = self.config.duration * 60
        start_time = time.time()
        last_seed = b""
        requests_since_last_reset = 0
        print_speed = False
        if self.config.send_zero_key is None:
            # Set this to True to not suppress log messages or evaluation of
            # replies later on even though we never send a key
            self.is_key_length_determined = True
        elif self.config.send_zero_key > 0:
            # A specific key_length was given, so use it and no automation
            self.is_key_length_determined = True
            self.key_length = self.config.send_zero_key
        else:
            # Start with length 1 in automatic search
            self.key_length = 1

        while duration <= 0 or time.time() - start_time < duration:
            # Print information about current dump speed every `interval` seconds.
            # As request/response times can jitter a few seconds, we 'arm' the print
            # in one half and 'shoot' once in the other half.
            interval = 60
            i = int(time.time() - start_time) % interval
            if i >= interval // 2:
                print_speed = True
            elif i < interval // 2 and print_speed is True:
                self.log_size(seeds_file, time.time() - start_time)
                print_speed = False

            if self.config.reset is not None:
                if (self.config.reset == 0 and self.attempt_reset) or (
                    self.config.reset > 0 and requests_since_last_reset == self.config.reset
                ):
                    logger.info(
                        f"Resetting the ECU after {requests_since_last_reset} seed requests"
                    )
                    await self.ecu.ecu_reset(0x01)

                    if await self.ecu.wait_for_ecu() is False:
                        logger.error("ECU did not respond after reset; exiting…")
                        sys.exit(1)

                    # Re-enter session. Checking/logging will be done a few lines later if required
                    await self.ecu.set_session(session)

                    requests_since_last_reset = 0
                    self.attempt_reset = False

            if self.config.check_session:
                if not await self.ecu.check_and_set_session(self.config.session):
                    logger.error(f"ECU persistently lost session {g_repr(self.config.session)}")
                    sys.exit(1)

            try:
                seed = await self.request_seed(self.config.level, self.config.data_record)
                if seed is None:
                    continue  # Errors are already logged in .request_seed()
            except TimeoutError:
                logger.error("Timeout while requesting seed")
                continue
            except Exception as e:
                logger.critical(f"Error while requesting seed: {g_repr(e)}")
                sys.exit(1)
            finally:
                requests_since_last_reset += 1

            # During detection of key length the same seed might be returned multiple times.
            # This is, however, not considered critical and should not affect statistical evaluations of the seeds.
            if self.is_key_length_determined is False:
                logger.debug("Still trying to find key size, not evaluating/saving seed responses")
            else:
                file.write(seed)

                if last_seed == seed:
                    logger.warning("Received the same seed as before")
                else:
                    logger.info(f"Received seed of length {len(seed)}")

            last_seed = seed

            if self.key_length > 0:
                try:
                    if await self.send_key(self.config.level):
                        break
                except TimeoutError:
                    logger.warning("Timeout while sending key")
                    continue
                except Exception as e:
                    logger.critical(f"Error while sending key: {g_repr(e)}")
                    sys.exit(1)

            if self.config.sleep is not None:
                logger.info(f"Sleeping for {self.config.sleep} seconds between seed requests…")
                await asyncio.sleep(self.config.sleep)

        file.close()
        self.log_size(seeds_file, time.time() - start_time)
        await self.ecu.leave_session(session, sleep=self.config.power_cycle_sleep)
