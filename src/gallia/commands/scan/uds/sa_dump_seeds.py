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
from gallia.services.uds import NegativeResponse, UDSRequestConfig
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
    send_zero_key: int = Field(
        0,
        description="Attempt to fool brute force protection by pretending to send a key after requesting a seed (all zero bytes, length can be specified)",
        metavar="BYTE_LENGTH",
        const=96,
    )
    reset: int | None = Field(
        None,
        description="Attempt to fool brute force protection by resetting the ECU after every nth requested seed.",
        const=1,
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

        i = -1
        seeds_file = Path.joinpath(self.artifacts_dir, "seeds.bin")
        file = seeds_file.open("wb", buffering=0)
        duration = self.config.duration * 60
        start_time = time.time()
        last_seed = b""
        reset = False
        runs_since_last_reset = 0
        print_speed = False

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

            if self.config.check_session or reset:
                if not await self.ecu.check_and_set_session(self.config.session):
                    logger.error(f"ECU persistently lost session {g_repr(self.config.session)}")
                    sys.exit(1)

            reset = False

            try:
                seed = await self.request_seed(self.config.level, self.config.data_record)
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

            file.write(seed)
            if last_seed == seed:
                logger.warning("Received the same seed as before")

            last_seed = seed

            if self.config.send_zero_key > 0:
                try:
                    if await self.send_key(self.config.level, bytes(self.config.send_zero_key)):
                        break
                except TimeoutError:
                    logger.warning("Timeout while sending key")
                    continue
                except Exception as e:
                    logger.critical(f"Error while sending key: {g_repr(e)}")
                    sys.exit(1)

            runs_since_last_reset += 1

            if runs_since_last_reset == self.config.reset:
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
                        "Lost connection to the ECU after performing a reset. Attempting to reconnect…"
                    )
                    await self.ecu.reconnect()

                # Re-enter session. Checking/logging will be done at the beginning of next iteration
                await self.ecu.set_session(session)

            if self.config.sleep is not None:
                logger.info(f"Sleeping for {self.config.sleep} seconds between seed requests…")
                await asyncio.sleep(self.config.sleep)

        file.close()
        self.log_size(seeds_file, time.time() - start_time)
        await self.ecu.leave_session(session, sleep=self.config.power_cycle_sleep)
