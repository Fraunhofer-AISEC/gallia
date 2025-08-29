# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import gzip
import io
import shlex
import shutil
import sys
from asyncio import subprocess
from datetime import datetime
from pathlib import Path
from typing import Self

from gallia.log import get_logger
from gallia.utils import handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


if sys.platform.startswith("linux") or sys.platform == "darwin":

    class Dumpcap:
        BUFSIZE = io.DEFAULT_BUFFER_SIZE

        def __init__(
            self,
            proc: subprocess.Process,
            outfile: Path,
            cleanup: int = 2,
        ) -> None:
            self.proc = proc
            self.outfile = outfile
            self.cleanup = cleanup
            self.ready_event = asyncio.Event()
            self.compressor = asyncio.create_task(self._compressor())
            self.compressor.add_done_callback(
                handle_task_error,
                context=set_task_handler_ctx_variable(__name__, "Dumpcap"),
            )

        @classmethod
        async def start(
            cls,
            dumpcap_argument_list: list[str],
            save_dir: Path,
        ) -> Self | None:
            if (dumpcap := shutil.which("dumpcap")) is None:
                raise RuntimeError("Cannot start Dumpcap, because `dumpcap` is not available!")

            cmd_str = shlex.join([dumpcap] + dumpcap_argument_list)

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd_str.split(),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
                await asyncio.sleep(0.2)
            except Exception as e:
                logger.error(f"Could not start dumpcap: ({e!r})")
                return None

            if proc.returncode:
                logger.error(f"dumpcap terminated with exit code: [{proc.returncode}]")
                return None

            logger.info(f'Started "dumpcap": {cmd_str}')

            return cls(
                proc, save_dir.joinpath(f"dumpcap-{int(datetime.now().timestamp())}.pcap.gz")
            )

        async def sync(self, timeout: float = 1) -> None:
            await asyncio.wait_for(self.ready_event.wait(), timeout)

        async def stop(self) -> None:
            logger.info(f"Waiting {self.cleanup}s for dumpcap to receive all packets")
            await asyncio.sleep(self.cleanup)
            try:
                self.proc.terminate()
            except ProcessLookupError:
                logger.warning("dumpcap terminated before gallia")
            await self.proc.wait()
            await self.compressor

        async def _compressor(self) -> None:
            ready = False
            assert self.proc.stdout
            with await asyncio.to_thread(gzip.open, self.outfile, "wb") as f:
                while True:
                    chunk = await self.proc.stdout.read(64 * 1024)
                    if chunk == b"":
                        break
                    # Dumpcap first writes the pcap header. It does this
                    # once the tool is ready. We can use this is as a poor
                    # man's synchronization primitive.
                    if not ready:
                        ready = True
                        self.ready_event.set()
                    await asyncio.to_thread(f.write, chunk)


if sys.platform == "win32":

    class Dumpcap:
        @classmethod
        async def start(
            cls,
            dumpcap_argument_list: list[str],
            save_dir: Path,
        ) -> Self | None:
            logger.warning("dumpcap is not available on windows")
            return None

        async def stop(self) -> None:
            pass

        async def sync(self) -> None:
            pass
