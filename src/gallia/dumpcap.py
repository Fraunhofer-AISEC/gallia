# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import gzip
import io
import os
import shutil
import socket
import struct
import sys
from asyncio import subprocess
from datetime import datetime
from pathlib import Path
from typing import Self, cast
from urllib.parse import urlsplit

from gallia.log import get_logger
from gallia.utils import handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


def _swap_bytes_16(x: int) -> int:
    return cast(int, struct.unpack(">H", struct.pack("<H", x))[0])


def dumpcap_argument_list_can(iface: str, arb_ids: list[int] | None = None) -> list[str] | None:
    """If no `arb_ids` are provided, all traffic on the interface is captured."""

    args = ["-q", "-i", iface, "-w", "-"]

    if arb_ids is not None:
        _filter: list[str] = []

        for arb_id in arb_ids:
            # TODO: Support extended CAN IDs
            if arb_id > 0x800:
                logger.error(f"Dumpcap currently does not support extended CAN Ids: {hex(arb_id)}")
                continue

            # Debug this with `dumpcap -d` or `tshark -x` to inspect the captured buffer.
            _filter.append(
                f"link[0:2] == {_swap_bytes_16(arb_id):#x}"
            )  # can_id is in little endian

        args += ["-f", " || ".join(_filter)]

    return args


async def dumpcap_argument_list_eth(host: str, port: int | None = None) -> list[str] | None:
    if proxy := os.getenv("all_proxy"):
        url = urlsplit(proxy)
        host = str(url.hostname) if url.hostname else "localhost"
        port = url.port or 1080  # Default SOCKS port

    # Resolve host string to ip address
    loop = asyncio.get_running_loop()
    res = await loop.getaddrinfo(
        host,
        port,
        type=socket.SocketKind.SOCK_STREAM,
    )

    # We don't do round robin, ergo we only have
    # 1 result. That's fine here. The data structure
    # of the return value of getaddrinfo() is weird,
    # but it's documented in the python docs:
    # https://docs.python.org/3/library/socket.html
    addr_tuple = res[0]
    ip, port = addr_tuple[4][0], addr_tuple[4][1]

    return [
        "-q",
        "-i",
        "any",
        "-w",
        "-",
        "-f",
        f"host {ip} and tcp port {port}",
    ]


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
                raise RuntimeError("Cannot start Dumpcap, because 'dumpcap' is not available!")

            logger.debug(f"Attempting to start 'dumpcap' with arguments {dumpcap_argument_list}")
            try:
                proc = await asyncio.create_subprocess_exec(
                    dumpcap,
                    *dumpcap_argument_list,
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

            logger.info("Started 'dumpcap'")

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
                    chunk = await self.proc.stdout.read(self.BUFSIZE)
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
