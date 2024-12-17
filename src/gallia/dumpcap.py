# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import gzip
import io
import os
import shlex
import struct
import sys
from asyncio import subprocess
from datetime import datetime
from pathlib import Path
from socket import SocketKind
from typing import Self, cast
from urllib.parse import urlparse

from gallia.log import get_logger
from gallia.net import split_host_port
from gallia.transports import TargetURI, TransportScheme
from gallia.utils import auto_int, handle_task_error, set_task_handler_ctx_variable

logger = get_logger(__name__)


if sys.platform.startswith("linux") or sys.platform == "darwin":

    class Dumpcap:
        BUFSIZE = io.DEFAULT_BUFFER_SIZE

        def __init__(
            self,
            proc: subprocess.Process,
            artifacts_dir: Path,
            outfile: Path,
            cleanup: int = 2,
        ) -> None:
            self.proc = proc
            self.artifacts_dir = artifacts_dir
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
            target: TargetURI,
            artifacts_dir: Path,
        ) -> Self | None:
            ts = int(datetime.now().timestamp())

            match target.scheme:
                case TransportScheme.ISOTP | TransportScheme.CAN_RAW:
                    outfile = artifacts_dir.joinpath(f"candump-{ts}.pcap.gz")
                    src_addr = (
                        auto_int(target.qs["src_addr"][0]) if "src_addr" in target.qs else None
                    )
                    dst_addr = (
                        auto_int(target.qs["dst_addr"][0]) if "dst_addr" in target.qs else None
                    )
                    cmd = cls._can_cmd(
                        target.netloc,
                        src_addr,
                        dst_addr,
                    )
                case TransportScheme.UNIX | TransportScheme.UNIX_LINES:
                    logger.warning("Dumpcap does not support unix domain sockets")
                    return None
                # There is currently no API for transport plugins to
                # register a scheme and a corresponding invocation
                # for dumpcap. So this match…case is best effort,
                # since it defaults to ethernet.
                case _:
                    outfile = artifacts_dir.joinpath(f"eth-{ts}.pcap.gz")
                    cmd = await cls._eth_cmd(target.netloc)

            if cmd is None:
                return None

            cmd_str = shlex.join(cmd)
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
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

            return cls(proc, artifacts_dir, outfile)

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

        @staticmethod
        def _swap_bytes_16(x: int) -> int:
            return cast(int, struct.unpack(">H", struct.pack("<H", x))[0])

        @staticmethod
        def _can_cmd(iface: str, src_addr: int | None, dst_addr: int | None) -> list[str] | None:
            args = ["dumpcap", "-q", "-i", iface, "-w", "-"]
            # Debug this with `dumpcap -d` or `tshark -x` to inspect the captured buffer.
            filter_ = ""

            if src_addr is not None and dst_addr is not None:
                # TODO: Support extended CAN IDs
                if src_addr > 0x800 or dst_addr > 0x800:
                    logger.error("Extended CAN Ids are currently not supported!")
                    return None

                filter_ += (
                    f"link[0:2] == {Dumpcap._swap_bytes_16(src_addr):#x} "  # can_id is in little endian
                    f"|| link[0:2] == {Dumpcap._swap_bytes_16(dst_addr):#x}"
                )
            args += ["-f", filter_]
            return args

        @staticmethod
        async def _eth_cmd(target_ip: str) -> list[str] | None:
            try:
                host, port = split_host_port(target_ip)
            except Exception as e:
                logger.error(f"Invalid argument for target ip: {target_ip}; {e}")
                return None

            if proxy := os.getenv("all_proxy"):
                url = urlparse(proxy)
                host = str(url.hostname) if url.hostname else "localhost"
                port = url.port if url.port else 1080

            loop = asyncio.get_running_loop()
            res = await loop.getaddrinfo(
                host,
                port,
                type=SocketKind.SOCK_STREAM,
            )
            # We don't do round robin, ergo we only have
            # 1 result. That's fine here. The data structure
            # of the return value of getaddrinfo() is weird,
            # but it's documented in the python docs:
            # https://docs.python.org/3/library/socket.html
            addr_tuple = res[0]
            ip, port = addr_tuple[4][0], addr_tuple[4][1]
            return [
                "dumpcap",
                "-q",
                "-i",
                "any",
                "-w",
                "-",
                "-f",
                f"host {ip} and tcp port {port}",
            ]


if sys.platform == "win32":

    class Dumpcap:
        @classmethod
        async def start(
            cls,
            target: TargetURI,
            artifacts_dir: Path,
        ) -> Self | None:
            logger.warn("dumpcap is not available on windows")
            return None

        async def stop(self) -> None:
            pass

        async def sync(self) -> None:
            pass
