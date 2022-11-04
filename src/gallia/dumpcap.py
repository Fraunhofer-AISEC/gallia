# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import gzip
import io
import os
import shlex
import struct
from asyncio import subprocess
from datetime import datetime
from pathlib import Path
from socket import SocketKind
from typing import cast
from urllib.parse import urlparse

from gallia.log import Logger, get_logger
from gallia.transports import ISOTPTransport, RawCANTransport, TargetURI
from gallia.utils import auto_int, split_host_port


class Dumpcap:
    BUFSIZE = io.DEFAULT_BUFFER_SIZE

    def __init__(
        self,
        proc: subprocess.Process,
        logger: Logger,
        artifacts_dir: Path,
        outfile: Path,
        cleanup: int = 2,
    ) -> None:
        self.proc = proc
        self.logger = logger
        self.artifacts_dir = artifacts_dir
        self.outfile = outfile
        self.cleanup = cleanup
        self.ready_event = asyncio.Event()
        self.compressor = asyncio.create_task(self._compressor())

    @classmethod
    async def start(
        cls,
        target: TargetURI,
        artifacts_dir: Path,
    ) -> Dumpcap:
        logger = get_logger("dumpcap")

        ts = int(datetime.now().timestamp())
        if target.scheme in [ISOTPTransport.SCHEME, RawCANTransport.SCHEME]:
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
        else:
            outfile = artifacts_dir.joinpath(f"eth-{ts}.pcap.gz")
            cmd = await cls._eth_cmd(target.netloc)

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
            raise

        if proc.returncode:
            raise RuntimeError(
                f"dumpcap terminated with exit code: [{proc.returncode}]"
            )

        logger.info(f'Started "dumpcap": {cmd_str}')

        return cls(proc, logger, artifacts_dir, outfile)

    async def sync(self, timeout: float = 1) -> None:
        await asyncio.wait_for(self.ready_event.wait(), timeout)

    async def stop(self) -> None:
        await asyncio.sleep(self.cleanup)
        try:
            self.proc.terminate()
        except ProcessLookupError:
            self.logger.warning("dumpcap terminated before gallia")
        await self.proc.wait()
        await self.compressor

    async def _compressor(self) -> None:
        # Gzip support in aiofiles is missing.
        # https://github.com/Tinche/aiofiles/issues/46
        ready = False
        assert self.proc.stdout
        with await asyncio.to_thread(gzip.open, self.outfile, "wb") as f:  # type: ignore
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
    def _can_cmd(iface: str, src_addr: int | None, dst_addr: int | None) -> list[str]:
        args = ["dumpcap", "-q", "-i", iface, "-w", "-"]
        # Debug this with `dumpcap -d` or `tshark -x` to inspect the captured buffer.
        filter_ = "link[1] == 0x01"  # broadcast flag; ignore "sent by us" frames

        if src_addr is not None and dst_addr is not None:
            # TODO: Support extended CAN IDs
            if src_addr > 0x800 or dst_addr > 0x800:
                raise ValueError("Extended CAN IDs are currently not supported!")

            # Debug this with `dumpcap -d` or `tshark -x` to inspect the captured buffer.
            filter_ += (
                f"&& (link[16:2] == {Dumpcap._swap_bytes_16(src_addr):#x} "  # can_id is in little endian
                f"|| link[16:2] == {Dumpcap._swap_bytes_16(dst_addr):#x})"
            )
        args += ["-f", filter_]
        return args

    @staticmethod
    async def _eth_cmd(target_ip: str) -> list[str]:
        try:
            host, port = split_host_port(target_ip)
        except Exception as e:
            raise ValueError(f"Invalid argument for target ip: {target_ip}; {e}") from e

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
