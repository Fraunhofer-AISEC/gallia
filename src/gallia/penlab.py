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
from functools import partial
from pathlib import Path
from socket import SocketKind  # pylint: disable=no-name-in-module
from typing import Callable, Optional, Union
from urllib.parse import urlparse

from opennetzteil import Netzteil

from gallia.penlog import Logger
from gallia.transports.base import TargetURI
from gallia.transports.can import ISOTPTransport, RawCANTransport
from gallia.utils import split_host_port, g_repr


class PowerSupplyURI(TargetURI):
    def __init__(self, raw: str) -> None:
        super().__init__(raw)
        if "id" not in self.qs:
            raise ValueError("id is missing in power-supply URI")
        if "channel" not in self.qs:
            raise ValueError("channel is missing in power-supply URI")

    @property
    def id(self) -> int:
        return int(self.qs["id"][0], 0)

    @property
    def channel(self) -> Union[int, list[int]]:
        if len(ch := self.qs["channel"]) == 1:
            return int(ch[0], 0)
        return list(map(partial(int, base=0), ch))


class PowerSupply:
    def __init__(self, channel_id: Union[int, list[int]], client: Netzteil) -> None:
        self.logger = Logger("penlab.experiment", flush=True)
        self.channel_id = channel_id
        self.netzteil = client
        self.mutex = asyncio.Lock()

    @classmethod
    async def connect(cls, target: PowerSupplyURI) -> PowerSupply:
        client = await Netzteil.connect(target.location, target.id)
        return cls(target.channel, client)

    async def _power(self, op: bool) -> None:
        assert self.netzteil
        if isinstance(self.channel_id, list):
            for id_ in self.channel_id:
                await self.netzteil.set_channel(id_, op)
        elif isinstance(self.channel_id, int):
            await self.netzteil.set_channel(self.channel_id, op)

    async def power_up(self) -> None:
        self.logger.log_info("power up experiment")
        await self._power(True)

    async def power_down(self) -> None:
        self.logger.log_info("power down experiment")
        await self._power(False)

    async def power_cycle(
        self,
        sleep: float = 2.0,
        callback: Optional[Callable] = None,
    ) -> None:
        async with self.mutex:
            await self.power_down()
            await asyncio.sleep(sleep)
            await self.power_up()
            if callback:
                await callback()


class Dumpcap:
    BUFSIZE = io.DEFAULT_BUFFER_SIZE

    def __init__(
        self,
        proc: subprocess.Process,  # pylint: disable=no-member
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
        artifacts_dir: Optional[os.PathLike] = None,
    ) -> Dumpcap:
        logger = Logger("penlab.dumpcap", flush=True)

        if artifacts_dir:
            artifacts_dir = Path(artifacts_dir)
        elif path := os.environ.get("PENRUN_ARTIFACTS"):
            artifacts_dir = Path(path)
        else:
            raise ValueError("no artifacts dir set")

        ts = int(datetime.now().timestamp())
        if target.scheme in [ISOTPTransport.SCHEME, RawCANTransport.SCHEME]:
            outfile = artifacts_dir.joinpath(f"candump-{ts}.pcap.gz")
            cmd = cls._can_cmd(target.netloc, target.src_addr, target.dst_addr)
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
            logger.log_error(f"Could not start dumpcap: ({g_repr(e)})")
            raise

        if proc.returncode:
            raise RuntimeError(
                f"dumpcap terminated with exit code: [{proc.returncode}]"
            )

        logger.log_preamble(f'Started "dumpcap": {cmd_str}')

        return cls(proc, logger, artifacts_dir, outfile)

    async def sync(self, timeout: float = 1) -> None:
        await asyncio.wait_for(self.ready_event.wait(), timeout)

    async def stop(self) -> None:
        await asyncio.sleep(self.cleanup)
        self.proc.terminate()
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
        return struct.unpack(">H", struct.pack("<H", x))[0]

    @staticmethod
    def _can_cmd(
        iface: str, src_addr: Optional[int], dst_addr: Optional[int]
    ) -> list[str]:
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
