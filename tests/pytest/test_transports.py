# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
import binascii
from collections.abc import AsyncIterator, Callable

import pytest

from gallia.log import setup_logging
from gallia.transports import BaseTransport, TargetURI, TCPLinesTransport, TCPTransport

listen_target = TargetURI("tcp://127.0.0.1:1234")
test_data = [b"hello" b"tcp"]


setup_logging()


class TCPServer:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[TCPTransport] = asyncio.Queue(1)

    async def _accept_cb(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await self.queue.put(TCPTransport(TargetURI("tcp://"), reader, writer))

    async def listen(self, target: TargetURI) -> None:
        self.server = await asyncio.start_server(
            self._accept_cb,
            host=target.hostname,
            port=target.port,
        )

    async def accept(self) -> TCPTransport:
        return await self.queue.get()

    def close(self) -> None:
        self.server.close()


async def _echo_test(
    client: BaseTransport,
    server: BaseTransport,
    line: bytes,
    converter: Callable[[bytes], bytes] | None = None,
) -> None:
    data = converter(line) if converter is not None else line

    await client.write(line)
    d = await server.read()
    assert data == d

    await server.write(data)
    d = await client.read()
    assert line == d


@pytest.fixture()
async def tcp_server() -> AsyncIterator[TCPServer]:
    tcp_server = TCPServer()
    await tcp_server.listen(listen_target)
    yield tcp_server
    tcp_server.close()


@pytest.mark.asyncio
async def test_tcp_wrong_scheme(tcp_server: TCPServer) -> None:
    with pytest.raises(ValueError):
        await TCPTransport.connect(TargetURI("foo://123"))


@pytest.mark.asyncio
async def test_tcp_reconnect(tcp_server: TCPServer) -> None:
    client = await TCPTransport.connect(listen_target)
    await tcp_server.accept()

    client = await client.reconnect()
    await tcp_server.accept()


@pytest.mark.asyncio
async def test_tcp_echo(tcp_server: TCPServer) -> None:
    client = await TCPTransport.connect(listen_target)
    server = await tcp_server.accept()

    for line in test_data:
        await _echo_test(client, server, line)


@pytest.mark.asyncio
async def test_tcp_linesep_echo(tcp_server: TCPServer) -> None:
    client = await TCPLinesTransport.connect(TargetURI("tcp-lines://127.0.0.1:1234"))
    server = await tcp_server.accept()

    def converter(data: bytes) -> bytes:
        return binascii.hexlify(data) + b"\n"

    for line in test_data:
        await _echo_test(client, server, line, converter)


@pytest.mark.asyncio
async def test_tcp_close(tcp_server: TCPServer) -> None:
    client = await TCPTransport.connect(listen_target)
    server = await tcp_server.accept()
    await client.close()
    await server.close()


@pytest.mark.asyncio
async def test_tcp_linesep_request(tcp_server: TCPServer) -> None:
    client = await TCPLinesTransport.connect(TargetURI("tcp-lines://127.0.0.1:1234"))
    server = await tcp_server.accept()

    await server.write(binascii.hexlify(b"world") + b"\n")
    resp = await client.request(b"hello")
    await server.read()
    assert resp == b"world"


@pytest.mark.asyncio
async def test_tcp_timeout(tcp_server: TCPServer) -> None:
    client = await TCPLinesTransport.connect(TargetURI("tcp-lines://127.0.0.1:1234"))
    server = await tcp_server.accept()

    async with asyncio.TaskGroup() as tg:
        tg.create_task(server.read())

        with pytest.raises(asyncio.TimeoutError):
            await client.request(b"hello", timeout=0.5)
