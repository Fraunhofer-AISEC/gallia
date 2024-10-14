# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import asyncio
from collections.abc import AsyncIterator

import pytest

from gallia.services.uds.core.client import UDSClient
from gallia.services.uds.core.exception import MissingResponse
from gallia.services.uds.core.service import PositiveResponse
from gallia.transports.base import BaseTransport, TargetURI
from gallia.transports.hsfz import HSFZConnection, HSFZTransport
from gallia.transports.tcp import TCPTransport

target = TargetURI("hsfz://localhost:6801?dst_addr=0x10&src_addr=0xf4")
listen_target = TargetURI("tcp://127.0.0.1:6801")


class TCPServer:
    def __init__(self) -> None:
        self.server: asyncio.Server
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

    async def close(self) -> None:
        self.server.close()
        await self.server.wait_closed()


@pytest.fixture()
async def dummy_server() -> AsyncIterator[TCPServer]:
    dummy_server = TCPServer()
    await dummy_server.listen(listen_target)
    yield dummy_server
    await dummy_server.close()


# FIXME: This is not a real hsfz server stack. If more than one connection is requested
# (aka. reconnects from the transport), the relevant test case might hang.
@pytest.fixture()
async def transports(dummy_server: TCPServer) -> AsyncIterator[tuple[BaseTransport, BaseTransport]]:
    hsfz_transport = await HSFZTransport.connect(target)
    dummy_transport = await dummy_server.accept()

    yield hsfz_transport, dummy_transport

    await hsfz_transport.close()
    await dummy_transport.close()


@pytest.mark.asyncio
async def test_reconnect_after_powercycle(dummy_server: TCPServer) -> None:
    hsfz_transport = await HSFZTransport.connect(target)
    dummy_transport = await dummy_server.accept()

    # Simulate powercycle.
    await dummy_transport.close()

    await hsfz_transport.reconnect()
    dummy_transport = await dummy_server.accept()

    await dummy_transport.close()
    await hsfz_transport.close()


@pytest.mark.asyncio
async def test_hsfz_timeout(transports: tuple[BaseTransport, BaseTransport]) -> None:
    hsfz_transport, _ = transports
    u = UDSClient(hsfz_transport, timeout=5)
    with pytest.raises(MissingResponse):
        await u.read_data_by_identifier(0x1234)


@pytest.mark.asyncio
async def test_hsfz_alive_check(transports: tuple[BaseTransport, BaseTransport]) -> None:
    _, dummy_transport = transports
    await dummy_transport.write(
        bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x12, 0xFF, 0xFF, 0xCA, 0xFF, 0xEE])
    )
    resp = await dummy_transport.read(4096)
    assert resp == bytes([0x00, 0x00, 0x00, 0x02, 0x00, 0x12, 0x00, 0xF4])


@pytest.mark.asyncio
async def test_hsfz_diagnose_request(transports: tuple[BaseTransport, BaseTransport]) -> None:
    hsfz_transport, dummy_transport = transports
    u = UDSClient(hsfz_transport, max_retry=0, timeout=1)
    task = asyncio.create_task(u.read_data_by_identifier(0x1234))
    await asyncio.sleep(0.5)
    # Send hsfz ack
    await dummy_transport.write(
        bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0xF4, 0x10, 0x22, 0x12, 0x34])
    )
    await asyncio.sleep(0.1)
    # Send caffee back.
    await dummy_transport.write(
        bytes(
            [
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x01,
                0x10,
                0xF4,
                0x62,
                0x12,
                0x34,
                0xCA,
                0xFF,
                0xEE,
            ]
        )
    )
    resp = await task
    assert isinstance(resp, PositiveResponse)
    assert resp.data_record == bytes([0xCA, 0xFF, 0xEE])


@pytest.mark.asyncio
async def test_request_pdu_mutex(transports: tuple[BaseTransport, BaseTransport]) -> None:
    # This test ensures that the uds send primitive request_pdu()
    # stays task safe. In other words, requests and responses
    # between task1 and task2 must not be mixed.
    hsfz_transport, dummy_transport = transports
    u = UDSClient(hsfz_transport, max_retry=0, timeout=1)
    task1 = asyncio.create_task(u.read_data_by_identifier(0x1234))
    task2 = asyncio.create_task(u.read_data_by_identifier(0x4321))
    for _ in range(2):
        req = await dummy_transport.read(4096)
        # Stupid check, but ok for this unit test.
        if req[9] == 0x12:
            # Send hsfz ack for task 1
            await dummy_transport.write(
                bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0xF4, 0x10, 0x22, 0x12, 0x34])
            )
        else:
            # Send hsfz ack for task 2
            await dummy_transport.write(
                bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0xF4, 0x10, 0x22, 0x43, 0x21])
            )
        await asyncio.sleep(0.1)
        # We did not have our morning coffee yet; send a response pending.
        await dummy_transport.write(
            bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x10, 0xF4, 0x7F, 0x22, 0x78])
        )
        await asyncio.sleep(0.3)
        if req[9] == 0x12:
            # Send caffee back.
            await dummy_transport.write(
                bytes(
                    [
                        0x00,
                        0x00,
                        0x00,
                        0x08,
                        0x00,
                        0x01,
                        0x10,
                        0xF4,
                        0x62,
                        0x12,
                        0x34,
                        0xCA,
                        0xFF,
                        0xEE,
                    ]
                )
            )
        else:
            # Send caeeff back.
            await dummy_transport.write(
                bytes(
                    [
                        0x00,
                        0x00,
                        0x00,
                        0x08,
                        0x00,
                        0x01,
                        0x10,
                        0xF4,
                        0x62,
                        0x43,
                        0x21,
                        0xCA,
                        0xEE,
                        0xFF,
                    ]
                )
            )

    resp = await task1
    assert isinstance(resp, PositiveResponse)
    assert resp.data_record == bytes([0xCA, 0xFF, 0xEE])

    resp = await task2
    assert isinstance(resp, PositiveResponse)
    assert resp.data_record == bytes([0xCA, 0xEE, 0xFF])


@pytest.mark.asyncio
async def test_unexpected_messages(transports: tuple[BaseTransport, BaseTransport]) -> None:
    hsfz_transport, dummy_transport = transports
    u = UDSClient(hsfz_transport, max_retry=0, timeout=1)
    task = asyncio.create_task(u.read_data_by_identifier(0x1234))

    await dummy_transport.read(4096)
    await dummy_transport.write(
        bytes([0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0xF4, 0x10, 0x22, 0x12, 0x34])
    )
    await dummy_transport.write(
        bytes(
            [
                # This message has the wrong hsfz dst address.
                # Must be ignored.
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x01,
                0x10,
                0xF5,
                0x62,
                0x12,
                0x34,
                0xCA,
                0xEE,
                0xFE,
            ]
        )
    )
    await dummy_transport.write(
        bytes(
            [
                0x00,
                0x00,
                0x00,
                0x08,
                0x00,
                0x01,
                0x10,
                0xF4,
                0x62,
                0x12,
                0x34,
                0xCA,
                0xEE,
                0xFF,
            ]
        )
    )
    resp = await task
    assert isinstance(resp, PositiveResponse)
    assert resp.data_record == bytes([0xCA, 0xEE, 0xFF])


@pytest.mark.asyncio
async def test_unread_messages(dummy_server: TCPServer) -> None:
    hsfz_conn = await HSFZConnection.connect("127.0.0.1", 6801, 0xF4, 0x10, 1.0)
    dummy_transport = await dummy_server.accept()

    tester_present = bytes([0x3E, 0x80])
    session_change = bytes([0x10, 0x01])

    # Write HSFZ ACK.
    await dummy_transport.write(
        bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0xF4, 0x10]) + tester_present
    )
    await dummy_transport.write(
        bytes(
            [
                0x00,
                0x00,
                0x00,
                0x05,
                0x00,
                0x01,
                0x10,
                0xF4,
                0xCA,
                0xFF,
                0xEE,
            ]
        )
    )
    await hsfz_conn.write_diag_request(tester_present)

    # Write HSFZ ACK.
    await dummy_transport.write(
        bytes([0x00, 0x00, 0x00, 0x04, 0x00, 0x02, 0xF4, 0x10]) + session_change
    )
    await dummy_transport.read(4096)
    frame = await hsfz_conn.read_frame()
    assert isinstance(frame, tuple)
    assert frame[2] == bytes([0xCA, 0xFF, 0xEE])
    await hsfz_conn.close()
