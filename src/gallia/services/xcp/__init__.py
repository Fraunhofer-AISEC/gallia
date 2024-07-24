# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Any

assert sys.platform.startswith("linux"), "unsupported platform"

from gallia.log import get_logger
from gallia.services.xcp import types
from gallia.transports import BaseTransport
from gallia.transports.can import RawCANTransport

logger = get_logger(__name__)


class XCPService:
    def __init__(self, transport: BaseTransport, timeout: float = 1.0) -> None:
        self.timeout = timeout
        self.transport = transport
        # This uses construct types which would result in a new
        # dependency. Let's go with Any for this attribute.
        self.byte_order: Any

    async def request(self, data: bytes, timeout: float | None = None) -> bytes:
        t = timeout if timeout else self.timeout
        resp = await self.transport.request(data, t)
        header = types.Response.parse(resp)
        logger.info(header)
        if int(header.type) != 255:
            raise ValueError(f"Unknown response type: {header.type}, maybe no XCP packet?")
        # strip header byte
        return resp[1:]

    async def connect(self) -> None:
        logger.info("XCP CONNECT")
        resp = await self.request(bytes([0xFF, 0x00]))
        tmp = types.ConnectResponsePartial.parse(resp)
        self.byte_order = tmp.commModeBasic.byteOrder
        tmp = types.ConnectResponse.parse(resp, byteOrder=self.byte_order)
        logger.info(tmp)
        logger.result("XCP CONNECT -> OK")

    async def disconnect(self) -> None:
        logger.info("XCP DISCONNECT")
        resp = await self.request(bytes([0xFE, 0x00]))
        logger.info(resp)
        logger.result("XCP DISCONNECT -> OK")

    async def get_status(self) -> None:
        logger.info("XCP GET_STATUS")
        resp = await self.request(bytes([0xFD]))
        tmp = types.GetStatusResponse.parse(resp, byteOrder=self.byte_order)
        logger.info(tmp)
        logger.result("XCP GET_STATUS -> OK")

    async def get_comm_mode_info(self) -> None:
        logger.info("XCP GET_COMM_MODE_INFO")
        resp = await self.request(bytes([0xFB]))
        tmp = types.GetCommModeInfoResponse.parse(
            resp,
            byteOrder=self.byte_order,
        )
        logger.info(tmp)
        logger.result("XCP GET_COMM_MODE_INFO -> OK")

    async def get_id(self, id_: int) -> None:
        logger.info(f"XCP GET_ID({id_})")
        resp = await self.request(bytes([0xFA, id_]))
        tmp = types.GetIDResponse.parse(resp, byteOrder=self.byte_order)
        logger.info(tmp)
        logger.result(f"XCP GET_ID({id_}) -> OK")

    async def upload(self, length: int) -> None:
        logger.info(f"XCP GET_UPLOAD({length}")
        resp = await self.request(bytes([0xF5, length]))
        logger.info(resp)
        logger.result(f"XCP GET_UPLOAD({length} -> OK")


class CANXCPSerivce(XCPService):
    def __init__(
        self,
        transport: RawCANTransport,
        master_id: int,
        slave_id: int,
        timeout: float = 1.0,
    ):
        self.master_id = master_id
        self.slave_id = slave_id

        super().__init__(transport, timeout)

    async def request(self, data: bytes, timeout: float | None = None) -> bytes:
        t = timeout if timeout else self.timeout

        assert isinstance(self.transport, RawCANTransport)

        await self.transport.sendto(data, self.slave_id, t)
        while True:
            dst_, resp = await self.transport.recvfrom(t)

            if dst_ == self.master_id:
                break

        header = types.Response.parse(resp)
        logger.info(header)
        if int(header.type) != 255:
            raise ValueError(f"Unknown response type: {header.type}, maybe no XCP packet?")
        # strip header byte
        return resp[1:]
