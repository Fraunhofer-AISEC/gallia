# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Optional

from gallia.services.xcp import types

from gallia.penlog import Logger
from gallia.transports.base import BaseTransport


class XCPService:
    def __init__(self, transport: BaseTransport, timeout: float = 1.0) -> None:
        self.logger = Logger("xcp", flush=True)
        self.timeout = timeout
        self.transport = transport
        # This uses construct types which would result in a new
        # dependency. Let's go with Any for this attribute.
        self.byte_order: Any

    async def request(self, data: bytes, timeout: Optional[float] = None) -> bytes:
        t = timeout if timeout else self.timeout
        resp = await self.transport.request(data, t)
        header = types.Response.parse(resp)
        self.logger.log_info(header)
        if int(header.type) != 255:
            raise ValueError(
                f"Unknown response type: {header.type}, maybe no XCP packet?"
            )
        # strip header byte
        return resp[1:]

    async def connect(self) -> None:
        self.logger.log_info("XCP CONNECT")
        resp = await self.request(bytes([0xFF, 0x00]))
        tmp = types.ConnectResponsePartial.parse(resp)
        self.byte_order = tmp.commModeBasic.byteOrder
        tmp = types.ConnectResponse.parse(resp, byteOrder=self.byte_order)
        self.logger.log_info(tmp)
        self.logger.log_summary("XCP CONNECT -> OK")

    async def disconnect(self) -> None:
        self.logger.log_info("XCP DISCONNECT")
        resp = await self.request(bytes([0xFE, 0x00]))
        self.logger.log_info(resp)
        self.logger.log_summary("XCP DISCONNECT -> OK")

    async def get_status(self) -> None:
        self.logger.log_info("XCP GET_STATUS")
        resp = await self.request(bytes([0xFD]))
        tmp = types.GetStatusResponse.parse(resp, byteOrder=self.byte_order)
        self.logger.log_info(tmp)
        self.logger.log_summary("XCP GET_STATUS -> OK")

    async def get_comm_mode_info(self) -> None:
        self.logger.log_info("XCP GET_COMM_MODE_INFO")
        resp = await self.request(bytes([0xFB]))
        tmp = types.GetCommModeInfoResponse.parse(
            resp,
            byteOrder=self.byte_order,
        )
        self.logger.log_info(tmp)
        self.logger.log_summary("XCP GET_COMM_MODE_INFO -> OK")

    async def get_id(self, id_: int) -> None:
        self.logger.log_info(f"XCP GET_ID({id_})")
        resp = await self.request(bytes([0xFA, id_]))
        tmp = types.GetIDResponse.parse(resp, byteOrder=self.byte_order)
        self.logger.log_info(tmp)
        self.logger.log_summary(f"XCP GET_ID({id_}) -> OK")

    async def upload(self, length: int) -> None:
        self.logger.log_info(f"XCP GET_UPLOAD({length}")
        resp = await self.request(bytes([0xF5, length]))
        self.logger.log_info(resp)
        self.logger.log_summary(f"XCP GET_UPLOAD({length} -> OK")
