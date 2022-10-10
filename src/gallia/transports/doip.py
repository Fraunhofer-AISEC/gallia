# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum, unique

from pydantic import BaseModel

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI


@unique
class ProtocolVersions(IntEnum):
    ISO_13400_2_2010 = 0x01
    ISO_13400_2_2012 = 0x02


@unique
class RoutingActivationRequestTypes(IntEnum):
    Default = 0x00
    WWH_OBD = 0x01
    CentralSecurity = 0xE0


@unique
class RoutingActivationResponseCodes(IntEnum):
    UnknownSourceAddress = 0x00
    NoRessources = 0x01
    InvalidConnectionEntry = 0x02
    AlreadyActived = 0x03
    AuthenticationMissing = 0x04
    ConfirmationRejected = 0x05
    UnsupportedActivationType = 0x06
    Success = 0x10
    SuccessConfirmationRequired = 0x11


@unique
class PayloadTypes(IntEnum):
    NegativeAcknowledge = 0x0000
    VehicleIdentificationRequestMessage = 0x0002
    VehicleIdentificationRequestMessageWithEID = 0x0003
    VehicleIdentificationRequestMessageWithVIN = 0x0004
    RoutingActivationRequest = 0x0005
    RoutingActivationResponse = 0x0006
    AliveCheckRequest = 0x0007
    AliveCheckResponse = 0x0008
    DoIPEntityStatusRequest = 0x4001
    DoIPEntityStatusResponse = 0x4002
    DiagnosticMessage = 0x8001
    DiagnosticMessagePositiveAcknowledgement = 0x8002
    DiagnosticMessageNegativeAcknowledgement = 0x8003


@unique
class DiagnosticMessagePositiveAckCodes(IntEnum):
    Success = 0x00


@unique
class DiagnosticMessageNegativeAckCodes(IntEnum):
    InvalidSourceAddress = 0x02
    UnknownTargetAddress = 0x03
    DiagnosticMessageTooLarge = 0x04
    OutOfMemory = 0x05
    TargetUnreachable = 0x06
    UnknownNetwork = 0x07
    TransportProtocolError = 0x08


@unique
class GenericHeaderNACKCodes(IntEnum):
    IncorrectPatternFormat = 0x01
    UnknownPayloadType = 0x02
    MessageTooLarge = 0x03
    OutOfMemory = 0x04
    InvalidPayloadLength = 0x05


class TimingAndCommunicationParameters(IntEnum):
    CtrlTimeout = 2000
    AnnounceWait = 500
    AnnounceInterval = 500
    AnnounceNum = 3
    DiagnosticMessageMessageAckTimeout = 50
    DiagnosticMessageMessageTimeout = 2000
    TCPGeneralInactivityTimeout = 5000
    TCPInitalInactivityTimeout = 2000
    TCPAliveCheckTimeout = 500
    ProcessingTimeout = 2000
    VecicleDiscoveryTimeout = 5000


@dataclass
class GenericHeader:
    ProtocolVersion: ProtocolVersions
    PayloadType: PayloadTypes
    PayloadLength: int
    PayloadTypeSpecificMessageContent: bytes

    def pack(self) -> bytes:
        return struct.pack(
            "!BBHL",
            self.ProtocolVersion,
            self.ProtocolVersion ^ 0xFF,
            self.PayloadType,
            self.PayloadLength,
        )

    @classmethod
    def unpack(cls, data: bytes) -> GenericHeader:
        (
            protocol_version,
            inverse_protocol_version,
            payload_type,
            payload_length,
        ) = struct.unpack("!BBHL", data)
        if protocol_version != inverse_protocol_version ^ 0xFF:
            raise ValueError("inverse protocol_version is invalid")
        return cls(
            protocol_version,
            PayloadTypes(payload_type),
            payload_length,
            b"",
        )


@dataclass
class GenericHeaderNegativeAcknowledge:
    GenericHeaderNACKCode: GenericHeaderNACKCodes


@dataclass
class RoutingActivationRequest:
    SourceAddress: int
    ActivationType: RoutingActivationRequestTypes
    Reserved: int = 0x00000000  # Not used, default value.
    # OEMReserved uint32

    def pack(self) -> bytes:
        return struct.pack(
            "!HBI", self.SourceAddress, self.ActivationType, self.Reserved
        )


@dataclass
class RoutingActivationResponse:
    SourceAddress: int
    TargetAddress: int
    RoutingActivationResponseCode: RoutingActivationResponseCodes
    Reserved: int = 0x00000000  # Not used, default value.
    # OEMReserved uint32

    @classmethod
    def unpack(cls, data: bytes) -> RoutingActivationResponse:
        (
            source_address,
            target_address,
            routing_activation_response_code,
            reserved,
        ) = struct.unpack("!HHBI", data)
        if reserved != 0x00000000:
            raise ValueError("reserved field contains data")
        return cls(
            source_address,
            target_address,
            routing_activation_response_code,
            reserved,
        )


@dataclass
class DiagnosticMessage:
    SourceAddress: int
    TargetAddress: int
    UserData: bytes

    def pack(self) -> bytes:
        return (
            struct.pack(
                "!HH",
                self.SourceAddress,
                self.TargetAddress,
            )
            + self.UserData
        )

    @classmethod
    def unpack(cls, data: bytes) -> DiagnosticMessage:
        source_address, target_address = struct.unpack("!HH", data[:4])
        data = data[4:]
        return cls(source_address, target_address, data)


@dataclass
class DiagnosticMessageAcknowledgement:
    SourceAddress: int
    TargetAddress: int
    ACKCode: int
    PreviousDiagnosticMessageData: bytes

    def pack(self) -> bytes:
        return (
            struct.pack(
                "!HHB",
                self.SourceAddress,
                self.TargetAddress,
                self.ACKCode,
            )
            + self.PreviousDiagnosticMessageData
        )


class DiagnosticMessagePositiveAcknowledgement(DiagnosticMessageAcknowledgement):
    ACKCode: DiagnosticMessagePositiveAckCodes

    @classmethod
    def unpack(cls, data: bytes) -> DiagnosticMessagePositiveAcknowledgement:
        source_address, target_address, ack_code = struct.unpack("!HHB", data[:5])
        prev_data = data[5:]

        return cls(
            source_address,
            target_address,
            DiagnosticMessagePositiveAckCodes(ack_code),
            prev_data,
        )


class DiagnosticMessageNegativeAcknowledgement(DiagnosticMessageAcknowledgement):
    ACKCode: DiagnosticMessageNegativeAckCodes

    @classmethod
    def unpack(cls, data: bytes) -> DiagnosticMessageNegativeAcknowledgement:
        source_address, target_address, ack_code = struct.unpack("!HHB", data[:5])
        prev_data = data[5:]

        return cls(
            source_address,
            target_address,
            DiagnosticMessageNegativeAckCodes(ack_code),
            prev_data,
        )


@dataclass
class AliveCheckRequest:
    pass


@dataclass
class AliveCheckResponse:
    SourceAddress: int

    def pack(self) -> bytes:
        return struct.pack("!H", self.SourceAddress)


# Messages expected to be sent by the DoIP gateway.
DoIPInData = (
    RoutingActivationResponse
    | DiagnosticMessage
    | DiagnosticMessagePositiveAcknowledgement
    | DiagnosticMessageNegativeAcknowledgement
    | AliveCheckRequest
)

# Messages expected to be sent by us.
DoIPOutData = RoutingActivationRequest | DiagnosticMessage | AliveCheckResponse

DoIPFrame = tuple[
    GenericHeader,
    DoIPInData | DoIPOutData,
]
DoIPDiagFrame = tuple[GenericHeader, DiagnosticMessage]


class DoIPConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        src_addr: int,
        target_addr: int,
    ):
        self.logger = get_logger("doip")
        self.reader = reader
        self.writer = writer
        self.src_addr = src_addr
        self.target_addr = target_addr
        self._read_queue: asyncio.Queue[DoIPFrame] = asyncio.Queue()
        self._read_task = asyncio.create_task(self._read_worker())
        self._closed = False
        self._mutex = asyncio.Lock()

    @classmethod
    async def connect(
        cls,
        host: str,
        port: int,
        src_addr: int,
        target_addr: int,
    ) -> DoIPConnection:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer, src_addr, target_addr)

    async def _read_frame(self) -> DoIPFrame:
        # Header is fixed size 8 byte.
        hdr_buf = await self.reader.readexactly(8)
        hdr = GenericHeader.unpack(hdr_buf)

        payload_buf = await self.reader.readexactly(hdr.PayloadLength)
        payload: DoIPInData
        match hdr.PayloadType:
            case PayloadTypes.RoutingActivationResponse:
                payload = RoutingActivationResponse.unpack(payload_buf)
            case PayloadTypes.DiagnosticMessagePositiveAcknowledgement:
                payload = DiagnosticMessagePositiveAcknowledgement.unpack(payload_buf)
            case PayloadTypes.DiagnosticMessageNegativeAcknowledgement:
                payload = DiagnosticMessageNegativeAcknowledgement.unpack(payload_buf)
            case PayloadTypes.DiagnosticMessage:
                payload = DiagnosticMessage.unpack(payload_buf)
            case PayloadTypes.AliveCheckRequest:
                payload = AliveCheckRequest()
            case _:
                raise BrokenPipeError(
                    f"unexpected DoIP message: {hdr} {payload_buf.hex()}"
                )
        return hdr, payload

    async def _read_worker(self) -> None:
        try:
            while True:
                hdr, data = await self._read_frame()
                if hdr.PayloadType == PayloadTypes.DiagnosticMessage and isinstance(
                    data, AliveCheckRequest
                ):
                    await self.write_alive_check_response()
                    continue
                await self._read_queue.put((hdr, data))
        except asyncio.CancelledError:
            self.logger.debug("read worker cancelled")

    async def read_frame_unsafe(self) -> DoIPFrame:
        # Avoid waiting on the queue forever when
        # the connection has been terminated.
        if self._closed:
            raise ConnectionError()
        return await self._read_queue.get()

    async def read_frame(self) -> DoIPFrame:
        async with self._mutex:
            return await self.read_frame_unsafe()

    async def read_diag_request_raw(self) -> DoIPDiagFrame:
        while True:
            hdr, payload = await self.read_frame()
            if not isinstance(payload, DiagnosticMessage):
                raise BrokenPipeError(f"unexpected DoIP message: {hdr} {payload}")
            if payload.SourceAddress != self.target_addr:
                self.logger.warning(
                    f"unexpected DoIP src address: {payload.SourceAddress:#04x}"
                )
                continue
            if payload.TargetAddress != self.src_addr:
                self.logger.warning(
                    f"unexpected DoIP target address: {payload.TargetAddress:#04x}"
                )
                continue
            return hdr, payload

    async def read_diag_request(self) -> bytes:
        _, payload = await self.read_diag_request_raw()
        return payload.UserData

    async def _read_ack(self, prev_data: bytes) -> None:
        hdr, payload = await self.read_frame_unsafe()
        if isinstance(payload, DiagnosticMessageNegativeAcknowledgement):
            raise BrokenPipeError(f"request denied: {hdr} {payload}")
        if not isinstance(payload, DiagnosticMessagePositiveAcknowledgement):
            raise BrokenPipeError(
                f"unexpected DoIP message: {hdr} {payload}, expected positive ACK"
            )

        if payload.SourceAddress != self.target_addr:
            self.logger.warning(
                f"ack: unexpected src_addr: {payload.SourceAddress:#04x}"
            )
        if payload.TargetAddress != self.src_addr:
            self.logger.warning(
                f"ack: unexpected dst_addr: {payload.TargetAddress:#04x}"
            )
        if (
            len(payload.PreviousDiagnosticMessageData) > 0
            and prev_data != payload.PreviousDiagnosticMessageData
        ):
            self.logger.warning("ack: previous data differs from request")
            self.logger.warning(
                f"ack: got: {payload.PreviousDiagnosticMessageData.hex()} expected {prev_data.hex()}"
            )

    async def _read_routing_activation_response(self) -> None:
        hdr, payload = await self.read_frame_unsafe()
        if hdr.PayloadType != PayloadTypes.RoutingActivationResponse or not isinstance(
            payload, RoutingActivationResponse
        ):
            raise BrokenPipeError(f"unexpected DoIP message: {hdr} {payload}")

        if (
            payload.RoutingActivationResponseCode
            != RoutingActivationResponseCodes.Success
        ):
            try:
                code = RoutingActivationResponseCodes(
                    payload.RoutingActivationResponseCode
                )
            except ValueError as e:
                raise ConnectionAbortedError(
                    f"unknown routing_activation_response_code: {payload.RoutingActivationResponseCode}"
                ) from e
            raise ConnectionAbortedError(f"routing activation denied: {code}")

    async def write_request_raw(self, hdr: GenericHeader, payload: DoIPOutData) -> None:
        async with self._mutex:
            buf = b""
            buf += hdr.pack()
            buf += payload.pack()
            self.writer.write(buf)
            await self.writer.drain()

            self.logger.trace(f"hdr: {hdr}, payload: {payload}")

            try:
                match payload:
                    case DiagnosticMessage():
                        # Now an ACK message is expected.
                        await asyncio.wait_for(
                            self._read_ack(payload.UserData),
                            TimingAndCommunicationParameters.DiagnosticMessageMessageAckTimeout
                            / 1000,
                        )
                    case RoutingActivationRequest():
                        await asyncio.wait_for(
                            self._read_routing_activation_response(),
                            TimingAndCommunicationParameters.DiagnosticMessageMessageAckTimeout
                            / 1000,
                        )
            except asyncio.TimeoutError as e:
                await self.close()
                raise BrokenPipeError() from e

    async def write_diag_request(self, data: bytes) -> None:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.DiagnosticMessage,
            PayloadLength=len(data) + 4,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = DiagnosticMessage(
            SourceAddress=self.src_addr,
            TargetAddress=self.target_addr,
            UserData=data,
        )
        await self.write_request_raw(hdr, payload)

    async def write_routing_activation_request(
        self,
        activation_type: RoutingActivationRequestTypes,
    ) -> None:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.RoutingActivationRequest,
            PayloadLength=7,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = RoutingActivationRequest(
            SourceAddress=self.src_addr,
            ActivationType=activation_type,
            Reserved=0x00,
        )
        await self.write_request_raw(hdr, payload)

    async def write_alive_check_response(self) -> None:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.AliveCheckResponse,
            PayloadLength=2,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = AliveCheckResponse(
            SourceAddress=self.src_addr,
        )
        await self.write_request_raw(hdr, payload)

    async def close(self) -> None:
        self._read_task.cancel()
        self.writer.close()
        await self.writer.wait_closed()


class DoIPConfig(BaseModel):
    src_addr: int
    target_addr: int
    activation_type: int = RoutingActivationRequestTypes.WWH_OBD.value


class DoIPTransport(BaseTransport, scheme="doip"):
    def __init__(
        self, target: TargetURI, port: int, config: DoIPConfig, conn: DoIPConnection
    ):
        super().__init__(target)
        self.port = port
        self.config = config
        self._conn = conn

    @staticmethod
    async def _connect(
        hostname: str,
        port: int,
        src_addr: int,
        target_addr: int,
        activation_type: int,
    ) -> DoIPConnection:
        conn = await DoIPConnection.connect(
            hostname,
            port,
            src_addr,
            target_addr,
        )
        await conn.write_routing_activation_request(
            RoutingActivationRequestTypes(activation_type)
        )
        return conn

    @classmethod
    async def connect(
        cls, target: str | TargetURI, timeout: float | None = None
    ) -> DoIPTransport:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        cls.check_scheme(t)

        if t.hostname is None:
            raise ValueError("no hostname specified")

        port = t.port if t.port is not None else 6801
        config = DoIPConfig(**t.qs_flat)
        conn = await asyncio.wait_for(
            cls._connect(
                t.hostname,
                port,
                config.src_addr,
                config.target_addr,
                config.activation_type,
            ),
            timeout,
        )
        return cls(t, port, config, conn)

    async def close(self) -> None:
        self.is_closed = True
        await self._conn.close()

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await asyncio.wait_for(self._conn.read_diag_request(), timeout)

        t = tags + ["read"] if tags is not None else ["read"]
        self.logger.trace(data.hex(), extra={"tags": t})
        return data

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        await asyncio.wait_for(self._conn.write_diag_request(data), timeout)

        t = tags + ["read"] if tags is not None else ["read"]
        self.logger.trace(data.hex(), extra={"tags": t})
        return len(data)
