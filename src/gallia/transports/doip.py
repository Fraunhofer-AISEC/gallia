# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Any

from pydantic import BaseModel, field_validator

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import auto_int

logger = get_logger("gallia.transport.doip")


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
    UNDEFINED = -0x01
    UnknownSourceAddress = 0x00
    NoResources = 0x01
    InvalidConnectionEntry = 0x02
    AlreadyActive = 0x03
    AuthenticationMissing = 0x04
    ConfirmationRejected = 0x05
    UnsupportedActivationType = 0x06
    Success = 0x10
    SuccessConfirmationRequired = 0x11

    @classmethod
    def _missing_(cls, value: Any) -> RoutingActivationResponseCodes:
        return cls.UNDEFINED


class DoIPRoutingActivationDeniedError(ConnectionAbortedError):
    rac_code: RoutingActivationResponseCodes

    def __init__(self, rac_code: int):
        self.rac_code = RoutingActivationResponseCodes(rac_code)
        super().__init__(
            f"DoIP routing activation denied: {self.rac_code.name} ({rac_code})"
        )


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
    UNDEFINED = -0x01
    InvalidSourceAddress = 0x02
    UnknownTargetAddress = 0x03
    DiagnosticMessageTooLarge = 0x04
    OutOfMemory = 0x05
    TargetUnreachable = 0x06
    UnknownNetwork = 0x07
    TransportProtocolError = 0x08

    @classmethod
    def _missing_(cls, value: Any) -> DiagnosticMessageNegativeAckCodes:
        return cls.UNDEFINED


class DoIPNegativeAckError(BrokenPipeError):
    nack_code: DiagnosticMessageNegativeAckCodes

    def __init__(self, negative_ack_code: int):
        self.nack_code = DiagnosticMessageNegativeAckCodes(negative_ack_code)
        super().__init__(
            f"DoIP negative ACK received: {self.nack_code.name} ({negative_ack_code})"
        )


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
    DiagnosticMessageMessageAckTimeout = 2000
    RoutingActivationResponseTimeout = 2000
    DiagnosticMessageMessageTimeout = 2000
    TCPGeneralInactivityTimeout = 5000
    TCPInitialInactivityTimeout = 2000
    TCPAliveCheckTimeout = 500
    ProcessingTimeout = 2000
    VehicleDiscoveryTimeout = 5000


@dataclass
class GenericHeader:
    ProtocolVersion: int
    PayloadType: int
    PayloadLength: int

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
            payload_type,
            payload_length,
        )


@dataclass
class GenericHeaderNegativeAcknowledge:
    GenericHeaderNACKCode: GenericHeaderNACKCodes


@dataclass
class RoutingActivationRequest:
    SourceAddress: int
    ActivationType: int
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
    RoutingActivationResponseCode: int
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
        self.reader = reader
        self.writer = writer
        self.src_addr = src_addr
        self.target_addr = target_addr
        self._read_queue: asyncio.Queue[DoIPFrame] = asyncio.Queue()
        self._read_task = asyncio.create_task(self._read_worker())
        self._is_closed = False
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
            logger.debug("read worker cancelled")
        except asyncio.IncompleteReadError as e:
            logger.debug(f"read worker received EOF: {e}")
        except Exception as e:
            logger.critical(f"read worker died with {type(e)}: {e}")

    async def read_frame_unsafe(self) -> DoIPFrame:
        # Avoid waiting on the queue forever when
        # the connection has been terminated.
        if self._is_closed:
            raise ConnectionError()
        return await self._read_queue.get()

    async def read_frame(self) -> DoIPFrame:
        async with self._mutex:
            return await self.read_frame_unsafe()

    async def read_diag_request_raw(self) -> DoIPDiagFrame:
        unexpected_packets: list[tuple[Any, Any]] = []
        while True:
            hdr, payload = await self.read_frame()
            if not isinstance(payload, DiagnosticMessage):
                logger.warning(
                    f"expected DoIP DiagnosticMessage, instead got: {hdr} {payload}"
                )
                unexpected_packets.append((hdr, payload))
                continue
            if (
                payload.SourceAddress != self.target_addr
                or payload.TargetAddress != self.src_addr
            ):
                logger.warning(
                    f"DoIP-DiagnosticMessage: unexpected addresses (src:dst); expected {self.src_addr}:{self.target_addr} but got: {payload.SourceAddress:#04x}:{payload.TargetAddress:#04x}"
                )
                unexpected_packets.append((hdr, payload))
                continue

            # Do not consume unexpected packets, but re-add them to the queue for other consumers
            for item in unexpected_packets:
                await self._read_queue.put(item)

            return hdr, payload

    async def read_diag_request(self) -> bytes:
        _, payload = await self.read_diag_request_raw()
        return payload.UserData

    async def _read_ack(self, prev_data: bytes) -> None:
        unexpected_packets: list[tuple[Any, Any]] = []
        while True:
            hdr, payload = await self.read_frame_unsafe()
            if not isinstance(
                payload, DiagnosticMessagePositiveAcknowledgement
            ) and not isinstance(payload, DiagnosticMessageNegativeAcknowledgement):
                logger.warning(
                    f"expected DoIP positive/negative ACK, instead got: {hdr} {payload}"
                )
                unexpected_packets.append((hdr, payload))
                continue

            if (
                payload.SourceAddress != self.target_addr
                or payload.TargetAddress != self.src_addr
            ):
                logger.warning(
                    f"DoIP-ACK: unexpected addresses (src:dst); expected {self.src_addr}:{self.target_addr} but got: {payload.SourceAddress:#04x}:{payload.TargetAddress:#04x}"
                )
                unexpected_packets.append((hdr, payload))
                continue
            if (
                len(payload.PreviousDiagnosticMessageData) > 0
                and prev_data != payload.PreviousDiagnosticMessageData
            ):
                logger.warning("ack: previous data differs from request")
                logger.warning(
                    f"DoIP-ACK: got: {payload.PreviousDiagnosticMessageData.hex()} expected {prev_data.hex()}"
                )
                unexpected_packets.append((hdr, payload))
                continue

            # Do not consume unexpected packets, but re-add them to the queue for other consumers
            for item in unexpected_packets:
                await self._read_queue.put(item)

            if isinstance(payload, DiagnosticMessageNegativeAcknowledgement):
                raise DoIPNegativeAckError(payload.ACKCode)
            return

    async def _read_routing_activation_response(self) -> None:
        unexpected_packets: list[tuple[Any, Any]] = []
        while True:
            hdr, payload = await self.read_frame_unsafe()
            if not isinstance(payload, RoutingActivationResponse):
                logger.warning(
                    f"expected DoIP RoutingActivationResponse, instead got: {hdr} {payload}"
                )
                unexpected_packets.append((hdr, payload))
                continue

            # Do not consume unexpected packets, but re-add them to the queue for other consumers
            for item in unexpected_packets:
                await self._read_queue.put(item)

            if (
                payload.RoutingActivationResponseCode
                != RoutingActivationResponseCodes.Success
            ):
                raise DoIPRoutingActivationDeniedError(
                    payload.RoutingActivationResponseCode
                )
            return

    async def write_request_raw(self, hdr: GenericHeader, payload: DoIPOutData) -> None:
        async with self._mutex:
            buf = b""
            buf += hdr.pack()
            buf += payload.pack()
            self.writer.write(buf)
            await self.writer.drain()

            logger.trace(f"hdr: {hdr}, payload: {payload}")

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
                            TimingAndCommunicationParameters.RoutingActivationResponseTimeout
                            / 1000,
                        )
            except asyncio.TimeoutError as e:
                await self.close()
                raise BrokenPipeError(
                    "Timeout while waiting for DoIP ACK message"
                ) from e

    async def write_diag_request(self, data: bytes) -> None:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.DiagnosticMessage,
            PayloadLength=len(data) + 4,
        )
        payload = DiagnosticMessage(
            SourceAddress=self.src_addr,
            TargetAddress=self.target_addr,
            UserData=data,
        )
        await self.write_request_raw(hdr, payload)

    async def write_routing_activation_request(
        self,
        activation_type: int,
    ) -> None:
        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.RoutingActivationRequest,
            PayloadLength=7,
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
        )
        payload = AliveCheckResponse(
            SourceAddress=self.src_addr,
        )
        await self.write_request_raw(hdr, payload)

    async def close(self) -> None:
        if self._is_closed:
            return
        self._is_closed = True
        self._read_task.cancel()
        self.writer.close()
        await self.writer.wait_closed()


class DoIPConfig(BaseModel):
    src_addr: int
    target_addr: int
    activation_type: int = RoutingActivationRequestTypes.WWH_OBD.value

    @field_validator(
        "src_addr",
        "target_addr",
        "activation_type",
        mode="before",
    )
    def auto_int(cls, v: str) -> int:
        return auto_int(v)


class DoIPTransport(BaseTransport, scheme="doip"):
    def __init__(
        self,
        target: TargetURI,
        port: int,
        config: DoIPConfig,
        conn: DoIPConnection,
    ):
        super().__init__(target)
        self.port = port
        self.config = config
        self._conn = conn
        self._is_closed = False

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
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> DoIPTransport:
        t = target if isinstance(target, TargetURI) else TargetURI(target)
        cls.check_scheme(t)

        if t.hostname is None:
            raise ValueError("no hostname specified")

        port = t.port if t.port is not None else 13400
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
        if self._is_closed:
            return
        self._is_closed = True
        await self._conn.close()

    async def read(
        self,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> bytes:
        data = await asyncio.wait_for(self._conn.read_diag_request(), timeout)

        t = tags + ["read"] if tags is not None else ["read"]
        logger.trace(data.hex(), extra={"tags": t})
        return data

    async def write(
        self,
        data: bytes,
        timeout: float | None = None,
        tags: list[str] | None = None,
    ) -> int:
        t = tags + ["write"] if tags is not None else ["write"]
        logger.trace(data.hex(), extra={"tags": t})

        try:
            await asyncio.wait_for(self._conn.write_diag_request(data), timeout)
        except DoIPNegativeAckError as e:
            if e.nack_code != DiagnosticMessageNegativeAckCodes.TargetUnreachable:
                raise e
            # TargetUnreachable can be just a temporary issue. Thus, we do not raise
            # BrokenPipeError but instead ignore it here and let upper layers handle
            # missing responses (i.e. raise a TimeoutError instead)
            logger.debug("DoIP message was ACKed with TargetUnreachable")
            raise asyncio.TimeoutError from e

        return len(data)
