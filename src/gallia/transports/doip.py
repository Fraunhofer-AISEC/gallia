from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import cast, Optional, TypedDict, Union

from gallia.penlog import Logger
from gallia.transports.base import BaseTransport, _int_spec, TargetURI


class ProtocolVersions(IntEnum):
    ISO_13400_2_2010 = 0x01
    ISO_13400_2_2012 = 0x02


class RoutingActivationRequestTypes(IntEnum):
    Default = 0x00
    WWH_OBD = 0x01
    CentralSecurity = 0xE0


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
    DoIPEntityStatusResponse = 0x4001
    DiagnosticMessage = 0x8001
    DiagnosticMessagePositiveAcknowledgement = 0x8002
    DiagnosticMessageNegativeAcknowledgement = 0x8003


class DiagnosticMessagePositiveAckCodes(IntEnum):
    Success = 0x00


class DiagnosticMessageNegativeAckCodes(IntEnum):
    InvalidSourceAddress = 0x02
    UnknownTargetAddress = 0x03
    DiagnosticMessageTooLarge = 0x04
    OutOfMemory = 0x05
    TargetUnreachable = 0x06
    UnknownNetwork = 0x07
    TransportProtocolError = 0x08


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
            inverse_protocol_version,
            PayloadTypes(payload_type),
            payload_length,
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
            source_address, target_address, routing_activation_response_code, reserved
        )


@dataclass
class DiagnosticMessage:
    SourceAddress: int
    TargetAddress: int
    UserData: bytes

    def pack(self) -> bytes:
        return struct.pack(
            "!HHp", self.SourceAddress, self.TargetAddress, self.UserData
        )

    @classmethod
    def unpack(cls, data: bytes) -> DiagnosticMessage:
        source_address, target_address, data = struct.unpack("!HHp", data)
        return cls(source_address, target_address, data)


@dataclass
class DiagnosticMessageAcknowledgement:
    SourceAddress: int
    TargetAddress: int
    ACKCode: int
    PreviousDiagnosticMessageData: bytes

    def pack(self) -> bytes:
        return struct.pack(
            "!HHBp",
            self.SourceAddress,
            self.TargetAddress,
            self.ACKCode,
            self.PreviousDiagnosticMessageData,
        )


class DiagnosticMessagePositiveAcknowledgement(DiagnosticMessageAcknowledgement):
    ACKCode: DiagnosticMessagePositiveAckCodes

    @classmethod
    def unpack(cls, data: bytes) -> DiagnosticMessagePositiveAcknowledgement:
        source_address, target_address, ack_code, prev_data = struct.unpack(
            "!HHBp", data
        )
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
        source_address, target_address, ack_code, prev_data = struct.unpack(
            "!HHBp", data
        )
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
DoIPInData = Union[
    RoutingActivationResponse,
    DiagnosticMessage,
    DiagnosticMessagePositiveAcknowledgement,
    DiagnosticMessageNegativeAcknowledgement,
    AliveCheckRequest,
]
# Messages expected to be sent by us.
DoIPOutData = Union[
    RoutingActivationRequest,
    DiagnosticMessage,
    AliveCheckResponse,
]
DoIPFrame = tuple[
    GenericHeader,
    Union[DoIPInData, DoIPOutData],
]
DoIPDiagFrame = tuple[GenericHeader, DiagnosticMessage]


class DoIPConnection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        src_addr: Optional[int],
        target_addr: Optional[int],
        activation_type: RoutingActivationRequestTypes,
    ):
        self.logger = Logger(component="doip", flush=True)
        self.reader = reader
        self.writer = writer
        self.src_addr = src_addr
        self.target_addr = target_addr
        self.activation_type = activation_type
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
        activation_type: RoutingActivationRequestTypes,
    ) -> DoIPConnection:
        reader, writer = await asyncio.open_connection(host, port)
        return cls(reader, writer, src_addr, target_addr, activation_type)

    async def _read_frame(self) -> DoIPFrame:
        # Header is fixed size 8 byte.
        hdr_buf = await self.reader.readexactly(8)
        hdr = GenericHeader.unpack(hdr_buf)

        payload_buf = await self.reader.readexactly(hdr.PayloadLength)
        payload: DoIPInData
        if hdr.PayloadType == PayloadTypes.RoutingActivationResponse:
            payload = RoutingActivationResponse.unpack(payload_buf)
        elif hdr.PayloadType == PayloadTypes.DiagnosticMessagePositiveAcknowledgement:
            payload = DiagnosticMessagePositiveAcknowledgement.unpack(payload_buf)
        elif hdr.PayloadType == PayloadTypes.DiagnosticMessageNegativeAcknowledgement:
            payload = DiagnosticMessageNegativeAcknowledgement.unpack(payload_buf)
        elif hdr.PayloadType == PayloadTypes.DiagnosticMessage:
            payload = DiagnosticMessage.unpack(payload_buf)
        elif hdr.PayloadType == PayloadTypes.AliveCheckRequest:
            payload = AliveCheckRequest()
        else:
            raise BrokenPipeError(f"unexpected DoIP message: {hdr} {payload}")
        self.logger.log_trace(f"hdr: {hdr}, data: {payload}")
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
            self.logger.log_debug("read worker cancelled")

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
                self.logger.log_warning(
                    f"unexpected DoIP src address: {payload.SourceAddress:#04x}"
                )
                continue
            if payload.TargetAddress != self.src_addr:
                self.logger.log_warning(
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

        if payload.SourceAddress != self.src_addr:
            self.logger.log_warning(
                f"ack: unexpected src_addr: {payload.SourceAddress:#04x}"
            )
        if payload.TargetAddress != self.target_addr:
            self.logger.log_warning(
                f"ack: unexpected dst_addr: {payload.TargetAddress:#04x}"
            )
        if prev_data != payload.PreviousDiagnosticMessageData:
            self.logger.log_warning("ack: previous data differs from request")
            self.logger.log_warning(
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
            raise ConnectionAbortedError(
                f"routing activation denied: {payload.RoutingActivationResponseCode.name}"
            )

    async def write_request_raw(self, hdr: GenericHeader, payload: DoIPOutData) -> None:
        async with self._mutex:
            buf = b""
            buf += hdr.pack()
            buf += payload.pack()
            self.writer.write(buf)
            await self.writer.drain()

            self.logger.log_trace(f"hdr: {hdr}, payload: {payload}")

            try:
                if isinstance(payload, DiagnosticMessage):
                    # Now an ACK message is expected.
                    await asyncio.wait_for(
                        self._read_ack(payload.UserData),
                        TimingAndCommunicationParameters.DiagnosticMessageMessageAckTimeout,
                    )
                elif isinstance(payload, RoutingActivationRequest):
                    await asyncio.wait_for(
                        self._read_routing_activation_response(),
                        TimingAndCommunicationParameters.DiagnosticMessageMessageAckTimeout,
                    )
            except asyncio.TimeoutError as e:
                await self.close()
                raise BrokenPipeError() from e

    async def write_diag_request(self, data: bytes) -> None:
        assert self.src_addr, "src_addr is not set"
        assert self.target_addr, "target_addr is not set"

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

    async def write_routing_activation_request(self) -> None:
        assert self.src_addr, "src_addr is not set"
        assert self.target_addr, "target_addr is not set"

        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.RoutingActivationRequest,
            PayloadLength=7,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = RoutingActivationRequest(
            SourceAddress=self.src_addr,
            ActivationType=self.activation_type,
            Reserved=0x00,
        )
        await self.write_request_raw(hdr, payload)

    async def write_alive_check_response(self) -> None:
        assert self.src_addr, "src_addr is not set"
        assert self.target_addr, "target_addr is not set"

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


_DoIP_SPEC_TYPE = TypedDict(
    "_DoIP_SPEC_TYPE",
    {
        "src_addr": int,
        "dst_addr": int,
        "activation_type": int,
    },
)

doip_spec = {
    "src_addr": (_int_spec(0), True),
    "dst_addr": (_int_spec(0), True),
    "activation_type": (
        _int_spec(RoutingActivationRequestTypes.WWH_OBD),
        False,
    ),
}

assertion_str = "bug: doip not connected"


class DoIPTransport(BaseTransport, scheme="doip", spec=doip_spec):
    def __init__(self, target: TargetURI):
        super().__init__(target)
        if target.hostname is None:
            raise ValueError("no hostname specified")
        self.port = target.port if target.port is not None else 6801
        self.args = cast(_DoIP_SPEC_TYPE, self._args)
        self.connection: Optional[DoIPConnection] = None

    async def _connect(self) -> None:
        assert self.target.hostname is not None, "bug: no hostname"

        self.connection = await DoIPConnection.connect(
            self.target.hostname,
            self.port,
            self.args["src_addr"],
            self.args["dst_addr"],
            RoutingActivationRequestTypes(self.args["activation_type"]),
        )
        await self.connection.write_routing_activation_request()

    async def connect(self, timeout: Optional[float] = None) -> None:
        assert self.target.hostname is not None, "bug: no hostname"

        async with self.mutex:
            await asyncio.wait_for(self._connect(), timeout)

    async def reconnect(self, timeout: Optional[float] = None) -> None:
        assert self.target.hostname is not None, "bug: no hostname"

        async with self.mutex:
            await self.terminate()
            await asyncio.wait_for(self._connect(), timeout)

    async def terminate(self) -> None:
        assert self.connection is not None, assertion_str

        await self.connection.close()

    async def read(
        self, timeout: Optional[float] = None, tags: Optional[list[str]] = None
    ) -> bytes:
        assert self.connection is not None, assertion_str

        data = await asyncio.wait_for(self.connection.read_diag_request(), timeout)
        self.logger.log_read(data.hex(), tags)
        return data

    async def write(
        self,
        data: bytes,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        assert self.connection is not None, assertion_str

        await asyncio.wait_for(self.connection.write_diag_request(data), timeout)
        self.logger.log_write(data.hex(), tags)
        return len(data)

    async def sendto(
        self,
        data: bytes,
        dst: int,
        timeout: Optional[float] = None,
        tags: Optional[list[str]] = None,
    ) -> int:
        assert self.connection is not None, assertion_str

        hdr = GenericHeader(
            ProtocolVersion=ProtocolVersions.ISO_13400_2_2012,
            PayloadType=PayloadTypes.DiagnosticMessage,
            PayloadLength=len(data) + 4,
            PayloadTypeSpecificMessageContent=b"",
        )
        payload = DiagnosticMessage(
            SourceAddress=self.args["src_addr"], TargetAddress=dst, UserData=data
        )
        await asyncio.wait_for(self.connection.write_request_raw(hdr, payload), timeout)
        self.logger.log_write(f"{dst:x}#{data.hex()}", tags)

        return len(data)

    async def recvfrom(
        self, timeout: Optional[float] = None, tags: Optional[list[str]] = None
    ) -> tuple[int, bytes]:
        assert self.connection is not None, assertion_str

        _, payload = await asyncio.wait_for(
            self.connection.read_diag_request_raw(), timeout
        )
        self.logger.log_read(
            f"{payload.SourceAddress:x}#{payload.UserData.hex()}", tags
        )
        return payload.SourceAddress, payload.UserData
