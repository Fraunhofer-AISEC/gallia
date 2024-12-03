# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import asyncio
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Any, Self

from pydantic import BaseModel, field_validator

from gallia.log import get_logger
from gallia.transports.base import BaseTransport, TargetURI
from gallia.utils import (
    auto_int,
    handle_task_error,
    set_task_handler_ctx_variable,
)

logger = get_logger(__name__)


@unique
class ProtocolVersions(IntEnum):
    ISO_13400_2_2010 = 0x01
    ISO_13400_2_2012 = 0x02
    ISO_13400_2_2019 = 0x03


@unique
class RoutingActivationRequestTypes(IntEnum):
    RESERVED = 0xFF
    ManufacturerSpecific = 0xFE
    Default = 0x00
    WWH_OBD = 0x01
    CentralSecurity = 0xE0

    @classmethod
    def _missing_(cls, value: Any) -> RoutingActivationRequestTypes:
        if value in range(0xE1, 0x100):
            return cls.ManufacturerSpecific
        return cls.RESERVED


@unique
class RoutingActivationResponseCodes(IntEnum):
    RESERVED = 0xFF
    ManufacturerSpecific = 0xFE
    UnknownSourceAddress = 0x00
    NoResources = 0x01
    InvalidConnectionEntry = 0x02
    AlreadyActive = 0x03
    AuthenticationMissing = 0x04
    ConfirmationRejected = 0x05
    UnsupportedActivationType = 0x06
    TLSRequired = 0x07
    Success = 0x10
    SuccessConfirmationRequired = 0x11

    @classmethod
    def _missing_(cls, value: Any) -> RoutingActivationResponseCodes:
        if value in range(0xE0, 0xFF):
            return cls.ManufacturerSpecific
        return cls.RESERVED


class DoIPRoutingActivationDeniedError(ConnectionAbortedError):
    rac_code: RoutingActivationResponseCodes

    def __init__(self, rac_code: int):
        self.rac_code = RoutingActivationResponseCodes(rac_code)
        super().__init__(f"DoIP routing activation denied: {self.rac_code.name} ({rac_code})")


@unique
class PayloadTypes(IntEnum):
    GenericDoIPHeaderNACK = 0x0000
    VehicleIdentificationRequestMessage = 0x0001
    VehicleIdentificationRequestMessageWithEID = 0x0002
    VehicleIdentificationRequestMessageWithVIN = 0x0003
    VehicleAnnouncementMessage = 0x004
    RoutingActivationRequest = 0x0005
    RoutingActivationResponse = 0x0006
    AliveCheckRequest = 0x0007
    AliveCheckResponse = 0x0008
    DoIPEntityStatusRequest = 0x4001
    DoIPEntityStatusResponse = 0x4002
    DiagnosticPowerModeInformationRequest = 0x4003
    DiagnosticPowerModeInformationResponse = 0x4004
    DiagnosticMessage = 0x8001
    DiagnosticMessagePositiveAcknowledgement = 0x8002
    DiagnosticMessageNegativeAcknowledgement = 0x8003


@unique
class DiagnosticMessagePositiveAckCodes(IntEnum):
    Success = 0x00


@unique
class DiagnosticMessageNegativeAckCodes(IntEnum):
    RESERVED = 0xFF
    InvalidSourceAddress = 0x02
    UnknownTargetAddress = 0x03
    DiagnosticMessageTooLarge = 0x04
    OutOfMemory = 0x05
    TargetUnreachable = 0x06
    UnknownNetwork = 0x07
    TransportProtocolError = 0x08

    @classmethod
    def _missing_(cls, value: Any) -> DiagnosticMessageNegativeAckCodes:
        return cls.RESERVED


class DoIPNegativeAckError(BrokenPipeError):
    nack_code: DiagnosticMessageNegativeAckCodes

    def __init__(self, negative_ack_code: int):
        self.nack_code = DiagnosticMessageNegativeAckCodes(negative_ack_code)
        super().__init__(f"DoIP negative ACK received: {self.nack_code.name} ({negative_ack_code})")


@unique
class GenericDoIPHeaderNACKCodes(IntEnum):
    RESERVED = 0xFF
    IncorrectPatternFormat = 0x00
    UnknownPayloadType = 0x01
    MessageTooLarge = 0x02
    OutOfMemory = 0x03
    InvalidPayloadLength = 0x04

    @classmethod
    def _missing_(cls, value: Any) -> GenericDoIPHeaderNACKCodes:
        return cls.RESERVED


class DoIPGenericHeaderNACKError(ConnectionAbortedError):
    nack_code: GenericDoIPHeaderNACKCodes

    def __init__(self, nack_code: int):
        self.nack_code = GenericDoIPHeaderNACKCodes(nack_code)
        super().__init__(f"DoIP generic header negative ACK: {self.nack_code.name} ({nack_code})")


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
class GenericDoIPHeaderNACK:
    GenericHeaderNACKCode: GenericDoIPHeaderNACKCodes

    def pack(self) -> bytes:
        return struct.pack(
            "!B",
            self.GenericHeaderNACKCode,
        )

    @classmethod
    def unpack(cls, data: bytes) -> GenericDoIPHeaderNACK:
        (generic_header_NACK_code,) = struct.unpack("!B", data)
        return cls(
            GenericDoIPHeaderNACKCodes(generic_header_NACK_code),
        )


@dataclass
class VehicleIdentificationRequestMessage:
    def pack(self) -> bytes:
        return b""


@dataclass
class VehicleAnnouncementMessage:
    VIN: bytes
    LogicalAddress: int
    EID: bytes
    GID: bytes
    FurtherActionRequired: FurtherActionCodes
    VINGIDSyncStatus: SynchronisationStatusCodes | None

    @classmethod
    def unpack(cls, data: bytes) -> VehicleAnnouncementMessage:
        if len(data) == 32:
            # VINGIDSyncStatus is optional
            (vin, logical_address, eid, gid, further_action_required) = struct.unpack(
                "!17sH6s6sB", data
            )
            vin_gid_sync_status = None
        else:
            (
                vin,
                logical_address,
                eid,
                gid,
                further_action_required,
                vin_gid_sync_status,
            ) = struct.unpack("!17sH6s6sBB", data)

        return cls(
            vin,
            logical_address,
            eid,
            gid,
            FurtherActionCodes(further_action_required),
            SynchronisationStatusCodes(vin_gid_sync_status)
            if vin_gid_sync_status is not None
            else None,
        )


@unique
class FurtherActionCodes(IntEnum):
    RESERVED = 0x0F
    ManufacturerSpecific = 0xFF
    NoFurtherActionRequired = 0x00
    RoutingActivationRequiredToInitiateCentralSecurity = 0x10

    @classmethod
    def _missing_(cls, value: Any) -> FurtherActionCodes:
        if value in range(0x11, 0x100):
            return cls.ManufacturerSpecific
        return cls.RESERVED


@unique
class SynchronisationStatusCodes(IntEnum):
    RESERVED = 0xFF
    VINGIDSynchronized = 0x00
    IncompleteVINGIDNotSynchronized = 0x10

    @classmethod
    def _missing_(cls, value: Any) -> SynchronisationStatusCodes:
        return cls.RESERVED


@dataclass
class DoIPEntityStatusRequest:
    def pack(self) -> bytes:
        return b""


@dataclass
class DoIPEntityStatusResponse:
    NodeType: NodeTypes
    MaximumConcurrentTCP_DATASockets: int
    CurrentlyOpenTCP_DATASockets: int
    MaximumDataSize: int | None

    @classmethod
    def unpack(cls, data: bytes) -> DoIPEntityStatusResponse:
        if len(data) == 3:
            # MaximumDataSize is optional
            (nt, mcts, ncts) = struct.unpack("!BBB", data)
            mds = None
        else:
            (nt, mcts, ncts, mds) = struct.unpack("!BBBI", data)

        return cls(NodeTypes(nt), mcts, ncts, mds)


@unique
class NodeTypes(IntEnum):
    RESERVED = 0xFF
    Gateway = 0x00
    Node = 0x01

    @classmethod
    def _missing_(cls, value: Any) -> NodeTypes:
        return cls.RESERVED


@dataclass
class RoutingActivationRequest:
    SourceAddress: int
    ActivationType: int
    Reserved: int = 0x00000000  # Not used, default value.
    # OEMReserved uint32

    def pack(self) -> bytes:
        return struct.pack("!HBI", self.SourceAddress, self.ActivationType, self.Reserved)


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
    GenericDoIPHeaderNACK
    | RoutingActivationResponse
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
    def __init__(  # noqa: PLR0913
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        src_addr: int,
        target_addr: int,
        protocol_version: int,
        separate_diagnostic_message_queue: bool = False,
    ):
        self.reader = reader
        self.writer = writer
        self.src_addr = src_addr
        self.target_addr = target_addr
        self.protocol_version = protocol_version
        self.separate_diagnostic_message_queue = separate_diagnostic_message_queue
        self._diagnostic_message_queue: asyncio.Queue[DoIPDiagFrame] = asyncio.Queue()
        self._read_queue: asyncio.Queue[DoIPFrame] = asyncio.Queue()
        self._read_task = asyncio.create_task(self._read_worker())
        self._read_task.add_done_callback(
            handle_task_error,
            context=set_task_handler_ctx_variable(__name__, "DoipReader"),
        )
        self._is_closed = False
        self._mutex = asyncio.Lock()

    @classmethod
    async def connect(  # noqa: PLR0913
        cls,
        host: str,
        port: int,
        src_addr: int,
        target_addr: int,
        so_linger: bool = False,
        protocol_version: int = ProtocolVersions.ISO_13400_2_2019,
        separate_diagnostic_message_queue: bool = False,
    ) -> Self:
        reader, writer = await asyncio.open_connection(host, port)

        if so_linger is True:
            # Depending on who will close the connection in the end, one party's socket
            # will remain in a TIME_WAIT state, which occupies resources until enough
            # time has passed. Setting the LINGER socket option tells our kernel to
            # close the connection with a RST, which brings the TCP connection to an
            # error state and thus avoids TIME_WAIT and instantly forces LISTEN or CLOSED
            # For more info, see e.g. Note 3 of :
            # https://www.ietf.org/rfc/rfc9293.html#name-state-machine-overview
            sock = writer.get_extra_info("socket")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))

        return cls(
            reader,
            writer,
            src_addr,
            target_addr,
            protocol_version,
            separate_diagnostic_message_queue,
        )

    async def _read_frame(self) -> DoIPFrame | tuple[None, None]:
        # Header is fixed size 8 byte.
        hdr_buf = await self.reader.readexactly(8)
        hdr = GenericHeader.unpack(hdr_buf)

        payload_buf = await self.reader.readexactly(hdr.PayloadLength)
        payload: DoIPInData
        match hdr.PayloadType:
            case PayloadTypes.GenericDoIPHeaderNACK:
                payload = GenericDoIPHeaderNACK.unpack(payload_buf)
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
                logger.warning(
                    f"DoIP message with unhandled PayloadType: {hdr} {payload_buf.hex()}"
                )
                return None, None
        logger.trace("Received DoIP message: %s, %s", hdr, payload)
        return hdr, payload

    async def _read_worker(self) -> None:
        try:
            while True:
                hdr, data = await self._read_frame()
                if hdr is None or data is None:
                    continue
                if hdr.PayloadType == PayloadTypes.AliveCheckRequest:
                    await self.write_alive_check_response()
                    continue
                if isinstance(data, DiagnosticMessage) and self.separate_diagnostic_message_queue:
                    await self._diagnostic_message_queue.put((hdr, data))
                    continue
                await self._read_queue.put((hdr, data))
        except asyncio.CancelledError:
            logger.debug("DoIP read worker got cancelled")
        except asyncio.IncompleteReadError as e:
            logger.debug(f"DoIP read worker received EOF: {e!r}")
        except Exception as e:
            logger.info(f"DoIP read worker died with {e!r}")
        finally:
            logger.debug("Feeding EOF to reader and requesting a close")
            self.reader.feed_eof()
            await self.close()

    async def read_frame_unsafe(self) -> DoIPFrame:
        # Avoid waiting on the queue forever when
        # the connection has been terminated.
        if self._is_closed:
            raise ConnectionError
        return await self._read_queue.get()

    async def read_frame(self) -> DoIPFrame:
        async with self._mutex:
            return await self.read_frame_unsafe()

    async def read_diag_request_raw(self) -> DoIPDiagFrame:
        unexpected_packets: list[tuple[Any, Any]] = []
        while True:
            if self.separate_diagnostic_message_queue:
                return await self._diagnostic_message_queue.get()
            hdr, payload = await self.read_frame()
            if not isinstance(payload, DiagnosticMessage):
                logger.warning(f"expected DoIP DiagnosticMessage, instead got: {hdr} {payload}")
                unexpected_packets.append((hdr, payload))
                continue
            if payload.SourceAddress != self.target_addr or payload.TargetAddress != self.src_addr:
                logger.warning(
                    f"DoIP-DiagnosticMessage: unexpected addresses (src:dst); expected {self.src_addr:#04x}:"
                    + f"{self.target_addr:#04x} but got: {payload.SourceAddress:#04x}:{payload.TargetAddress:#04x}"
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
            if not isinstance(payload, DiagnosticMessagePositiveAcknowledgement) and not isinstance(
                payload, DiagnosticMessageNegativeAcknowledgement
            ):
                logger.warning(f"expected DoIP positive/negative ACK, instead got: {hdr} {payload}")
                unexpected_packets.append((hdr, payload))
                continue

            if payload.SourceAddress != self.target_addr or payload.TargetAddress != self.src_addr:
                logger.warning(
                    f"DoIP-ACK: unexpected addresses (src:dst); expected {self.src_addr:#04x}:{self.target_addr:#04x} "
                    + f"but got: {payload.SourceAddress:#04x}:{payload.TargetAddress:#04x}"
                )
                unexpected_packets.append((hdr, payload))
                continue
            if (
                len(payload.PreviousDiagnosticMessageData) > 0
                and payload.PreviousDiagnosticMessageData
                != prev_data[: len(payload.PreviousDiagnosticMessageData)]
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

            if payload.RoutingActivationResponseCode != RoutingActivationResponseCodes.Success:
                raise DoIPRoutingActivationDeniedError(payload.RoutingActivationResponseCode)
            return

    async def write_request_raw(self, hdr: GenericHeader, payload: DoIPOutData) -> None:
        async with self._mutex:
            buf = b""
            buf += hdr.pack()
            buf += payload.pack()
            self.writer.write(buf)
            await self.writer.drain()

            logger.trace("Sent DoIP message: hdr: %s, payload: %s", hdr, payload)

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
            except TimeoutError as e:
                await self.close()
                raise BrokenPipeError("Timeout while waiting for DoIP ACK message") from e

    async def write_diag_request(self, data: bytes) -> None:
        hdr = GenericHeader(
            ProtocolVersion=self.protocol_version,
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
            ProtocolVersion=self.protocol_version,
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
            ProtocolVersion=self.protocol_version,
            PayloadType=PayloadTypes.AliveCheckResponse,
            PayloadLength=2,
        )
        payload = AliveCheckResponse(
            SourceAddress=self.src_addr,
        )
        await self.write_request_raw(hdr, payload)

    async def close(self) -> None:
        logger.debug("Closing DoIP connection...")
        if self._is_closed:
            logger.debug("Already closed!")
            return
        self._is_closed = True
        logger.debug("Cancelling read worker")
        self._read_task.cancel()
        self.writer.close()
        logger.debug("Awaiting confirmation of closed writer")
        try:
            await self.writer.wait_closed()
        except ConnectionError as e:
            logger.debug(f"Exception while waiting for the writer to close: {e!r}")


class DoIPConfig(BaseModel):
    src_addr: int
    target_addr: int
    activation_type: int = RoutingActivationRequestTypes.WWH_OBD.value
    protocol_version: int = ProtocolVersions.ISO_13400_2_2019

    @field_validator(
        "src_addr",
        "target_addr",
        "activation_type",
        "protocol_version",
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
    async def _connect(  # noqa: PLR0913
        hostname: str,
        port: int,
        src_addr: int,
        target_addr: int,
        activation_type: int,
        protocol_version: int,
    ) -> DoIPConnection:
        conn = await DoIPConnection.connect(
            hostname,
            port,
            src_addr,
            target_addr,
            protocol_version=protocol_version,
        )
        await conn.write_routing_activation_request(RoutingActivationRequestTypes(activation_type))
        return conn

    @classmethod
    async def connect(
        cls,
        target: str | TargetURI,
        timeout: float | None = None,
    ) -> Self:
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
                config.protocol_version,
            ),
            timeout,
        )
        return cls(t, port, config, conn)

    async def reconnect(self, timeout: float | None = None) -> Self:
        # It might be that the DoIP endpoint is not immediately ready for another
        # connection, so set the timeout to 10s by default.
        return await super().reconnect(10 if timeout is None else timeout)

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
            # missing responses
            logger.debug("DoIP message was ACKed with TargetUnreachable")

        return len(data)
