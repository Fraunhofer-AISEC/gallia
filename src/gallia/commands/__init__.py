# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.command.base import AsyncScript
from gallia.commands.discover.doip import DoIPDiscoverer, DoIPDiscovererConfig
from gallia.commands.discover.hsfz import HSFZDiscoverer, HSFZDiscovererConfig
from gallia.commands.primitive.generic.pdu import GenericPDUPrimitive, GenericPDUPrimitiveConfig
from gallia.commands.primitive.uds.dtc import (
    ClearDTCPrimitive,
    ClearDTCPrimitiveConfig,
    ControlDTCPrimitive,
    ControlDTCPrimitiveConfig,
    ReadDTCPrimitive,
    ReadDTCPrimitiveConfig,
)
from gallia.commands.primitive.uds.ecu_reset import ECUResetPrimitive, ECUResetPrimitiveConfig
from gallia.commands.primitive.uds.iocbi import IOCBIPrimitive, IOCBIPrimitiveConfig
from gallia.commands.primitive.uds.pdu import SendPDUPrimitive, SendPDUPrimitiveConfig
from gallia.commands.primitive.uds.ping import PingPrimitive, PingPrimitiveConfig
from gallia.commands.primitive.uds.rdbi import (
    ReadByIdentifierPrimitive,
    ReadByIdentifierPrimitiveConfig,
)
from gallia.commands.primitive.uds.rmba import RMBAPrimitive, RMBAPrimitiveConfig
from gallia.commands.primitive.uds.rtcl import RTCLPrimitive, RTCLPrimitiveConfig
from gallia.commands.primitive.uds.vin import VINPrimitive, VINPrimitiveConfig
from gallia.commands.primitive.uds.wdbi import (
    WriteByIdentifierPrimitive,
    WriteByIdentifierPrimitiveConfig,
)
from gallia.commands.primitive.uds.wmba import WMBAPrimitive, WMBAPrimitiveConfig
from gallia.commands.scan.uds.identifiers import ScanIdentifiers, ScanIdentifiersConfig
from gallia.commands.scan.uds.memory import MemoryFunctionsScanner, MemoryFunctionsScannerConfig
from gallia.commands.scan.uds.reset import ResetScanner, ResetScannerConfig
from gallia.commands.scan.uds.sa_dump_seeds import SASeedsDumper, SASeedsDumperConfig
from gallia.commands.scan.uds.services import ServicesScanner, ServicesScannerConfig
from gallia.commands.scan.uds.sessions import SessionsScanner, SessionsScannerConfig

registry: list[type[AsyncScript]] = [
    DoIPDiscoverer,
    ECUResetPrimitive,
    GenericPDUPrimitive,
    HSFZDiscoverer,
    IOCBIPrimitive,
    MemoryFunctionsScanner,
    PingPrimitive,
    RMBAPrimitive,
    RTCLPrimitive,
    ReadByIdentifierPrimitive,
    ResetScanner,
    SASeedsDumper,
    ScanIdentifiers,
    SessionsScanner,
    ServicesScanner,
    ClearDTCPrimitive,
    ControlDTCPrimitive,
    ReadDTCPrimitive,
    ECUResetPrimitive,
    VINPrimitive,
    IOCBIPrimitive,
    PingPrimitive,
    RMBAPrimitive,
    RTCLPrimitive,
    GenericPDUPrimitive,
    SendPDUPrimitive,
    ServicesScanner,
    SessionsScanner,
    VINPrimitive,
    WMBAPrimitive,
    WriteByIdentifierPrimitive,
]

# TODO: Investigate why linters didn't catch faulty strings in here.
__all__ = [
    "ClearDTCPrimitive",
    "ClearDTCPrimitiveConfig",
    "ControlDTCPrimitive",
    "ControlDTCPrimitiveConfig",
    "DoIPDiscoverer",
    "DoIPDiscovererConfig",
    "ECUResetPrimitive",
    "ECUResetPrimitiveConfig",
    "GenericPDUPrimitive",
    "GenericPDUPrimitiveConfig",
    "HSFZDiscoverer",
    "HSFZDiscovererConfig",
    "IOCBIPrimitive",
    "IOCBIPrimitiveConfig",
    "MemoryFunctionsScanner",
    "MemoryFunctionsScannerConfig",
    "PingPrimitive",
    "PingPrimitiveConfig",
    "RMBAPrimitive",
    "RMBAPrimitiveConfig",
    "RTCLPrimitive",
    "RTCLPrimitiveConfig",
    "ReadByIdentifierPrimitive",
    "ReadByIdentifierPrimitiveConfig",
    "ReadDTCPrimitive",
    "ReadDTCPrimitiveConfig",
    "ResetScanner",
    "ResetScannerConfig",
    "SASeedsDumper",
    "SASeedsDumperConfig",
    "ScanIdentifiers",
    "ScanIdentifiersConfig",
    "SendPDUPrimitive",
    "SendPDUPrimitiveConfig",
    "ServicesScanner",
    "ServicesScannerConfig",
    "SessionsScanner",
    "SessionsScannerConfig",
    "VINPrimitive",
    "VINPrimitiveConfig",
    "WMBAPrimitive",
    "WMBAPrimitiveConfig",
    "WriteByIdentifierPrimitive",
    "WriteByIdentifierPrimitiveConfig",
]


if sys.platform.startswith("linux"):
    from gallia.commands.discover.find_xcp import CanFindXCP, CanFindXCPConfig
    from gallia.commands.discover.isotp import IsotpDiscoverer, IsotpDiscovererConfig
    from gallia.commands.fuzz.uds.pdu import PDUFuzzer, PDUFuzzerConfig
    from gallia.commands.script.vecu import (
        DbVirtualECU,
        DbVirtualECUConfig,
        RngVirtualECU,
        RngVirtualECUConfig,
    )

    registry += [
        CanFindXCP,
        IsotpDiscoverer,
        PDUFuzzer,
        DbVirtualECU,
        RngVirtualECU,
    ]

    __all__ += [
        "CanFindXCP",
        "CanFindXCPConfig",
        "DbVirtualECU",
        "DbVirtualECUConfig",
        "IsotpDiscoverer",
        "IsotpDiscovererConfig",
        "PDUFuzzer",
        "PDUFuzzerConfig",
        "RngVirtualECU",
        "RngVirtualECUConfig",
    ]


if sys.platform == "win32":
    from gallia.commands.script.flexray import (
        FRConfigDump,
        FRConfigDumpConfig,
        FRDump,
        FRDumpConfig,
    )

    registry += [FRDump, FRConfigDump]
    __all__ += ["FRConfigDump", "FRConfigDumpConfig", "FRDump", "FRDumpConfig"]
