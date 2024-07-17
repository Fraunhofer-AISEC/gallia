# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys

from gallia.command.base import BaseCommand
from gallia.commands.discover.doip import DoIPDiscoverer
from gallia.commands.primitive.generic.pdu import GenericPDUPrimitive
from gallia.commands.primitive.uds.dtc import DTCPrimitive
from gallia.commands.primitive.uds.ecu_reset import ECUResetPrimitive
from gallia.commands.primitive.uds.iocbi import IOCBIPrimitive
from gallia.commands.primitive.uds.pdu import SendPDUPrimitive
from gallia.commands.primitive.uds.ping import PingPrimitive
from gallia.commands.primitive.uds.rdbi import ReadByIdentifierPrimitive
from gallia.commands.primitive.uds.rmba import RMBAPrimitive
from gallia.commands.primitive.uds.rtcl import RTCLPrimitive
from gallia.commands.primitive.uds.vin import VINPrimitive
from gallia.commands.primitive.uds.wdbi import WriteByIdentifierPrimitive
from gallia.commands.primitive.uds.wmba import WMBAPrimitive
from gallia.commands.scan.uds.identifiers import ScanIdentifiers
from gallia.commands.scan.uds.memory import MemoryFunctionsScanner
from gallia.commands.scan.uds.reset import ResetScanner
from gallia.commands.scan.uds.sa_dump_seeds import SASeedsDumper
from gallia.commands.scan.uds.services import ServicesScanner
from gallia.commands.scan.uds.sessions import SessionsScanner

registry: list[type[BaseCommand]] = [
    DoIPDiscoverer,
    MemoryFunctionsScanner,
    ReadByIdentifierPrimitive,
    ResetScanner,
    SASeedsDumper,
    ScanIdentifiers,
    SessionsScanner,
    ServicesScanner,
    DTCPrimitive,
    ECUResetPrimitive,
    VINPrimitive,
    IOCBIPrimitive,
    PingPrimitive,
    RMBAPrimitive,
    RTCLPrimitive,
    GenericPDUPrimitive,
    SendPDUPrimitive,
    WMBAPrimitive,
    WriteByIdentifierPrimitive,
]

__all__ = [
    "DoIPDiscoverer",
    "DMemoryFunctionsScanner",
    "DReadByIdentifierPrimitive",
    "DResetScanner",
    "DSASeedsDumper",
    "DScanIdentifiers",
    "DSessionsScanner",
    "DServicesScanner",
    "DDTCPrimitive",
    "DECUResetPrimitive",
    "DVINPrimitive",
    "DIOCBIPrimitive",
    "DPingPrimitive",
    "DRMBAPrimitive",
    "DRTCLPrimitive",
    "DGenericPDUPrimitive",
    "DSendPDUPrimitive",
    "DWMBAPrimitive",
    "DWriteByIdentifierPrimitive",
]


if sys.platform.startswith("linux"):
    from gallia.commands.discover.find_xcp import FindXCP
    from gallia.commands.discover.uds.isotp import IsotpDiscoverer
    from gallia.commands.fuzz.uds.pdu import PDUFuzzer
    from gallia.commands.primitive.uds.xcp import SimpleTestXCP
    from gallia.commands.script.vecu import VirtualECU

    registry += [
        FindXCP,
        IsotpDiscoverer,
        PDUFuzzer,
        SimpleTestXCP,
        VirtualECU,
    ]

    __all__ += [
        "FindXCP",
        "IsotpDiscoverer",
        "PDUFuzzer",
        "SimpleTestXCP",
        "VirtualECU",
    ]
