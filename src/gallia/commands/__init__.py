# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from gallia.command.base import BaseCommand
from gallia.commands.discover.doip import DoIPDiscoverer
from gallia.commands.discover.find_xcp import FindXCP
from gallia.commands.discover.uds.isotp import IsotpDiscoverer
from gallia.commands.fuzz.uds.pdu import PDUFuzzer
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
from gallia.commands.primitive.uds.xcp import SimpleTestXCP
from gallia.commands.scan.uds.identifiers import ScanIdentifiers
from gallia.commands.scan.uds.memory import MemoryFunctionsScanner
from gallia.commands.scan.uds.reset import ResetScanner
from gallia.commands.scan.uds.sa_dump_seeds import SASeedsDumper
from gallia.commands.scan.uds.sa_levels import SALevelScanner
from gallia.commands.scan.uds.services import ServicesScanner
from gallia.commands.scan.uds.sessions import SessionsScanner
from gallia.commands.script.vecu import VirtualECU

registry: list[type[BaseCommand]] = [
    # SimpleTestXCP,
    DoIPDiscoverer,
    IsotpDiscoverer,
    FindXCP,
    PDUFuzzer,
    MemoryFunctionsScanner,
    ReadByIdentifierPrimitive,
    ResetScanner,
    SASeedsDumper,
    SALevelScanner,
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
    VirtualECU,
    WriteByIdentifierPrimitive,
    SimpleTestXCP,
]

__all__ = [x.__name__ for x in registry]
