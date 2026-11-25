# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# Importing a command submodule should leave the other commands unloaded.
__lazy_modules__ = {
    "gallia.commands._registry",
    "gallia.commands.discover.doip",
    "gallia.commands.discover.find_xcp",
    "gallia.commands.discover.hsfz",
    "gallia.commands.discover.isotp",
    "gallia.commands.fuzz.uds.pdu",
    "gallia.commands.primitive.generic.pdu",
    "gallia.commands.primitive.uds.dtc",
    "gallia.commands.primitive.uds.ecu_reset",
    "gallia.commands.primitive.uds.iocbi",
    "gallia.commands.primitive.uds.pdu",
    "gallia.commands.primitive.uds.ping",
    "gallia.commands.primitive.uds.rdbi",
    "gallia.commands.primitive.uds.rmba",
    "gallia.commands.primitive.uds.rtcl",
    "gallia.commands.primitive.uds.vin",
    "gallia.commands.primitive.uds.wdbi",
    "gallia.commands.primitive.uds.wmba",
    "gallia.commands.scan.uds.identifiers",
    "gallia.commands.scan.uds.memory",
    "gallia.commands.scan.uds.reset",
    "gallia.commands.scan.uds.sa_dump_seeds",
    "gallia.commands.scan.uds.services",
    "gallia.commands.scan.uds.sessions",
    "gallia.commands.script.flexray",
    "gallia.commands.script.vecu",
}

import sys

from gallia.commands.discover.doip import DoIPDiscoverer
from gallia.commands.discover.hsfz import HSFZDiscoverer
from gallia.commands.primitive.generic.pdu import GenericPDUPrimitive
from gallia.commands.primitive.uds.dtc import (
    ClearDTCPrimitive,
    ControlDTCPrimitive,
    ReadDTCPrimitive,
)
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

# TODO: Investigate why linters didn't catch faulty strings in here.
__all__ = [
    "ClearDTCPrimitive",
    "ControlDTCPrimitive",
    "DoIPDiscoverer",
    "ECUResetPrimitive",
    "GenericPDUPrimitive",
    "HSFZDiscoverer",
    "IOCBIPrimitive",
    "MemoryFunctionsScanner",
    "PingPrimitive",
    "RMBAPrimitive",
    "RTCLPrimitive",
    "ReadByIdentifierPrimitive",
    "ReadDTCPrimitive",
    "ResetScanner",
    "SASeedsDumper",
    "ScanIdentifiers",
    "SendPDUPrimitive",
    "ServicesScanner",
    "SessionsScanner",
    "VINPrimitive",
    "WMBAPrimitive",
    "WriteByIdentifierPrimitive",
]


if sys.platform.startswith("linux"):
    from gallia.commands.discover.find_xcp import CanFindXCP
    from gallia.commands.discover.isotp import IsotpDiscoverer
    from gallia.commands.fuzz.uds.pdu import PDUFuzzer
    from gallia.commands.script.vecu import DbVirtualECU, RngVirtualECU

    __all__ += [
        "CanFindXCP",
        "DbVirtualECU",
        "IsotpDiscoverer",
        "PDUFuzzer",
        "RngVirtualECU",
    ]


if sys.platform == "win32":
    from gallia.commands.script.flexray import FRConfigDump, FRDump

    __all__ += ["FRConfigDump", "FRDump"]


from gallia.commands._registry import registry as registry
