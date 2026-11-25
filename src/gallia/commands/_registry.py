# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from typing import Any

from gallia import commands
from gallia.command.base import AsyncScript

registry: list[type[AsyncScript[Any]]] = [
    commands.DoIPDiscoverer,
    commands.ECUResetPrimitive,
    commands.GenericPDUPrimitive,
    commands.HSFZDiscoverer,
    commands.IOCBIPrimitive,
    commands.MemoryFunctionsScanner,
    commands.PingPrimitive,
    commands.RMBAPrimitive,
    commands.RTCLPrimitive,
    commands.ReadByIdentifierPrimitive,
    commands.ResetScanner,
    commands.SASeedsDumper,
    commands.ScanIdentifiers,
    commands.SessionsScanner,
    commands.ServicesScanner,
    commands.ClearDTCPrimitive,
    commands.ControlDTCPrimitive,
    commands.ReadDTCPrimitive,
    commands.ECUResetPrimitive,
    commands.VINPrimitive,
    commands.IOCBIPrimitive,
    commands.PingPrimitive,
    commands.RMBAPrimitive,
    commands.RTCLPrimitive,
    commands.GenericPDUPrimitive,
    commands.SendPDUPrimitive,
    commands.ServicesScanner,
    commands.SessionsScanner,
    commands.VINPrimitive,
    commands.WMBAPrimitive,
    commands.WriteByIdentifierPrimitive,
]

if sys.platform.startswith("linux"):
    registry += [
        commands.CanFindXCP,
        commands.IsotpDiscoverer,
        commands.PDUFuzzer,
        commands.DbVirtualECU,
        commands.RngVirtualECU,
    ]

if sys.platform == "win32":
    registry += [commands.FRDump, commands.FRConfigDump]
