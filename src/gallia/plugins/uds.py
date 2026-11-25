# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

__lazy_modules__ = {
    "gallia.commands",
    "gallia.commands.primitive.uds.dddi",
    "gallia.commands.script.rerun",
    "gallia.services.uds",
    "gallia.transports",
}

import sys
from collections.abc import Mapping

from gallia.commands import (
    ClearDTCPrimitive,
    ControlDTCPrimitive,
    DoIPDiscoverer,
    ECUResetPrimitive,
    GenericPDUPrimitive,
    HSFZDiscoverer,
    IOCBIPrimitive,
    MemoryFunctionsScanner,
    PingPrimitive,
    ReadByIdentifierPrimitive,
    ReadDTCPrimitive,
    ResetScanner,
    RMBAPrimitive,
    RTCLPrimitive,
    SASeedsDumper,
    ScanIdentifiers,
    SendPDUPrimitive,
    ServicesScanner,
    SessionsScanner,
    VINPrimitive,
    WMBAPrimitive,
    WriteByIdentifierPrimitive,
)
from gallia.commands.primitive.uds.dddi import (
    ClearDynamicallyDefinedDataIdentifierDDDIPrimitive,
    DefineByIdentifierDDDIPrimitive,
    DefineByMemoryAddressDDDIPrimitive,
)
from gallia.commands.script.rerun import Rerunner
from gallia.plugins.plugin import Command, CommandTree, Plugin
from gallia.services.uds import ECU
from gallia.transports import BaseTransport, registry

if sys.platform.startswith("linux"):
    from gallia.commands import DbVirtualECU, IsotpDiscoverer, PDUFuzzer, RngVirtualECU

if sys.platform == "win32":
    from gallia.commands import FRConfigDump, FRDump


class UDSPlugin(Plugin):
    @classmethod
    def name(cls) -> str:
        return "Gallia UDS"

    @classmethod
    def description(cls) -> str:
        return "Default Gallia plugin for Unified Diagnostic Services (UDS) functionality"

    @classmethod
    def transports(cls) -> list[type[BaseTransport]]:
        return registry

    @classmethod
    def ecus(cls) -> list[type[ECU]]:
        return [ECU]

    @classmethod
    def commands(cls) -> Mapping[str, CommandTree | Command]:
        tree = {
            "discover": CommandTree(
                description="discover scanners for hosts and endpoints",
                subtree={
                    "doip": lambda: DoIPDiscoverer,
                    "hsfz": lambda: HSFZDiscoverer,
                },
            ),
            "primitive": CommandTree(
                description="protocol specific primitives",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "rdbi": lambda: ReadByIdentifierPrimitive,
                            "dddi": CommandTree(
                                description="DynamicallyDefineDataIdentifiers",
                                subtree={
                                    "identifier": lambda: DefineByIdentifierDDDIPrimitive,
                                    "memory": lambda: DefineByMemoryAddressDDDIPrimitive,
                                    "clear": lambda: (
                                        ClearDynamicallyDefinedDataIdentifierDDDIPrimitive
                                    ),
                                },
                            ),
                            "dtc": CommandTree(
                                description="DiagnosticTroubleCodes",
                                subtree={
                                    "clear": lambda: ClearDTCPrimitive,
                                    "control": lambda: ControlDTCPrimitive,
                                    "read": lambda: ReadDTCPrimitive,
                                },
                            ),
                            "ecu-reset": lambda: ECUResetPrimitive,
                            "vin": lambda: VINPrimitive,
                            "iocbi": lambda: IOCBIPrimitive,
                            "ping": lambda: PingPrimitive,
                            "rmba": lambda: RMBAPrimitive,
                            "rtcl": lambda: RTCLPrimitive,
                            "pdu": lambda: SendPDUPrimitive,
                            "wmba": lambda: WMBAPrimitive,
                            "wdbi": lambda: WriteByIdentifierPrimitive,
                        },
                    ),
                    "generic": CommandTree(
                        description="generic networks primitives",
                        subtree={"pdu": lambda: GenericPDUPrimitive},
                    ),
                },
            ),
            "scan": CommandTree(
                description="scanners for network protocol parameters",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "memory": lambda: MemoryFunctionsScanner,
                            "reset": lambda: ResetScanner,
                            "dump-seeds": lambda: SASeedsDumper,
                            "identifiers": lambda: ScanIdentifiers,
                            "sessions": lambda: SessionsScanner,
                            "services": lambda: ServicesScanner,
                        },
                    )
                },
            ),
            "script": CommandTree(
                description="miscellaneous helper scripts",
                subtree={"rerun": lambda: Rerunner},
            ),
        }

        if sys.platform.startswith("linux"):
            tree["discover"].subtree.update(
                {
                    "isotp": lambda: IsotpDiscoverer,
                }
            )

            tree.update(
                {
                    "fuzz": CommandTree(
                        description="fuzzing tools",
                        subtree={
                            "uds": CommandTree(
                                description="Universal Diagnostic Services",
                                subtree={"pdu": lambda: PDUFuzzer},
                            )
                        },
                    ),
                }
            )

            tree["script"].subtree.update(
                {
                    "vecu": CommandTree(
                        description="spawn a virtual UDS ECU",
                        subtree={
                            "db": lambda: DbVirtualECU,
                            "rng": lambda: RngVirtualECU,
                        },
                    ),
                }
            )

        if sys.platform == "win32":
            tree["script"].subtree.update(
                {
                    "fr-dump": lambda: FRDump,
                    "fr-dump-config": lambda: FRConfigDump,
                }
            )

        return tree
