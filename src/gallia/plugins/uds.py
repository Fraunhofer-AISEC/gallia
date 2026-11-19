# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
from collections.abc import Mapping
from typing import TYPE_CHECKING

from gallia.plugins.plugin import Command, CommandTree, Plugin
from gallia.transports import registry

if TYPE_CHECKING:
    from gallia.services.uds import ECU
    from gallia.transports import BaseTransport


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
        from gallia.services.uds import ECU

        return [ECU]

    @classmethod
    def commands(cls) -> Mapping[str, CommandTree | Command]:
        tree = {
            "discover": CommandTree(
                description="discover scanners for hosts and endpoints",
                subtree={
                    "doip": "gallia.commands.discover.doip:DoIPDiscoverer",
                    "hsfz": "gallia.commands.discover.hsfz:HSFZDiscoverer",
                },
            ),
            "primitive": CommandTree(
                description="protocol specific primitives",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "rdbi": "gallia.commands.primitive.uds.rdbi:ReadByIdentifierPrimitive",
                            "dddi": CommandTree(
                                description="DynamicallyDefineDataIdentifiers",
                                subtree={
                                    "identifier": "gallia.commands.primitive.uds.dddi:DefineByIdentifierDDDIPrimitive",
                                    "memory": "gallia.commands.primitive.uds.dddi:DefineByMemoryAddressDDDIPrimitive",
                                    "clear": "gallia.commands.primitive.uds.dddi:ClearDynamicallyDefinedDataIdentifierDDDIPrimitive",
                                },
                            ),
                            "dtc": CommandTree(
                                description="DiagnosticTroubleCodes",
                                subtree={
                                    "clear": "gallia.commands.primitive.uds.dtc:ClearDTCPrimitive",
                                    "control": "gallia.commands.primitive.uds.dtc:ControlDTCPrimitive",
                                    "read": "gallia.commands.primitive.uds.dtc:ReadDTCPrimitive",
                                },
                            ),
                            "ecu-reset": "gallia.commands.primitive.uds.ecu_reset:ECUResetPrimitive",
                            "vin": "gallia.commands.primitive.uds.vin:VINPrimitive",
                            "iocbi": "gallia.commands.primitive.uds.iocbi:IOCBIPrimitive",
                            "ping": "gallia.commands.primitive.uds.ping:PingPrimitive",
                            "rmba": "gallia.commands.primitive.uds.rmba:RMBAPrimitive",
                            "rtcl": "gallia.commands.primitive.uds.rtcl:RTCLPrimitive",
                            "pdu": "gallia.commands.primitive.uds.pdu:SendPDUPrimitive",
                            "wmba": "gallia.commands.primitive.uds.wmba:WMBAPrimitive",
                            "wdbi": "gallia.commands.primitive.uds.wdbi:WriteByIdentifierPrimitive",
                        },
                    ),
                    "generic": CommandTree(
                        description="generic networks primitives",
                        subtree={
                            "pdu": "gallia.commands.primitive.generic.pdu:GenericPDUPrimitive"
                        },
                    ),
                },
            ),
            "scan": CommandTree(
                description="scanners for network protocol parameters",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "memory": "gallia.commands.scan.uds.memory:MemoryFunctionsScanner",
                            "reset": "gallia.commands.scan.uds.reset:ResetScanner",
                            "dump-seeds": "gallia.commands.scan.uds.sa_dump_seeds:SASeedsDumper",
                            "identifiers": "gallia.commands.scan.uds.identifiers:ScanIdentifiers",
                            "sessions": "gallia.commands.scan.uds.sessions:SessionsScanner",
                            "services": "gallia.commands.scan.uds.services:ServicesScanner",
                        },
                    )
                },
            ),
            "script": CommandTree(
                description="miscellaneous helper scripts",
                subtree={"rerun": "gallia.commands.script.rerun:Rerunner"},
            ),
        }

        if sys.platform.startswith("linux"):
            tree["discover"].subtree.update(
                {
                    "isotp": "gallia.commands.discover.isotp:IsotpDiscoverer",
                }
            )

            tree.update(
                {
                    "fuzz": CommandTree(
                        description="fuzzing tools",
                        subtree={
                            "uds": CommandTree(
                                description="Universal Diagnostic Services",
                                subtree={"pdu": "gallia.commands.fuzz.uds.pdu:PDUFuzzer"},
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
                            "db": "gallia.commands.script.vecu:DbVirtualECU",
                            "rng": "gallia.commands.script.vecu:RngVirtualECU",
                        },
                    ),
                }
            )

        if sys.platform == "win32":
            tree["script"].subtree.update(
                {
                    "fr-dump": "gallia.commands.script.flexray:FRDump",
                    "fr-dump-config": "gallia.commands.script.flexray:FRConfigDump",
                }
            )

        return tree
