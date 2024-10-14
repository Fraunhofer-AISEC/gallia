# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from collections.abc import Mapping

from gallia.command import BaseCommand
from gallia.commands import HSFZDiscoverer
from gallia.commands.discover.doip import DoIPDiscoverer
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
from gallia.commands.primitive.uds.rdbi import (
    ReadByIdentifierPrimitive,
)
from gallia.commands.primitive.uds.rmba import RMBAPrimitive
from gallia.commands.primitive.uds.rtcl import RTCLPrimitive
from gallia.commands.primitive.uds.vin import VINPrimitive
from gallia.commands.primitive.uds.wdbi import (
    WriteByIdentifierPrimitive,
)
from gallia.commands.primitive.uds.wmba import WMBAPrimitive
from gallia.commands.scan.uds.identifiers import ScanIdentifiers
from gallia.commands.scan.uds.memory import MemoryFunctionsScanner
from gallia.commands.scan.uds.reset import ResetScanner
from gallia.commands.scan.uds.sa_dump_seeds import SASeedsDumper
from gallia.commands.scan.uds.services import ServicesScanner
from gallia.commands.scan.uds.sessions import SessionsScanner
from gallia.commands.script.rerun import Rerunner
from gallia.commands.script.vecu import DbVirtualECU, RngVirtualECU
from gallia.plugins.plugin import CommandTree, Plugin
from gallia.services.uds import ECU
from gallia.transports import BaseTransport, registry


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
    def commands(cls) -> Mapping[str, CommandTree | type[BaseCommand]]:
        tree = {
            "discover": CommandTree(
                description="discover scanners for hosts and endpoints",
                subtree={"doip": DoIPDiscoverer, "hsfz": HSFZDiscoverer},
            ),
            "primitive": CommandTree(
                description="protocol specific primitives",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "rdbi": ReadByIdentifierPrimitive,
                            "dtc": CommandTree(
                                description="DiagnosticTroubleCodes",
                                subtree={
                                    "clear": ClearDTCPrimitive,
                                    "control": ControlDTCPrimitive,
                                    "read": ReadDTCPrimitive,
                                },
                            ),
                            "ecu-reset": ECUResetPrimitive,
                            "vin": VINPrimitive,
                            "iocbi": IOCBIPrimitive,
                            "ping": PingPrimitive,
                            "rmba": RMBAPrimitive,
                            "rtcl": RTCLPrimitive,
                            "pdu": SendPDUPrimitive,
                            "wmba": WMBAPrimitive,
                            "wdbi": WriteByIdentifierPrimitive,
                        },
                    ),
                    "generic": CommandTree(
                        description="generic networks primitives",
                        subtree={"pdu": GenericPDUPrimitive},
                    ),
                },
            ),
            "scan": CommandTree(
                description="scanners for network protocol parameters",
                subtree={
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "memory": MemoryFunctionsScanner,
                            "reset": ResetScanner,
                            "dump-seeds": SASeedsDumper,
                            "identifiers": ScanIdentifiers,
                            "sessions": SessionsScanner,
                            "services": ServicesScanner,
                        },
                    )
                },
            ),
            "script": CommandTree(
                description="miscellaneous helper scripts",
                subtree={"rerun": Rerunner},
            ),
        }

        if sys.platform.startswith("linux"):
            from gallia.commands.discover.uds.isotp import IsotpDiscoverer
            from gallia.commands.fuzz.uds.pdu import PDUFuzzer

            tree["discover"].subtree.update(
                {
                    "uds": CommandTree(
                        description="Universal Diagnostic Services",
                        subtree={
                            "isotp": IsotpDiscoverer,
                        },
                    ),
                }
            )

            tree.update(
                {
                    "fuzz": CommandTree(
                        description="fuzzing tools",
                        subtree={
                            "uds": CommandTree(
                                description="Universal Diagnostic Services",
                                subtree={"pdu": PDUFuzzer},
                            )
                        },
                    ),
                }
            )

            tree["script"].subtree.update(
                {
                    "vecu": CommandTree(
                        description="spawn a virtual UDS ECU",
                        subtree={"db": DbVirtualECU, "rng": RngVirtualECU},
                    ),
                }
            )

        if sys.platform == "win32":
            from gallia.commands.script.flexray import (
                FRConfigDump,
                FRDump,
            )

            tree["script"].subtree.update(
                {
                    "fr-dump": FRDump,
                    "fr-dump-config": FRConfigDump,
                }
            )

        return tree
