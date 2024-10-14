# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from collections.abc import Mapping

from gallia.command import BaseCommand
from gallia.plugins.plugin import CommandTree, Plugin


class XCPPlugin(Plugin):
    @classmethod
    def name(cls) -> str:
        return "Gallia XCP"

    @classmethod
    def description(cls) -> str:
        return "Default Gallia plugin for Universal Measurement and Calibration Protocol (XCP) functionality"

    @classmethod
    def commands(cls) -> Mapping[str, CommandTree | type[BaseCommand]]:
        tree: dict[str, CommandTree | type[BaseCommand]] = {}

        if sys.platform.startswith("linux"):
            from gallia.commands.discover.find_xcp import CanFindXCP, TcpFindXCP, UdpFindXCP
            from gallia.commands.primitive.uds.xcp import SimpleTestXCP

            tree = {
                "discover": CommandTree(
                    description=None,
                    subtree={
                        "xcp": CommandTree(
                            description="XCP enumeration scanner",
                            subtree={
                                "can": CanFindXCP,
                                "tcp": TcpFindXCP,
                                "udp": UdpFindXCP,
                            },
                        ),
                    },
                ),
                "primitive": CommandTree(
                    description=None,
                    subtree={
                        "xcp": SimpleTestXCP,
                    },
                ),
            }

        return tree
