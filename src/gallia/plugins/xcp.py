# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from collections.abc import Mapping

from gallia.plugins.plugin import Command, CommandTree, Plugin


class XCPPlugin(Plugin):
    @classmethod
    def name(cls) -> str:
        return "Gallia XCP"

    @classmethod
    def description(cls) -> str:
        return "Default Gallia plugin for Universal Measurement and Calibration Protocol (XCP) functionality"

    @classmethod
    def commands(cls) -> Mapping[str, CommandTree | Command]:
        tree: dict[str, CommandTree | Command] = {}

        if sys.platform.startswith("linux"):
            tree = {
                "discover": CommandTree(
                    description=None,
                    subtree={"xcp": "gallia.commands.discover.find_xcp:CanFindXCP"},
                )
            }

        return tree
