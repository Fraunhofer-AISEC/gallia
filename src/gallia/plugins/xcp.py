# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

__lazy_modules__ = {"gallia.commands"}

import sys
from collections.abc import Mapping

from gallia.plugins.plugin import Command, CommandTree, Plugin

if sys.platform.startswith("linux"):
    from gallia.commands import CanFindXCP


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
                    subtree={"xcp": lambda: CanFindXCP},
                )
            }

        return tree
