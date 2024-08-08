import sys

from gallia.plugins.plugin import Command, CommandTree, Plugin


class XCPPlugin(Plugin):
    @classmethod
    def name(cls) -> str:
        return "Gallia XCP"

    @classmethod
    def description(cls) -> str:
        return "Default Gallia plugin for Universal Measurement and Calibration Protocol (XCP) functionality"

    @classmethod
    def commands(cls) -> dict[str, CommandTree | Command]:
        tree = {}

        if sys.platform.startswith("linux"):
            from gallia.commands.discover.find_xcp import (
                CanFindXCPConfig,
                FindXCP,
                TcpFindXCPConfig,
                UdpFindXCPConfig,
            )
            from gallia.commands.primitive.uds.xcp import SimpleTestXCP, SimpleTestXCPConfig

            tree = {
                "discover": CommandTree(
                    description=None,
                    subtree={
                        "xcp": CommandTree(
                            description="XCP enumeration scanner",
                            subtree={
                                "can": Command(
                                    description="XCP enumeration scanner for CAN",
                                    config=CanFindXCPConfig,
                                    command=FindXCP,
                                ),
                                "tcp": Command(
                                    description="XCP enumeration scanner for TCP",
                                    config=TcpFindXCPConfig,
                                    command=FindXCP,
                                ),
                                "udp": Command(
                                    description="XCP enumeration scanner for UDP",
                                    config=UdpFindXCPConfig,
                                    command=FindXCP,
                                ),
                            },
                        ),
                    }
                ),
                "primitive": CommandTree(
                    description=None,
                    subtree={
                        "xcp": Command(
                            description="XCP tester",
                            config=SimpleTestXCPConfig,
                            command=SimpleTestXCP,
                        )
                    }
                )
            }

        return tree
