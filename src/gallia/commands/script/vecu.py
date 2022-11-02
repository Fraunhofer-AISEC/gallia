# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# pylint: disable=eval-used

import json
import random
import sys
from argparse import Namespace
from pathlib import Path

from gallia.command import AsyncScript
from gallia.services.uds.core.constants import UDSIsoServices
from gallia.services.uds.server import (
    DBUDSServer,
    ISOTPUDSServerTransport,
    RandomUDSServer,
    TCPUDSServerTransport,
    UDSServer,
    UDSServerTransport,
)
from gallia.transports import ISOTPTransport, TargetURI
from gallia.transports.tcp import TCPLinesTransport

dynamic_attr_prefix = "dynamic_attr_"


class VirtualECU(AsyncScript):
    """Spawn a virtual ECU for testing purposes"""

    COMMAND = "vecu"
    SHORT_HELP = "spawn a virtual UDS ECU"
    EPILOG = "https://fraunhofer-aisec.github.io/gallia/uds/virtual_ecu.html"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "target",
            type=TargetURI,
        )

        sub_parsers = self.parser.add_subparsers(dest="cmd")
        sub_parsers.required = True

        db = sub_parsers.add_parser("db")
        db.add_argument(
            "path",
            type=Path,
        )
        db.add_argument("--ecu", type=str)
        db.add_argument("--properties", type=json.loads)
        # db.set_defaults(yolo=True)

        rng = sub_parsers.add_parser("rng")
        rng.add_argument(
            "--seed",
            default=random.randint(0, sys.maxsize),
            help="Set the seed of the internal random number generator. This supports reproducibility.",
        )

        # Expose all other parameters of the random UDS server
        tmp = RandomUDSServer(0)
        parent_attrs = True

        for v in tmp.__dict__:
            if parent_attrs:
                if v == "seed":
                    parent_attrs = False

                if v.startswith("use_default_response_if"):
                    self.parser.add_argument(f"--{v}", dest=f"{dynamic_attr_prefix}{v}")

                continue

            if not v.startswith("_"):
                rng.add_argument(f"--{v}", dest=f"{dynamic_attr_prefix}{v}")

    async def main(self, args: Namespace) -> None:
        cmd: str = args.cmd
        server: UDSServer

        if cmd == "db":
            server = DBUDSServer(args.path, args.ecu, args.properties)
        elif cmd == "rng":
            server = RandomUDSServer(args.seed)
        else:
            assert False

        for key, value in vars(args).items():
            if key.startswith(dynamic_attr_prefix) and value is not None:
                setattr(
                    server,
                    key[len(dynamic_attr_prefix) :],
                    eval(
                        value,
                        {service.name: service for service in UDSIsoServices},
                    ),
                )

        target: TargetURI = args.target
        transport: UDSServerTransport

        if target.scheme == TCPLinesTransport.SCHEME:
            transport = TCPUDSServerTransport(server, target)
        elif target.scheme == ISOTPTransport.SCHEME:
            transport = ISOTPUDSServerTransport(server, target)
        else:
            self.logger.error(
                f"Unsupported transport scheme! Use any of ["
                f"{TCPLinesTransport.SCHEME}, {ISOTPTransport.SCHEME}]"
            )
            sys.exit(1)

        try:
            await server.setup()
            await transport.run()
        finally:
            await server.teardown()
