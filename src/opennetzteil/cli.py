# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import sys
from argparse import ArgumentParser, Namespace

from gallia.command import AsyncScript
from gallia.config import load_config_file
from gallia.powersupply import PowerSupplyURI
from gallia.utils import strtobool
from opennetzteil import netzteile


class CLI(AsyncScript):
    COMMAND = "netzteil-cli"

    def configure_parser(self) -> None:
        self.parser.add_argument(
            "-t",
            "--target",
            metavar="URI",
            type=PowerSupplyURI,
            default=self.config.get_value(
                "opennetzteil.target",
                self.config.get_value("gallia.scanner.power_supply"),
            ),
            help="URI specifying the location of the powersupply",
        )
        self.parser.add_argument(
            "-c",
            "--channel",
            type=int,
            required=True,
            help="the channel number to control",
        )
        self.parser.add_argument(
            "-a",
            "--attr",
            choices=["voltage", "current", "output"],
            required=True,
            help="the attribute to control",
        )

        subparsers = self.parser.add_subparsers()

        get_parser = subparsers.add_parser("get")
        get_parser.set_defaults(subcommand="get")

        set_parser = subparsers.add_parser("set")
        set_parser.set_defaults(subcommand="set")
        set_parser.add_argument("VALUE")

    async def setup(self, args: Namespace) -> None:
        if args.target is None:
            self.parser.error("specify -t/--target!")

    async def main(self, args: Namespace) -> None:
        for netzteil in netzteile:
            if args.target.product_id == netzteil.PRODUCT_ID:
                client = await netzteil.connect(args.target, timeout=1.0)
                break
        else:
            self.parser.error(
                f"powersupply {args.power_supply.product_id} is not supported"
            )

        match args.subcommand:
            case "get":
                match args.attr:
                    case "voltage":
                        print(await client.get_voltage(args.channel))
                    case "current":
                        print(await client.get_current(args.channel))
                    case "output":
                        if args.channel == 0:
                            print(await client.get_master())
                        else:
                            print(await client.get_output(args.channel))
            case "set":
                match args.attr:
                    case "voltage":
                        await client.set_voltage(args.channel, float(args.VALUE))
                    case "current":
                        await client.set_current(args.channel, float(args.VALUE))
                    case "output":
                        if args.channel == 0:
                            await client.set_master(strtobool(args.VALUE))
                        else:
                            await client.set_output(args.channel, strtobool(args.VALUE))


def main() -> None:
    parser = ArgumentParser()
    config, _ = load_config_file()
    cli = CLI(parser, config)
    sys.exit(cli.entry_point(parser.parse_args()))


if __name__ == "__main__":
    main()
