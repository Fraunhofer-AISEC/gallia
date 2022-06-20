# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

# import os
# from argparse import Namespace
#
# from gallia.udscan.core import AsyncScript
# from opennetzteil import PowerSupply, PowerSupplyURI
#
#
# class CLI(AsyncScript):
#
#     def add_parser(self):
#         self.parser.add_argument(
#             "-u",
#             "--power-supply",
#             metavar="URI",
#             default=os.environ.get("GALLIA_POWER_SUPPLY"),
#             type=PowerSupplyURI,
#             help="URI specifying the location of the relevant opennetzteil server",
#         )
#
#         group = self.parser.add_mutually_exclusive_group()
#         group.add_argument("-m", "--master", help="get or set master channel")
#
#     async def main(args: Namespace):
#         power_supply = await PowerSupply.connect(args.power_supply)
#
#         if
