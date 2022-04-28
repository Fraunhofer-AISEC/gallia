import asyncio
import binascii
import random
from argparse import BooleanOptionalAction, Namespace

from gallia.udscan.core import Scanner


class Floody(Scanner):
    def add_parser(self) -> None:
        self.parser.set_defaults(tester_present=False)

        self.parser.add_argument(
            "--randomize-dst-addr",
            action=BooleanOptionalAction,
            default=True,
            help="randomize the dst_addr",
        )
        self.parser.add_argument(
            "--randomize-data",
            action=BooleanOptionalAction,
            default=True,
            help="randomize the payload",
        )
        self.parser.add_argument(
            "--data",
            type=binascii.unhexlify,
            default=bytes([0xAF, 0xFE]),
            help="static payload in case randomize is off",
        )
        self.parser.add_argument(
            "--sleep",
            type=float,
            default=0.01,
            help="time to sleep between messages",
        )
        self.parser.add_argument(
            "-l",
            "--len",
            type=int,
            default=8,
            help="payload length",
        )
        self.parser.add_argument(
            "--max-dst-addr",
            type=int,
            default=0x7FF,
            help="the highest dst_addr in case it is randomized",
        )
        self.parser.add_argument(
            "--min-dst-addr",
            type=int,
            default=1,
            help="the lowest dst_addr in case it is randomized",
        )

    def get_dst_addr(self, args: Namespace) -> int:
        if args.randomize_dst_addr:
            return random.randint(args.min_dst_addr, args.max_dst_addr)
        if not args.target.dst_addr:
            self.parser.error("please provide dst_addr in the argument to --target")
        return args.target.dst_addr

    def get_payload(self, args: Namespace) -> bytes:
        if args.randomize_data:
            return random.randbytes(random.randint(1, args.len))
        return args.data

    async def main(self, args: Namespace) -> None:
        assert self.transport

        while True:
            id_ = self.get_dst_addr(args)
            payload = self.get_payload(args)
            await self.transport.sendto(payload, id_)
            await asyncio.sleep(args.sleep)
