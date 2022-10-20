# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
from itertools import islice
from pathlib import Path
from typing import cast

from gallia.log import PenlogPriority, PenlogReader


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("FILE", nargs="+", type=Path)
    parser.add_argument(
        "-p",
        "--priority",
        metavar="PRIO",
        type=PenlogPriority.from_str,
        default=PenlogPriority.INFO,
        help="maximal message priority",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-t",
        "--tail",
        action="store_true",
        help="jump to tail while parsing max. -n/--lines lines",
    )
    group.add_argument(
        "--head",
        action="store_true",
        help="only print first -n/--lines lines",
    )
    group.add_argument(
        "-r",
        "--reverse",
        action="store_true",
        help="print the log records in reverse order",
    )
    parser.add_argument(
        "-n",
        "--lines",
        type=int,
        default=100,
        help="print the last n lines",
    )
    return parser.parse_args()


def _main() -> int:
    args = parse_args()

    for file in args.FILE:
        file = cast(Path, file)
        if not file.is_file():
            print(f"not a regular file: {file}", file=sys.stderr)
            return 1

        reader = PenlogReader(file)

        record_generator = reader.records(args.priority, reverse=args.reverse)
        if args.head:
            record_generator = islice(record_generator, args.lines)
        elif args.tail:
            record_generator = reader.records(args.priority, offset=-args.lines)

        for record in record_generator:
            print(record)

    reader.close()

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
