# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
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

        if args.tail:
            records = reader.pick_records(
                args.priority, start=-1, n=args.lines, reverse=True
            )
            for record in records:
                print(record)
            reader.close()
            return 0

        n = 0
        for priority in reader.priorities():
            if priority > args.priority:
                continue

            print(reader.current_record)

            n += 1
            if args.head and n == args.lines:
                break

    reader.close()

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
