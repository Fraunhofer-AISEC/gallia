# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
from itertools import islice
from pathlib import Path
from typing import cast

import msgspec

from gallia.log import ColorMode, PenlogPriority, PenlogReader, set_color_mode


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
    parser.add_argument(
        "--color",
        choices=["auto", "always", "never"],
        default="auto",
        help="when to use terminal colors",
    )
    return parser.parse_args()


def _main() -> int:
    args = parse_args()

    for file in args.FILE:
        file = cast(Path, file)
        if not (file.is_file() or file.is_fifo() or file != "-"):
            print(f"not a regular file: {file}", file=sys.stderr)
            return 1

        set_color_mode(ColorMode(args.color), stream=sys.stdout)

        with PenlogReader(file) as reader:
            record_generator = reader.records(args.priority, reverse=args.reverse)
            if args.head:
                record_generator = islice(record_generator, args.lines)
            elif args.tail:
                record_generator = reader.records(args.priority, offset=-args.lines)

            for record in record_generator:
                print(record)

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except (msgspec.DecodeError, msgspec.ValidationError) as e:
        print(f"invalid file format: {e}", file=sys.stderr)
    # BrokenPipeError appears when stuff is piped to | head.
    except (KeyboardInterrupt, BrokenPipeError):
        pass


if __name__ == "__main__":
    main()
