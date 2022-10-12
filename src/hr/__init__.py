# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import io
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
    parser.add_argument(
        "-t",
        "--tail",
        action="store_true",
        help="jump to tail while parsing max. --tail-size records",
    )
    parser.add_argument(
        "--tail-position",
        type=float,
        metavar="FLOAT",
        default=0.95,
        help="start at offset = filesize * `FLOAT`",
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
            reader.seek(0, io.SEEK_END)
            reader.seek(int(args.tail_position * reader.tell()))
            # Drop current line which is most likely incomplete.
            reader.readline()

        for priority in reader.priorities():
            if priority > args.priority:
                continue

            print(reader.current_record)

    reader.close()

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
