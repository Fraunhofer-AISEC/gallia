# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import gzip
import io
import logging
import sys
from pathlib import Path
from typing import cast

import zstandard

from gallia.log import (
    ConsoleFormatter,
    PenlogPriority,
    parse_penlog_record,
    priority_to_level,
)


def _PrioType(x: str) -> PenlogPriority:
    if x.isnumeric():
        return PenlogPriority(int(x, base=0))
    return PenlogPriority.from_str(x)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("FILE", nargs="+", type=Path)
    parser.add_argument(
        "-p",
        "--priority",
        type=_PrioType,
        default=PenlogPriority.INFO,
        help="maximal message priority",
    )
    return parser.parse_args()


def _main() -> int:
    args = parse_args()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ConsoleFormatter())

    if args.priority not in priority_to_level:
        print(f"invalid priority: {args.priority}", file=sys.stderr)
        return 1

    loglevel = priority_to_level[args.priority]
    handler.setLevel(loglevel)

    for file in args.FILE:
        file = cast(Path, file)

        with file.open("rb") as f:
            if file.suffix == ".zst":
                cctx = zstandard.ZstdDecompressor()
                reader = io.BufferedReader(cctx.stream_reader(f))  # type: ignore
            elif file.suffix == ".gz":
                reader = io.BufferedReader(gzip.GzipFile(fileobj=f))  # type: ignore
            else:
                reader = f

            while True:
                line = reader.readline().strip()
                if line == b"":
                    break

                penlog_record = parse_penlog_record(line)
                if penlog_record.priority > args.priority:
                    continue

                handler.emit(penlog_record.to_log_record())
    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
