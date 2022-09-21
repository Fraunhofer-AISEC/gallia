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

from gallia.log import ConsoleFormatter, PenlogPriority, PenlogRecord


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("FILE", nargs="+", type=Path)
    parser.add_argument(
        "-p",
        "--priority",
        type=PenlogPriority.from_str,
        default=PenlogPriority.INFO,
        help="maximal message priority",
    )
    return parser.parse_args()


def _main() -> int:
    args = parse_args()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(ConsoleFormatter())
    handler.setLevel(args.priority.to_level())

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

                log_record = PenlogRecord.parse_json(line)
                if log_record.priority > args.priority:
                    continue

                handler.emit(log_record.to_log_record())
    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
