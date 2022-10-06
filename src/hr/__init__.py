# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import gzip
import io
import logging
import sys
from collections.abc import Iterator, Sized
from pathlib import Path
from typing import Generic, TypeVar, cast

import zstandard

from gallia.log import ConsoleFormatter, PenlogPriority, PenlogRecord

T = TypeVar("T")


class RingBuffer(Sized, Generic[T]):
    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.write_ptr = 0
        self.read_ptr = 0
        self.data: list[T] = []

    def __len__(self) -> int:
        return len(self.data)

    def __iter__(self) -> Iterator[T]:
        if self.is_full:
            for i in range(self.read_ptr, self.read_ptr + len(self)):
                self.read_ptr = i % self.capacity
                yield self.data[self.read_ptr]
        else:
            yield from self.data

    @property
    def is_full(self) -> bool:
        if len(self) == self.capacity:
            return True
        return False

    def append(self, x: T) -> None:
        if self.is_full:
            self.data[self.write_ptr] = x
        else:
            self.data.append(x)

        if self.write_ptr == self.read_ptr:
            self.read_ptr = (self.read_ptr + 1) % self.capacity
        self.write_ptr = (self.write_ptr + 1) % self.capacity

    def get(self) -> T:
        res = self.data[self.read_ptr]
        self.read_ptr = (self.read_ptr + 1) % self.capacity
        return res


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
        "--tail-size",
        type=int,
        metavar="INT",
        default=1000,
        help="the maximal amount of parsed records for --tail",
    )
    return parser.parse_args()


def emit_tail(reader: io.BufferedReader, size: int) -> io.BufferedReader:
    buffer: RingBuffer[bytes] = RingBuffer(size)
    for line in reader.readlines():
        buffer.append(line)
    return io.BufferedReader(io.BytesIO(b"".join(buffer)))  # type: ignore


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

            if args.tail:
                reader = emit_tail(reader, args.tail_size)

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
