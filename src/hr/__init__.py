# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import binascii
import os
import signal
import sys
from itertools import islice
from pathlib import Path
from typing import cast

import msgspec

from gallia import dissect, exitcodes
from gallia.log import ColorMode, PenlogPriority, PenlogReader, PenlogRecord, resolve_color_mode


def extract_tag_info(raw_tag: str) -> str:
    parts = raw_tag.split("=", maxsplit=2)
    if len(parts) != 2:
        raise ValueError()
    return parts[1]


def get_io_info(tags: list[str]) -> tuple[str, str]:
    found_iotype = False
    found_proto = False
    for tag in tags:
        if tag.startswith("io"):
            iotype = extract_tag_info(tag)
            found_iotype = True
        if tag.startswith("proto"):
            proto = extract_tag_info(tag)
            found_proto = True
        if found_iotype and found_proto:
            return iotype, proto
    raise ValueError()


def dissect_record(record: PenlogRecord) -> str | None:
    if record.tags is None:
        return None

    try:
        iotype, proto = get_io_info(record.tags)
    except ValueError:
        return None

    if proto not in dissect.registry:
        return None

    dissector = dissect.registry[proto]
    data = binascii.unhexlify(record.data)

    out = ""
    for field in dissector.dissect(data, iotype):
        out += f"{field.name}: {field.dissected_data}"
    return out


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
        help="argument for --head/--tail)",
    )
    parser.add_argument(
        "-d",
        "--dissect",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="dissect log messages with io and proto tags",
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
        path = cast(Path, file)
        if not (path.is_file() or path.is_fifo() or str(path) == "-"):
            print(f"not a regular file: {path}", file=sys.stderr)
            return 1

        colored = resolve_color_mode(ColorMode(args.color), stream=sys.stdout)

        with PenlogReader(path) as reader:
            record_generator = reader.records(args.priority, reverse=args.reverse)
            if args.head:
                record_generator = islice(record_generator, args.lines)
            elif args.tail:
                record_generator = reader.records(args.priority, offset=-args.lines)

            for record in record_generator:
                record.colored = colored
                if args.dissect:
                    # TODO: Maybe a method of the record? record.dissect()?
                    if (dissected := dissect_record(record)) is not None:
                        print(f"     {dissected}")
                    print(record, end="")
                else:
                    print(record, end="")

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except (msgspec.DecodeError, msgspec.ValidationError) as e:
        print(f"invalid file format: {e}", file=sys.stderr)
        sys.exit(exitcodes.DATAERR)
    # BrokenPipeError appears when stuff is piped to | head.
    # This is not an error for hr.
    except BrokenPipeError:
        # https://docs.python.org/3/library/signal.html#note-on-sigpipe
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(exitcodes.OK)
    except KeyboardInterrupt:
        sys.exit(128 + signal.SIGINT)


if __name__ == "__main__":
    main()
