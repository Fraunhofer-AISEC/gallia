# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os
import signal
import sys
import textwrap
from collections import deque
from collections.abc import Iterator
from itertools import islice
from pathlib import Path

from gallia import exitcodes
from gallia.cli.hr.filters import FILTER_SYNTAX, RecordFilter
from gallia.cli.hr.formatting import RecordFormatter
from gallia.log import (
    PenlogPriority,
    PenlogReader,
    PenlogRecord,
    guess_color_setting_for_stream,
    stream_raw_records,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Display penlog files in a human readable format",
        epilog="filter syntax:\n" + textwrap.indent(FILTER_SYNTAX, "  "),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
        "-f",
        "--filter",
        metavar="EXPR",
        type=RecordFilter.parse,
        default=RecordFilter(),
        help="only show matching records, e.g. 'module=scanner tag=result !timeout'; "
        "see the filter syntax below",
    )
    parser.add_argument(
        "-c",
        "--cursed",
        action="store_true",
        help="open the file in an interactive curses based viewer",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-t",
        "--tail",
        action="store_true",
        help="only print last -n/--lines lines",
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
        help="number of lines for --head and --tail",
    )

    output = parser.add_argument_group("output options")
    output.add_argument(
        "--prefix",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="show timestamp, module and tags",
    )
    output.add_argument(
        "--relative-timings",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="show timestamps relative to the first displayed record",
    )
    output.add_argument(
        "--interpret",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="interpret UDS messages; they appear as comments next to the original message",
    )

    cursed = parser.add_argument_group("cursed options")
    cursed.add_argument(
        "--theme",
        choices=["auto", "dark", "light"],
        default="auto",
        help="the background of the terminal, for highlighting the cursor line; "
        "auto asks the terminal (default: %(default)s)",
    )
    cursed.add_argument(
        "--no-mouse",
        dest="mouse",
        action="store_false",
        help="disable the mouse (clicking and scrolling), e.g. for selecting text "
        "without holding Shift",
    )
    cursed.add_argument(
        "--terminal-progress",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="show the loading progress in the terminal's native progress bar (OSC 9;4); "
        "default: auto",
    )

    args = parser.parse_args()
    if args.cursed and len(args.FILE) > 1:
        parser.error("--cursed supports only a single FILE")
    return args


def _select_records(path: Path, args: argparse.Namespace) -> Iterator[PenlogRecord]:
    record_filter: RecordFilter = args.filter

    if args.reverse:
        # Needs random access; the only case which needs a temporary file
        # for compressed files.
        with PenlogReader(path) as reader:
            reverse = reader.records(args.priority, reverse=True)
            yield from filter(record_filter, reverse) if record_filter else reverse
            if reader.error is not None:
                raise reader.error
        return

    # Everything else streams the file with constant memory usage.
    lines = stream_raw_records(path, args.priority)
    if record_filter:
        # The fast check on the raw record avoids parsing most records.
        lines = filter(record_filter.may_match, lines)
    if args.tail and not record_filter:
        # Only parse the last records.
        lines = iter(deque(lines, maxlen=args.lines))

    records: Iterator[PenlogRecord] = map(PenlogRecord.parse_json, lines)
    if record_filter:
        records = filter(record_filter, records)
    if args.head:
        records = islice(records, args.lines)
    elif args.tail and record_filter:
        records = iter(deque(records, maxlen=args.lines))
    yield from records


def _main() -> int:
    args = parse_args()

    for path in args.FILE:
        if not (path.is_file() or path.is_fifo() or str(path) == "-"):
            print(f"not a regular file: {path}", file=sys.stderr)
            return 1

    formatter = RecordFormatter(
        prefix=args.prefix,
        relative_timings=args.relative_timings,
        interpret=args.interpret,
    )

    if args.cursed:
        from gallia.cli.hr.tui import run

        run(
            args.FILE[0],
            priority=args.priority,
            record_filter=args.filter,
            formatter=formatter,
            terminal_progress=args.terminal_progress,
            theme=args.theme,
            mouse=args.mouse,
        )
        return 0

    colors = guess_color_setting_for_stream(sys.stdout)

    for path in args.FILE:
        for record in _select_records(path, args):
            record.colors = colors
            print(formatter.format(record), end="")

    return 0


def main() -> None:
    try:
        sys.exit(_main())
    except json.JSONDecodeError as e:
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
    # After BrokenPipeError, which is an OSError as well.
    except OSError as e:
        print(f"hr: {e}", file=sys.stderr)
        sys.exit(exitcodes.IOERR)


if __name__ == "__main__":
    main()
