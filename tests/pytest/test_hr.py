# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import json

import pytest

from gallia.cli.hr.filters import FilterError, RecordFilter
from gallia.cli.hr.formatting import RecordFormatter
from gallia.log import PenlogPriority, PenlogRecord


def make_record(
    data: str,
    module: str = "scanner",
    tags: list[str] | None = None,
    proto: str | None = None,
) -> PenlogRecord:
    return PenlogRecord(
        module=module,
        host="host",
        data=data,
        datetime=datetime.datetime(2020, 1, 1),
        priority=PenlogPriority.INFO,
        tags=tags,
        _proto=proto,
    )


def test_filter() -> None:
    records = [make_record(f"record {n}", tags=["even"] if n % 2 == 0 else None) for n in range(10)]
    record_filter = RecordFilter("tag=even")
    assert [r.data for r in records if record_filter(r)] == [f"record {n}" for n in range(0, 10, 2)]


@pytest.mark.parametrize(
    ("text", "matches"),
    [
        ("", True),
        ("timeout", True),
        ("TIMEOUT", True),
        ("!timeout", False),
        ("absent", False),
        ("!absent", True),
        ("module=scanner", True),
        ("module=uds,scanner", True),
        ("module=scan", False),
        ("module!=scanner", False),
        ("module!=uds", True),
        ("tag=result", True),
        ("tag=info", True),
        ("tag=other", False),
        ("tag!=result", False),
        ("data~^got a", True),
        ("data~^timeout", False),
        ("data!~^timeout", True),
        ("'data~got a'", True),
        ('data~"got a Timeout"', True),
        ('data~"got a timeout"', False),
        ("module=scanner tag=result timeout", True),
        ("module=scanner tag=result absent", False),
        ("tag=", False),
        ("line=", True),
    ],
)
def test_filter_language(text: str, matches: bool) -> None:
    record = make_record("got a Timeout", tags=["result", "info"])
    record_filter = RecordFilter(text)
    assert record_filter(record) is matches
    # The fast check on the raw record must never exclude a match.
    raw = json.dumps({"module": record.module, "data": record.data, "tags": record.tags})
    if matches:
        assert record_filter.may_match(raw.encode())


def test_filter_raw_escaping() -> None:
    record = make_record('say "hi"', tags=['"quoted"'])
    raw = json.dumps({"module": record.module, "data": record.data, "tags": record.tags}).encode()
    for text in ["'say \"hi\"'", "tag='\"quoted\"'"]:
        record_filter = RecordFilter(text)
        assert record_filter(record)
        assert record_filter.may_match(raw)


@pytest.mark.parametrize("text", ["foo=bar", "data~(", "'unterminated"])
def test_filter_errors(text: str) -> None:
    assert not RecordFilter()
    with pytest.raises(FilterError):
        RecordFilter(text)


def test_view_zones() -> None:
    curses = pytest.importorskip("curses")
    del curses
    from gallia.cli.hr.tui import View

    info, debug, error = PenlogPriority.INFO, PenlogPriority.DEBUG, PenlogPriority.ERROR
    view = View(zones=((0, info),), filter=RecordFilter())

    view = view.with_priority(10, 20, debug, 100)
    assert view.zones == ((0, info), (10, debug), (20, info))
    assert [view.zone_index(i) for i in (0, 9, 10, 19, 20, 99)] == [0, 0, 1, 1, 2, 2]
    assert view.zone_bounds(1, 100) == (10, 20, debug)
    assert view.zone_bounds(2, 100) == (20, 100, info)

    # Overlapping from the left and merging of adjacent equal zones.
    assert view.with_priority(5, 15, info, 100).zones == ((0, info), (15, debug), (20, info))
    # Nested.
    assert view.with_priority(12, 14, error, 100).zones == (
        (0, info),
        (10, debug),
        (12, error),
        (14, debug),
        (20, info),
    )
    # Covering everything.
    assert view.with_priority(0, 100, error, 100).zones == ((0, error),)
    # Up to the end of the file.
    assert view.with_priority(15, 100, error, 100).zones == ((0, info), (10, debug), (15, error))


def test_formatter_default_is_console_format() -> None:
    record = make_record("hello", tags=["a", "b"])
    assert RecordFormatter().format(record) == str(record)


def test_formatter_aligns_continuation_lines() -> None:
    record = make_record("first\nsecond\n\nfourth")
    record.stacktrace = "Traceback:\n  line 1"
    indent = " " * len("Jan 01 00:00:00.000 scanner: ")
    assert RecordFormatter().format(record) == (
        "Jan 01 00:00:00.000 scanner: first\n"
        f"{indent}second\n"
        "\n"
        f"{indent}fourth\n"
        "\n"
        f"{indent}Traceback:\n"
        f"{indent}  line 1\n"
    )
    # Without the prefix, nothing is indented.
    assert RecordFormatter(prefix=False).format(record) == (
        "first\nsecond\n\nfourth\n\nTraceback:\n  line 1\n"
    )


def test_formatter_relative_timings() -> None:
    start = datetime.datetime(2020, 1, 1)
    records = [make_record(str(n)) for n in range(3)]
    records[1].datetime = start + datetime.timedelta(days=1, hours=2, minutes=3, seconds=4.567)
    records[2].datetime = start - datetime.timedelta(seconds=1)

    formatter = RecordFormatter(relative_timings=True)
    # Relative to the first formatted record.
    assert [formatter.format_timestamp(r.datetime).strip() for r in records] == [
        "+0d 00:00:00.000",
        "+1d 02:03:04.567",
        "-0d 00:00:01.000",
    ]
    assert formatter.format(records[1]).startswith("  +1d 02:03:04.567 scanner: 1")


def test_formatter_no_prefix() -> None:
    assert RecordFormatter(prefix=False).format(make_record("hello")) == "hello\n"


@pytest.mark.parametrize(
    ("data", "proto", "text", "color"),
    [
        ("22f190", "uds", "ReadDataByIdentifierRequest", "\033[36m"),
        # Records without protocol, e.g. of older logfiles, are dissected as UDS.
        ("7f2231", None, "NegativeResponse", "\033[38;5;208m"),
        ("0x7e8#30000000", "iso15765", "flow control", "\033[34m"),
        ("0x7e8#30000000", "can", None, None),
        ("no hex", None, None, None),
    ],
)
def test_formatter_dissect(
    data: str, proto: str | None, text: str | None, color: str | None
) -> None:
    record = make_record(data, proto=proto)
    line = RecordFormatter(prefix=False, dissect=True).format(record)
    if text is None:
        assert line == f"{data}\n"
    else:
        assert line.startswith(f"{data}  # ") and text in line
    # Without --dissect, nothing is added.
    assert RecordFormatter(prefix=False).format(record) == f"{data}\n"

    record.colors = True
    line = RecordFormatter(prefix=False, dissect=True).format(record)
    assert (f"{color}  # " in line) if color is not None else "  # " not in line


def test_filter_proto() -> None:
    assert RecordFilter("proto=uds")(make_record("22f190", proto="uds"))
    assert not RecordFilter("proto=uds")(make_record("22f190"))
    assert RecordFilter("proto=")(make_record("22f190"))
    raw = b'{"data": "22f190", "_proto": "uds"}'
    assert RecordFilter("proto=uds").may_match(raw)
    assert not RecordFilter("proto=can").may_match(raw)


GRAY = "\033[0;38;5;245m"


@pytest.mark.parametrize(
    ("priority", "style"),
    [
        (PenlogPriority.EMERGENCY, "\033[31m\033[1m"),
        (PenlogPriority.ALERT, "\033[31m\033[1m"),
        (PenlogPriority.CRITICAL, "\033[31m\033[1m"),
        (PenlogPriority.ERROR, "\033[31m"),
        (PenlogPriority.WARNING, "\033[33m"),
        (PenlogPriority.NOTICE, "\033[1m"),
        (PenlogPriority.INFO, ""),
        (PenlogPriority.DEBUG, GRAY),
        (PenlogPriority.TRACE, GRAY),
    ],
)
def test_console_colors(priority: PenlogPriority, style: str) -> None:
    record = make_record("hello")
    record.priority = priority
    record.colors = True
    # Only the data is colored; this is the same in hr --cursed.
    assert RecordFormatter().format(record) == f"Jan 01 00:00:00.000 scanner: {style}hello\033[0m\n"
