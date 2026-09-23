# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import datetime
import json

import pytest

from gallia.cli.hr.filters import FilterError, RecordFilter
from gallia.log import PenlogPriority, PenlogRecord


def make_record(data: str, module: str = "scanner", tags: list[str] | None = None) -> PenlogRecord:
    return PenlogRecord(
        module=module,
        host="host",
        data=data,
        datetime=datetime.datetime(2020, 1, 1),
        priority=PenlogPriority.INFO,
        tags=tags,
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
