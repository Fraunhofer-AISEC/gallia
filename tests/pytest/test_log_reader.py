# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

import gzip
import json
import random
import re
import sys
from pathlib import Path

import pytest

from gallia.log import (
    Loglevel,
    PenlogPriority,
    PenlogReader,
    PenlogRecord,
    add_zst_log_handler,
    get_logger,
    remove_zst_log_handler,
    stream_raw_records,
    stream_records,
)

if sys.version_info < (3, 14):
    import zstandard as zstd
else:
    from compression import zstd

# The priority of the n-th record; covers all priorities in varying order.
PRIORITIES = [6, 7, 8, 3, 6, 5, 8, 8, 4, 6, 0, 7]


def make_line(n: int, priority: int, prefix: bool) -> str:
    record = {
        "module": "test",
        "host": "host",
        "data": f"record {n}",
        "datetime": "2020-04-23T15:21:50.620310",
        "priority": priority,
        "version": 2,
        "tags": ["even"] if n % 2 == 0 else None,
    }
    return (f"<{priority}>" if prefix else "") + json.dumps(record) + "\n"


@pytest.fixture(params=["plain", "prefix", "zst", "gz"])
def logfile(request: pytest.FixtureRequest, tmp_path: Path) -> Path:
    content = "".join(
        make_line(n, p, request.param != "plain") for n, p in enumerate(PRIORITIES)
    ).encode()
    match request.param:
        case "zst":
            path = tmp_path / "log.json.zst"
            path.write_bytes(zstd.compress(content))
        case "gz":
            path = tmp_path / "log.json.gz"
            path.write_bytes(gzip.compress(content))
        case _:
            path = tmp_path / "log.json"
            path.write_bytes(content)
    return path


def data(records: list[int]) -> list[str]:
    return [f"record {n}" for n in records]


def expected(priority: int) -> list[int]:
    return [n for n, p in enumerate(PRIORITIES) if p <= priority]


def test_index(logfile: Path) -> None:
    with PenlogReader(logfile) as reader:
        assert len(reader) == len(PRIORITIES)
        assert [reader.priority(i) for i in range(len(reader))] == PRIORITIES
        assert reader[3].data == "record 3"
        assert reader[-1].data == f"record {len(PRIORITIES) - 1}"


@pytest.mark.parametrize("priority", list(PenlogPriority))
def test_records(logfile: Path, priority: PenlogPriority) -> None:
    with PenlogReader(logfile) as reader:
        assert [r.data for r in reader.records(priority)] == data(expected(priority))
        assert [r.data for r in reader.records(priority, reverse=True)] == data(
            expected(priority)[::-1]
        )
        assert [r.data for r in reader.records(priority, offset=5)] == data(
            [n for n in expected(priority) if n >= 5]
        )
        assert [r.data for r in reader.records(priority, offset=-3)] == data(
            [n for n in expected(priority) if n >= len(PRIORITIES) - 3]
        )


def test_find(logfile: Path) -> None:
    with PenlogReader(logfile) as reader:
        assert reader.find(PenlogPriority.ERROR) == 3
        assert reader.find(PenlogPriority.ERROR, 4) == 10
        assert reader.find(PenlogPriority.ERROR, 4, 10) is None
        assert reader.find(PenlogPriority.EMERGENCY, 11) is None
        assert reader.rfind(PenlogPriority.ERROR) == 10
        assert reader.rfind(PenlogPriority.ERROR, 0, 10) == 3
        assert reader.rfind(PenlogPriority.ERROR, 4, 10) is None
        assert reader.rfind(PenlogPriority.TRACE, 0, 5) == 4


def test_broken_and_blank_lines(tmp_path: Path) -> None:
    path = tmp_path / "log.json"
    path.write_text(make_line(0, 6, False) + "\n  \nno json\n" + make_line(1, 7, False))
    with PenlogReader(path) as reader:
        assert len(reader) == 3
        # Broken records are reported as errors to make them visible.
        assert reader.priority(1) == PenlogPriority.ERROR
        assert reader.raw(1) == b"no json"
        with pytest.raises(json.JSONDecodeError):
            reader[1]
        assert reader[2].data == "record 1"


def test_broken_priorities(tmp_path: Path) -> None:
    path = tmp_path / "log.json"
    path.write_text('<\n{"priority":\n{"priority": 9}\n' + make_line(0, 6, False))
    priorities = [PenlogPriority.ERROR] * 3 + [PenlogPriority.INFO]
    with PenlogReader(path) as reader:
        assert [reader.priority(i) for i in range(len(reader))] == priorities
    assert len(list(stream_raw_records(path, PenlogPriority.ERROR))) == 3
    assert len(list(stream_raw_records(path, PenlogPriority.INFO))) == 4


def test_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "log.json"
    path.touch()
    with PenlogReader(path) as reader:
        assert len(reader) == 0
        assert list(reader.records()) == []
        assert list(reader.records(reverse=True)) == []
        assert reader.find(PenlogPriority.TRACE) is None


def test_search(logfile: Path) -> None:
    even = re.compile(rb'"even"')
    with PenlogReader(logfile) as reader:
        assert reader.search(even) == 0
        assert reader.search(even, 1) == 2
        assert reader.search(even, 1, 2) is None
        assert reader.rsearch(even) == len(PRIORITIES) - 2
        assert reader.rsearch(even, 0, 10) == 8
        assert reader.rsearch(even, 9, 10) is None


def test_incremental_index(logfile: Path) -> None:
    record_9 = re.compile(rb'"record 9"')
    with PenlogReader(logfile) as reader:
        while reader.indexed < 5:
            assert not reader.update_index(max_records=5 - reader.indexed)
        assert reader.indexed == 5
        assert not reader.index_complete
        # Searches must not look beyond the index.
        assert reader.search(record_9, 0, 5) is None
        assert reader.rsearch(record_9, 0, 5) is None
        # Random access only indexes as far as needed.
        assert reader.find(PenlogPriority.ERROR, 0, 4) == 3
        assert reader.indexed == 5
        assert reader.priority(7) == PRIORITIES[7]
        assert reader.indexed > 7
        while not reader.update_index(max_records=5):
            pass
        assert reader.index_complete
        assert reader.index_progress == 1.0
        assert reader.find(PenlogPriority.ERROR, 4) == 10
        assert reader.search(record_9) == reader.rsearch(record_9) == 9


@pytest.mark.parametrize("suffix", [".zst", ".gz"])
def test_truncated_file(tmp_path: Path, suffix: str) -> None:
    content = "".join(make_line(n, 6, False) for n in range(2000)).encode()
    compressed = zstd.compress(content) if suffix == ".zst" else gzip.compress(content)
    path = tmp_path / f"log.json{suffix}"
    path.write_bytes(compressed[: len(compressed) // 2])

    with PenlogReader(path) as reader:
        records = [r.data for r in reader.records()]
        assert isinstance(reader.error, OSError)
        # Everything before the damaged part is available; incomplete
        # records are dropped.
        assert 0 < len(records) < 2000
        assert records == data(list(range(len(records))))

    with pytest.raises(OSError, match="reading"):
        streamed = []
        for record in stream_records(path):
            streamed.append(record.data)
    # Streaming returns the same records before the error.
    assert streamed == records


@pytest.mark.parametrize("priority", list(PenlogPriority))
def test_stream(logfile: Path, priority: PenlogPriority) -> None:
    assert [r.data for r in stream_records(logfile, priority)] == data(expected(priority))
    raw = list(stream_raw_records(logfile, priority))
    assert [PenlogRecord.parse_json(r).data for r in raw] == data(expected(priority))


def test_index_progress(tmp_path: Path) -> None:
    # Random data compresses badly; zstd reads the input in 128 KiB blocks,
    # which determines the granularity of the progress.
    rng = random.Random(0)
    content = "".join(
        make_line(n, 6, False).replace(f"record {n}", rng.randbytes(64).hex()) for n in range(20000)
    ).encode()
    path = tmp_path / "log.json.zst"
    path.write_bytes(zstd.compress(content))

    with PenlogReader(path) as reader:
        # Use small chunks to get several progress steps.
        reader.SPOOL_CHUNK_SIZE = 0x10000
        progress = [reader.index_progress]
        while not reader.update_index(1000):
            progress.append(reader.index_progress)
        progress.append(reader.index_progress)

    assert all(p is not None for p in progress)
    assert progress == sorted(progress)  # type: ignore[type-var]
    assert progress[0] == 0.0
    assert progress[-1] == 1.0
    assert len(set(progress)) > 3


def test_zst_multiple_frames(tmp_path: Path) -> None:
    # E.g. concatenated logfiles; all frames are read.
    frames = [
        "".join(make_line(n, 6, False) for n in range(start, start + 500)).encode()
        for start in (0, 500, 1000)
    ]
    path = tmp_path / "log.json.zst"
    path.write_bytes(b"".join(zstd.compress(frame) for frame in frames))

    assert [r.data for r in stream_records(path)] == data(list(range(1500)))
    with PenlogReader(path) as reader:
        assert len(reader) == 1500
        assert reader.error is None
        assert reader[-1].data == "record 1499"


def test_logger_reports_the_callers_line(tmp_path: Path) -> None:
    path = tmp_path / "log.json.zst"
    handler = add_zst_log_handler("test_line", path, Loglevel.TRACE)
    logger = get_logger("test_line")
    logger.setLevel(Loglevel.TRACE)
    line = sys._getframe().f_lineno + 2
    for log in (logger.trace, logger.debug, logger.notice, logger.result):
        log("message")
    remove_zst_log_handler("test_line", handler)

    for record in stream_records(path):
        assert record.line == f"{__file__}:{line}", record.data
        assert record._python_func_name == "test_logger_reports_the_callers_line"
