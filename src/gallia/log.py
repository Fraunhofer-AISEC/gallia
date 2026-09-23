# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import atexit
import dataclasses
import datetime
import gzip
import io
import json
import logging
import mmap
import os
import re
import shutil
import socket
import sys
import tempfile
import textwrap
import time
import traceback
from array import array
from bisect import bisect_right
from collections.abc import Iterator
from enum import Enum, IntEnum, unique
from logging.handlers import QueueHandler, QueueListener
from pathlib import Path
from queue import Queue
from types import TracebackType
from typing import Any, BinaryIO, Self, TextIO, TypeAlias, cast

import platformdirs

if sys.version_info < (3, 14):
    import zstandard as zstd
else:
    from compression import zstd

gmt_offset = time.localtime().tm_gmtoff
tz = datetime.timezone(datetime.timedelta(seconds=gmt_offset))


def guess_color_setting_for_stream(stream: TextIO) -> bool:
    if sys.platform == "win32":
        return False
    # https://no-color.org/
    if os.getenv("NO_COLOR") is not None:
        return False
    return stream.isatty()


# https://stackoverflow.com/a/35804945
def _add_logging_level(level_name: str, level_num: int) -> None:
    method_name = level_name.lower()

    if hasattr(logging, level_name):
        raise AttributeError(f"{level_name} already defined in logging module")
    if hasattr(logging, method_name):
        raise AttributeError(f"{method_name} already defined in logging module")
    if hasattr(logging.getLoggerClass(), method_name):
        raise AttributeError(f"{method_name} already defined in logger class")

    # This method was inspired by the answers to Stack Overflow post
    # http://stackoverflow.com/q/2183233/2988730, especially
    # http://stackoverflow.com/a/13638084/2988730
    def for_level(self, message, *args, **kwargs):  # type: ignore[no-untyped-def]
        if self.isEnabledFor(level_num):
            # Report the caller of this method, not this method.
            kwargs["stacklevel"] = kwargs.get("stacklevel", 1) + 1
            self._log(
                level_num,
                message,
                args,
                **kwargs,
            )

    def to_root(message, *args, **kwargs):  # type: ignore[no-untyped-def]
        logging.log(level_num, message, *args, **kwargs)  # noqa: LOG015

    logging.addLevelName(level_num, level_name)
    setattr(logging, level_name, level_num)
    setattr(logging.getLoggerClass(), method_name, for_level)
    setattr(logging, method_name, to_root)


_add_logging_level("TRACE", 5)
_add_logging_level("NOTICE", 25)


@unique
class Loglevel(IntEnum):
    """A wrapper around the constants exposed by python's
    ``logging`` module. Since gallia adds two additional
    loglevel's (``NOTICE`` and ``TRACE``), this class
    provides a type safe way to access the loglevels.
    The level ``NOTICE`` was added to conform better to
    RFC3164. Subsequently, ``TRACE`` was added to have
    a facility for optional debug messages.
    Loglevel describes python specific values for loglevels
    which are required to integrate with the python ecosystem.
    For generic priority values, see :class:`PenlogPriority`.
    """

    CRITICAL = logging.CRITICAL
    ERROR = logging.ERROR
    WARNING = logging.WARNING
    NOTICE = logging.NOTICE  # type: ignore[attr-defined]
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    TRACE = logging.TRACE  # type: ignore[attr-defined]


@unique
class PenlogPriority(IntEnum):
    """PenlogPriority holds the values which are written
    to json log records. These values conform to RFC3164
    with the addition of ``TRACE``. Since Python uses different
    int values for the loglevels, there are two enums in
    gallia describing loglevels. PenlogPriority describes
    generic priority values which are included in json
    log records.
    """

    EMERGENCY = 0
    ALERT = 1
    CRITICAL = 2
    ERROR = 3
    WARNING = 4
    NOTICE = 5
    INFO = 6
    DEBUG = 7
    TRACE = 8

    @classmethod
    def from_str(cls, string: str) -> PenlogPriority:
        """Converts a string to an instance of PenlogPriority.
        ``string`` can be a numeric value (0 to 8 inclusive)
        or a string with a case insensitive name of the level
        (e.g. ``debug``).
        """
        if string.isnumeric():
            return cls(int(string, 0))

        match string.lower():
            case "emergency":
                return cls.EMERGENCY
            case "alert":
                return cls.ALERT
            case "critical":
                return cls.CRITICAL
            case "error":
                return cls.ERROR
            case "warning":
                return cls.WARNING
            case "notice":
                return cls.NOTICE
            case "info":
                return cls.INFO
            case "debug":
                return cls.DEBUG
            case "trace":
                return cls.TRACE
            case _:
                raise ValueError(f"{string} not a valid priority")

    @classmethod
    def from_level(cls, value: int) -> PenlogPriority:
        """Converts an int value (e.g. from python's logging module)
        to an instance of this class.
        """
        match value:
            case Loglevel.TRACE:
                return cls.TRACE
            case Loglevel.DEBUG:
                return cls.DEBUG
            case Loglevel.INFO:
                return cls.INFO
            case Loglevel.NOTICE:
                return cls.NOTICE
            case Loglevel.WARNING:
                return cls.WARNING
            case Loglevel.ERROR:
                return cls.ERROR
            case Loglevel.CRITICAL:
                return cls.CRITICAL
            case _:
                raise ValueError("invalid value")

    def to_level(self) -> Loglevel:
        """Converts an instance of PenlogPriority to :class:`Loglevel`."""
        try:
            return _PRIORITY_TO_LEVEL[self]
        except KeyError:
            raise ValueError("invalid value") from None


# Lookup tables used on hot paths (e.g. hr reading large penlog files) to
# avoid the overhead of IntEnum's match-based to_level() and Enum's
# value-lookup machinery in PenlogRecord.parse_json().
_PRIORITY_TO_LEVEL: dict[PenlogPriority, Loglevel] = {
    PenlogPriority.TRACE: Loglevel.TRACE,
    PenlogPriority.DEBUG: Loglevel.DEBUG,
    PenlogPriority.INFO: Loglevel.INFO,
    PenlogPriority.NOTICE: Loglevel.NOTICE,
    PenlogPriority.WARNING: Loglevel.WARNING,
    PenlogPriority.ERROR: Loglevel.ERROR,
    PenlogPriority.CRITICAL: Loglevel.CRITICAL,
}
_PRIORITY_BY_VALUE: dict[int, PenlogPriority] = {p.value: p for p in PenlogPriority}


def setup_logging(
    level: Loglevel = Loglevel.DEBUG,
    logger_name: str = "gallia",
    volatile_info: bool = False,
    colors: bool = True,
    syslog_format: bool = False,
) -> None:
    """Enable and configure gallia's logging system.
    If this fuction is not called as early as possible,
    the logging system is in an undefined state und might
    not behave as expected. Always use this function to
    initialize gallia's logging. For instance, ``setup_logging()``
    initializes a QueueHandler to avoid blocking calls during
    logging.

    :param level: The loglevel to enable for the console handler.
    :param file_level: The loglevel to enable for the file handler.
    :param path: The path to the logfile containing json records.
    :param color_mode: The color mode to use for the console.
    """
    # These are slow and not used by gallia.
    logging.logMultiprocessing = False
    logging.logThreads = False
    logging.logProcesses = False

    logger = logging.getLogger(logger_name)
    # LogLevel cannot be 0 (NOTSET), because only the root logger sends it to its handlers then
    logger.setLevel(1)

    # Clean up potentially existing handlers and create a new async QueueHandler for stderr output
    while len(logger.handlers) > 0:
        logger.handlers[0].close()
        logger.removeHandler(logger.handlers[0])

    add_stderr_log_handler(logger_name, level, volatile_info, colors, syslog_format)


def add_stderr_log_handler(
    logger_name: str,
    level: Loglevel,
    volatile_info: bool,
    colors: bool,
    syslog_format: bool,
) -> None:
    queue: Queue[Any] = Queue()
    logger = logging.getLogger(logger_name)
    logger.addHandler(QueueHandler(queue))

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.terminator = ""  # We manually handle the terminator while formatting

    console_formatter = _ConsoleFormatter()
    console_formatter.colors = colors
    console_formatter.volatile_info = (
        volatile_info and level == Loglevel.INFO
    )  # Disable volatile info for DEBUG/TRACE
    console_formatter.syslog_format = syslog_format

    stderr_handler.setFormatter(console_formatter)

    queue_listener = QueueListener(
        queue,
        *[stderr_handler],
        respect_handler_level=True,
    )
    queue_listener.start()
    atexit.register(queue_listener.stop)


def add_zst_log_handler(
    logger_name: str,
    filepath: Path,
    file_log_level: Loglevel,
) -> _ZstdFileHandler:
    queue: Queue[Any] = Queue()
    logger = get_logger(logger_name)
    qh = QueueHandler(queue)
    logger.addHandler(qh)

    zstd_handler = _ZstdFileHandler(
        filepath,
        queue_handler=qh,
        level=file_log_level,
    )
    zstd_handler.setLevel(file_log_level)
    zstd_handler.setFormatter(_JSONFormatter())

    queue_listener = QueueListener(
        queue,
        *[zstd_handler],
        respect_handler_level=True,
    )
    queue_listener.start()
    zstd_handler.queue_listener = queue_listener
    return zstd_handler


def remove_zst_log_handler(logger_name: str, handler: _ZstdFileHandler) -> None:
    """This function removes the handler from the specified logger and closes it"""
    logger = get_logger(logger_name)
    # It is important to remove the Handler, otherwise it would still receive log messages
    logger.removeHandler(handler.queue_handler)
    handler.close()


@dataclasses.dataclass
class _PenlogRecordV2:
    module: str
    host: str
    data: str
    datetime: str
    priority: int
    version: int
    tags: list[str] | None = None
    line: str | None = None
    stacktrace: str | None = None
    _python_level_no: int | None = None
    _python_level_name: str | None = None
    _python_func_name: str | None = None
    # Unstable: the protocol of the data, see PenlogRecord.proto.
    _proto: str | None = None


_PenlogRecord: TypeAlias = _PenlogRecordV2


def level_style(levelno: int) -> tuple[ConsoleColor, bool]:
    """Returns the console color of a log level and whether it is bold.
    This is used by the console log and hr."""
    match levelno:
        case Loglevel.TRACE | Loglevel.DEBUG:
            return ConsoleColor.GRAY, False
        case Loglevel.NOTICE:
            return ConsoleColor.NOP, True
        case Loglevel.WARNING:
            return ConsoleColor.YELLOW, False
        case Loglevel.ERROR:
            return ConsoleColor.RED, False
        case Loglevel.CRITICAL:
            return ConsoleColor.RED, True
        case _:
            return ConsoleColor.NOP, False


def _colorize_msg(data: str, levelno: int) -> tuple[str, int]:
    color, bold = level_style(levelno)
    style = color.value + (ConsoleColor.BOLD.value if bold else "")
    return style + data + ConsoleColor.RESET.value, len(style)


def _format_tags(tags: list[str] | None) -> str:
    if tags is None or len(tags) == 0:
        return ""
    return f" [{', '.join(tags)}]"


def _format_record_for_syslog(
    name: str,
    data: str,
    levelno: int,
    tags: list[str] | None,
    stacktrace: str | None,
) -> str:
    priority = PenlogPriority.from_level(levelno).value
    msg = f"<{priority}>{name}{_format_tags(tags)} {data}\n"
    if stacktrace is not None:
        return msg + "\n" + stacktrace
    return msg


_MONTH_ABBREVIATIONS = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)


def format_timestamp(dt: datetime.datetime) -> str:
    """Formats a timestamp as displayed in the console log."""
    # Equivalent to dt.strftime("%b %d %H:%M:%S.%f")[:-3], but avoids the
    # locale-aware strftime() call, which is significantly slower and is
    # exercised once per record when e.g. hr formats a large penlog file.
    # Always renders the month in English, regardless of the system locale.
    return (
        f"{_MONTH_ABBREVIATIONS[dt.month - 1]} {dt.day:02d} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}.{dt.microsecond // 1000:03d}"
    )


def format_prefix(timestamp: str, name: str, tags: list[str] | None) -> str:
    """Formats the prefix of a console log line: timestamp, name, and tags."""
    return f"{timestamp} {name}{_format_tags(tags)}: "


def _format_record(
    dt: datetime.datetime,
    name: str,
    data: str,
    levelno: int,
    tags: list[str] | None,
    stacktrace: str | None,
    colors: bool = False,
    volatile_info: bool = False,
    prefix: str | None = None,
    suffix: str = "",
    align: bool = False,
) -> str:
    msg = ""
    if volatile_info:
        msg += "\33[2K"  # Clean current line
    extra_len = 4
    if prefix is None:
        prefix = format_prefix(format_timestamp(dt), name, tags)
    msg += prefix

    if align:
        # Continuation lines start below the first one, after the prefix.
        indent = " " * len(prefix)
        first, newline, rest = data.partition("\n")
        data = first + newline + textwrap.indent(rest, indent)
        if stacktrace is not None:
            stacktrace = textwrap.indent(stacktrace, indent)

    if colors:
        tmp_msg, extra_len_tmp = _colorize_msg(data, levelno)
        msg += tmp_msg
        extra_len += extra_len_tmp
    else:
        msg += data
    msg += suffix

    if volatile_info and levelno <= Loglevel.INFO:
        terminal_width, _ = shutil.get_terminal_size()
        msg = msg[: terminal_width + extra_len - 1]  # Adapt length to invisible ANSI colors
        msg += ConsoleColor.RESET.value
        msg += "\r"
    else:
        msg += "\n"

    if stacktrace is not None:
        msg += "\n"
        msg += stacktrace
        # Stacktraces of records usually lack the final newline; otherwise,
        # the next record would continue its last line.
        if not stacktrace.endswith("\n"):
            msg += "\n"

    return msg


@dataclasses.dataclass
class PenlogRecord:
    module: str
    host: str
    data: str
    datetime: datetime.datetime
    # FIXME: Enums are slow.
    priority: PenlogPriority
    tags: list[str] | None = None
    colors: bool = False
    line: str | None = None
    stacktrace: str | None = None
    _python_level_no: int | None = None
    _python_level_name: str | None = None
    _python_func_name: str | None = None
    _proto: str | None = None

    @property
    def proto(self) -> str | None:
        """The protocol of the data, e.g. ``uds``, for logged messages; it
        names the dissector (see :mod:`gallia.dissect`), which are named like
        in Wireshark. Unstable: it is stored in the ``_proto`` field."""
        return self._proto

    @property
    def level(self) -> int:
        """The Python log level of the record. EMERGENCY and ALERT, which
        Python does not know, are CRITICAL."""
        if self._python_level_no is not None:
            return self._python_level_no
        return _PRIORITY_TO_LEVEL.get(self.priority, Loglevel.CRITICAL)

    def __str__(self) -> str:
        return self.format()

    def format(self, prefix: str | None = None, suffix: str = "", align: bool = False) -> str:
        """Formats the record like the console log. ``prefix`` replaces the
        default prefix (see :func:`format_prefix`); ``suffix`` is appended
        to the data. With ``align``, continuation lines of the data and the
        stacktrace are indented to start below the first line of the data."""
        return _format_record(
            dt=self.datetime,
            name=self.module,
            data=self.data,
            levelno=self.level,
            tags=self.tags,
            stacktrace=self.stacktrace,
            colors=self.colors,
            prefix=prefix,
            suffix=suffix,
            align=align,
        )

    @classmethod
    def parse_priority(cls, data: bytes) -> int | None:
        if not data.startswith(b"<"):
            return None

        prio_str = data[1 : data.index(b">")]
        return int(prio_str)

    @classmethod
    def parse_json(cls, data: bytes) -> Self:
        if data.startswith(b"<"):
            data = data[data.index(b">") + 1 :]

        record = json.loads(data.decode())
        if (v := record["version"]) != 2:
            raise json.JSONDecodeError(f"invalid log record version {v}", data.decode(), 0)

        priority_value = record["priority"]

        try:
            priority = _PRIORITY_BY_VALUE[priority_value]
        except KeyError:
            raise ValueError(f"{priority_value!r} is not a valid PenlogPriority") from None

        return cls(
            module=record["module"],
            host=record["host"],
            data=record["data"],
            datetime=datetime.datetime.fromisoformat(record["datetime"]),
            priority=priority,
            tags=record.get("tags"),
            line=record.get("line"),
            stacktrace=record.get("stacktrace"),
            _python_level_no=record.get("_python_level_no"),
            _python_level_name=record.get("_python_level_name"),
            _python_func_name=record.get("_python_func_name"),
            _proto=record.get("_proto"),
        )

    def to_log_record(self) -> logging.LogRecord:
        level = self.priority.to_level()
        timestamp = self.datetime.timestamp()
        msecs = (timestamp - int(timestamp)) * 1000

        lineno = 0
        pathname = ""
        if (line := self.line) is not None:
            pathname, lineno_str = line.rsplit(":", 1)
            lineno = int(lineno_str)

        return logging.makeLogRecord(
            {
                "name": self.module,
                "priority": self.priority,
                "levelno": level,
                "levelname": logging.getLevelName(level),
                "msg": self.data,
                "pathname": pathname,
                "lineno": lineno,
                "created": timestamp,
                "msecs": msecs,
                "host": self.host,
                "tags": self.tags,
            }
        )


_PRIORITY_KEY = b'"priority":'
# Plain ints for the hot loops; accessing and comparing enums is slow.
_EMERGENCY = int(PenlogPriority.EMERGENCY)
_TRACE = int(PenlogPriority.TRACE)
_ERROR = int(PenlogPriority.ERROR)
# Indexing bytes returns ints; compare them with these.
_LESS_THAN = ord("<")
_SPACE = ord(" ")
_ZERO = ord("0")
_CHUNK_SIZE = 1 << 20


def _scan_priority(data: bytes | bytearray | mmap.mmap, start: int, end: int) -> int:
    """Extracts the priority of the record in ``data[start:end]``
    without parsing the JSON. Broken records are ``ERROR``."""
    if data[start] == _LESS_THAN:
        pos = start + 1
    elif (pos := data.find(_PRIORITY_KEY, start, end)) != -1:
        pos += len(_PRIORITY_KEY)
        while pos < end and data[pos] == _SPACE:
            pos += 1
    else:
        return _ERROR

    if pos < end and _EMERGENCY <= (prio := data[pos] - _ZERO) <= _TRACE:
        return prio
    return _ERROR


def _is_blank(data: bytes | bytearray | mmap.mmap, start: int, end: int) -> bool:
    # Only slice (= copy) the line if it might be blank.
    return end <= start or (data[start] in b" \t\r\n" and data[start:end].isspace())


if sys.version_info < (3, 14):

    class _ZstdReader(io.BufferedIOBase):
        """Decompresses zstd data with python-zstandard. Unlike zstandard.open(),
        it raises EOFError for truncated data like compression.zstd does."""

        def __init__(self, raw: io.BufferedIOBase) -> None:
            self._raw = raw
            self._dctx = zstd.ZstdDecompressor()
            self._dobj = self._dctx.decompressobj()
            self._buffer = b""
            self._pos = 0
            self._in_frame = False
            self._eof = False

        def readable(self) -> bool:
            return True

        def _feed(self, data: bytes) -> None:
            # Only called when the buffer has been consumed.
            output: list[bytes] = []
            while data:
                if self._dobj.eof:
                    # The next frame of a file with several frames.
                    self._dobj = self._dctx.decompressobj()
                output.append(self._dobj.decompress(data))
                data = self._dobj.unused_data if self._dobj.eof else b""
            self._buffer = b"".join(output)
            self._pos = 0
            self._in_frame = not self._dobj.eof

        def read1(self, size: int | None = -1) -> bytes:
            while self._pos >= len(self._buffer) and not self._eof:
                if chunk := self._raw.read(1 << 17):
                    self._feed(chunk)
                elif self._in_frame:
                    raise EOFError(
                        "Compressed file ended before the end-of-stream marker was reached"
                    )
                else:
                    self._eof = True
            end = len(self._buffer) if size is None or size < 0 else self._pos + size
            data = self._buffer[self._pos : end]
            self._pos += len(data)
            return data

        def read(self, size: int | None = -1) -> bytes:
            if size is not None and size >= 0:
                return self.read1(size)
            return b"".join(iter(self.read1, b""))

        def close(self) -> None:
            self._raw.close()
            super().close()


def _open_source(path: Path, raw: io.BufferedIOBase) -> io.BufferedIOBase:
    """Returns a stream of the decompressed data of ``raw``."""
    match path.suffix:
        case ".zst":
            if sys.version_info < (3, 14):
                return _ZstdReader(raw)
            return cast(io.BufferedIOBase, zstd.open(raw, "rb"))
        case ".gz":
            return gzip.open(raw, "rb")
        case _:
            return raw


def _open_raw(path: Path) -> io.BufferedIOBase:
    if str(path) == "-":
        # A separate descriptor; stdin might be replaced by the terminal
        # (e.g. for curses), while the data is still read.
        return os.fdopen(os.dup(sys.stdin.fileno()), "rb")
    return path.open("rb")


def stream_raw_records(
    path: Path | str, priority: PenlogPriority = PenlogPriority.TRACE
) -> Iterator[bytes]:
    """Streams the raw JSON of all records with a priority of at least
    ``priority``. Supports plain, ``.zst`` and ``.gz`` compressed files as
    well as ``-`` for stdin. The file is read sequentially with constant
    memory usage; for random access, see :class:`PenlogReader`.

    Raises OSError if the file cannot be read, e.g. if it is truncated.
    The records up to the damaged part are returned before."""
    path = Path(path)
    key_len = len(_PRIORITY_KEY)
    max_prio = int(priority)  # See _TRACE.
    with _open_raw(path) as raw, _open_source(path, raw) as source:
        rest = b""
        while True:
            pieces: list[bytes] = []
            size = 0
            error = None
            try:
                # read1() returns what is available; for truncated files,
                # the records before the damaged part are returned.
                while size < _CHUNK_SIZE and (piece := source.read1(_CHUNK_SIZE - size)):
                    pieces.append(piece)
                    size += len(piece)
            except Exception as e:
                error = OSError(f"reading {path} failed: {e}")
                error.__cause__ = e
            eof = size == 0 and error is None

            # Splitting chunks is much faster than reading lines. The last
            # line is incomplete, unless the end of the file is reached.
            lines = (rest + b"".join(pieces)).split(b"\n")
            rest = b"" if eof else lines.pop()

            # This is the hot loop.
            for line in lines:
                if not line or (line[0] in b" \t\r" and line.isspace()):
                    continue
                if max_prio < _TRACE:
                    # Fast paths for '<N>{...' and '{..."priority": N', which save
                    # the function call; _scan_priority() handles everything else,
                    # e.g. broken records.
                    try:
                        if line[0] == _LESS_THAN:
                            prio = line[1] - _ZERO
                        elif (pos := line.find(_PRIORITY_KEY)) != -1:
                            pos += key_len
                            prio = line[pos + (line[pos] == _SPACE)] - _ZERO
                        else:
                            prio = -1  # Not found; see _scan_priority().
                    except IndexError:
                        prio = -1
                    if not _EMERGENCY <= prio <= _TRACE:
                        prio = _scan_priority(line, 0, len(line))
                    if prio > max_prio:
                        continue
                yield line

            if error is not None:
                raise error
            if eof:
                return


def stream_records(
    path: Path | str, priority: PenlogPriority = PenlogPriority.TRACE
) -> Iterator[PenlogRecord]:
    """Like :func:`stream_raw_records`, but returns parsed records."""
    return map(PenlogRecord.parse_json, stream_raw_records(path, priority))


class PenlogReader:
    """Random access reader for penlog files.

    Plain, ``.zst`` and ``.gz`` compressed files as well as pipes (``-``
    for stdin) are supported. The file is memory mapped; compressed files
    and pipes are decompressed/copied to a temporary file ("spool") while
    it is indexed. Thus, the first records are available immediately.
    For only reading the file once from start to end, :func:`stream_records`
    is faster and needs no temporary file.

    Records are parsed on demand only. For random access (``len()``,
    indexing, :meth:`find`, :meth:`rfind`, reverse iteration) a compact
    index is built lazily, which costs nine bytes per record: the file
    offset and the priority. Thus, arbitrarily large files can be read
    without keeping the records in memory.

    The index is only built as far as needed; e.g. ``reader[10]`` indexes
    the first eleven records, ``len(reader)`` indexes the whole file.
    :meth:`update_index` allows building it incrementally in the
    background, e.g. in an event loop.
    """

    SPOOL_CHUNK_SIZE = _CHUNK_SIZE

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        # The compressed file (or the pipe) and the decompressed stream,
        # while spooling; None for plain files, which are mapped directly.
        self._raw: io.BufferedIOBase | None = None
        self._source: io.BufferedIOBase | None = None
        self._compressed_size: int | None = None

        if self._needs_spool(self.path):
            self._raw = _open_raw(self.path)
            self._source = _open_source(self.path, self._raw)
            if self.path.is_file():
                self._compressed_size = self.path.stat().st_size
            self._file = self._spool_file()
        else:
            self._file = self.path.open("rb")

        # The available data; grows while spooling.
        self._data: mmap.mmap | bytes = b""
        self._offsets = array("Q")
        self._priorities = bytearray()
        # One byte per record for each requested priority: 1 if the record
        # has at least this priority. Allows searching with find()/rfind().
        self._masks: dict[int, bytearray] = {}
        # The position up to which the data has been indexed.
        self._scan_pos = 0
        self._index_complete = False
        # Set if reading failed, e.g. for truncated files. The data read
        # until then is available nevertheless.
        self.error: OSError | None = None

        if self._source is None:
            self._map(os.fstat(self._file.fileno()).st_size)

    @staticmethod
    def _needs_spool(path: Path) -> bool:
        if str(path) == "-" or path.suffix in (".zst", ".gz") or path.is_fifo():
            return True
        with path.open("rb") as f:
            try:
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                return False
            except ValueError:
                # E.g. empty files or special files.
                return os.fstat(f.fileno()).st_size != 0

    def _spool_file(self) -> BinaryIO:
        # /tmp is often a small tmpfs; use the cache directory for large files.
        tmpdir = None
        if self._compressed_size is not None:
            estimate = self._compressed_size * (50 if self.path.suffix in (".zst", ".gz") else 1)
            if shutil.disk_usage(tempfile.gettempdir()).free < estimate:
                tmpdir = platformdirs.user_cache_path(ensure_exists=True)
        return cast(BinaryIO, tempfile.TemporaryFile(dir=tmpdir))

    def _map(self, size: int) -> None:
        if size > len(self._data):
            self._data = mmap.mmap(self._file.fileno(), size, access=mmap.ACCESS_READ)

    @property
    def _spooling(self) -> bool:
        return self._source is not None

    def _spool_chunk(self) -> None:
        """Decompresses the next chunk into the spool file."""
        assert self._source is not None and self._raw is not None
        chunk = bytearray()
        try:
            # read1() returns what is available; for truncated files, the
            # data before the damaged part is kept.
            while len(chunk) < self.SPOOL_CHUNK_SIZE and (
                piece := self._source.read1(self.SPOOL_CHUNK_SIZE - len(chunk))
            ):
                chunk += piece
            done = len(chunk) == 0
        except Exception as e:
            self.error = OSError(f"reading {self.path} failed: {e}")
            done = True

        if chunk:
            try:
                self._file.write(chunk)
                self._file.flush()
            except OSError as e:
                self.error = OSError(f"spooling {self.path} failed: {e}")
                done = True
            self._map(self._file.tell())

        if done:
            self._source.close()
            self._raw.close()
            self._source = None
            self._raw = None

    @property
    def index_complete(self) -> bool:
        return self._index_complete

    @property
    def indexed(self) -> int:
        """The number of records in the index so far."""
        return len(self._offsets)

    @property
    def index_progress(self) -> float | None:
        """The indexed fraction of the file between 0 and 1; None if
        unknown, e.g. for pipes."""
        if self._index_complete:
            return 1.0
        if not self._spooling:
            return self._scan_pos / max(len(self._data), 1)
        if self._compressed_size is None or self._raw is None:
            return None
        # Data is only decompressed when the previous data has been indexed.
        return min(self._raw.tell() / max(self._compressed_size, 1), 1.0)

    @staticmethod
    def _mask_table(priority: int) -> bytes:
        return bytes(1 if i <= priority else 0 for i in range(256))

    def _index_limit(self) -> int:
        """The end of the data which can be indexed: complete lines only,
        unless all data is available. After an error, e.g. for a truncated
        file, the last line is incomplete."""
        size = len(self._data)
        if not self._spooling and self.error is None:
            return size
        return self._data.rfind(b"\n", self._scan_pos, size) + 1

    def update_index(self, max_records: int = 0x4000) -> bool:
        """Extends the index by at most ``max_records`` records.
        Returns True if the index is complete."""
        if self._index_complete:
            return True

        if self._spooling and self._index_limit() <= self._scan_pos:
            self._spool_chunk()

        data = self._data
        pos = self._scan_pos
        limit = self._index_limit()
        offsets = self._offsets
        priorities = self._priorities
        n = len(offsets)
        while pos < limit and len(offsets) - n < max_records:
            end = data.find(b"\n", pos, limit)
            if end == -1:
                end = limit
            if not _is_blank(data, pos, end):
                offsets.append(pos)
                priorities.append(_scan_priority(data, pos, end))
            pos = end + 1
        self._scan_pos = max(pos, self._scan_pos)

        new_priorities = priorities[n:]
        for priority, mask in self._masks.items():
            mask.extend(new_priorities.translate(self._mask_table(priority)))

        self._index_complete = not self._spooling and self._index_limit() <= self._scan_pos
        return self._index_complete

    def build_index(self) -> None:
        """Completes the index. This is done implicitly if needed."""
        while not self.update_index(0x10000):
            pass

    def _ensure_indexed(self, index: int) -> None:
        """Extends the index until it covers ``index``."""
        if index < 0:
            self.build_index()
        while index >= len(self._offsets) and not self.update_index():
            pass

    @property
    def file_size(self) -> int:
        """The size of the (decompressed) data available so far."""
        return len(self._data)

    def offset(self, index: int) -> int:
        """Returns the position of the record at ``index`` in the
        (decompressed) data."""
        self._ensure_indexed(index)
        return self._offsets[index]

    def raw(self, index: int) -> bytes:
        """Returns the raw bytes of the record at ``index``."""
        self._ensure_indexed(index)
        start = self._offsets[index]
        end = self._data.find(b"\n", start)
        return self._data[start : end if end != -1 else len(self._data)]

    def priority(self, index: int) -> PenlogPriority:
        """Returns the priority of the record at ``index`` without parsing it."""
        self._ensure_indexed(index)
        return _PRIORITY_BY_VALUE[self._priorities[index]]

    def _mask(self, priority: int) -> bytearray:
        if (mask := self._masks.get(priority)) is None:
            mask = self._masks[priority] = self._priorities.translate(self._mask_table(priority))
        return mask

    def _search_range(self, end: int | None) -> int:
        if end is None:
            self.build_index()
            return len(self._offsets)
        self._ensure_indexed(end - 1)
        return end

    def find(self, priority: int, start: int = 0, end: int | None = None) -> int | None:
        """Returns the index of the first record in ``[start, end)`` with a
        priority of at least ``priority``, or None."""
        end = self._search_range(end)
        i = self._mask(priority).find(1, start, end)
        return i if i != -1 else None

    def rfind(self, priority: int, start: int = 0, end: int | None = None) -> int | None:
        """Returns the index of the last record in ``[start, end)`` with a
        priority of at least ``priority``, or None."""
        end = self._search_range(end)
        i = self._mask(priority).rfind(1, start, end)
        return i if i != -1 else None

    def _byte_range(self, start: int, end: int) -> tuple[int, int]:
        """Returns the byte range of the indexed records ``[start, end)``."""
        pos = self._offsets[start]
        if end < len(self._offsets):
            return pos, self._offsets[end]
        # The end of the last indexed record.
        return pos, min(self._scan_pos, len(self._data))

    def search(
        self, pattern: re.Pattern[bytes], start: int = 0, end: int | None = None
    ) -> int | None:
        """Returns the index of the first record in ``[start, end)`` whose raw
        bytes match ``pattern``, or None. The pattern must not match newlines.
        This does not parse any records and is thus fast."""
        end = self._search_range(end)
        if start >= end:
            return None
        pos, endpos = self._byte_range(start, end)
        if (m := pattern.search(self._data, pos, endpos)) is None:
            return None
        return bisect_right(self._offsets, m.start()) - 1

    def rsearch(
        self, pattern: re.Pattern[bytes], start: int = 0, end: int | None = None
    ) -> int | None:
        """Like :meth:`search`, but returns the last matching record."""
        end = self._search_range(end)
        if start >= end:
            return None
        pos, endpos = self._byte_range(start, end)
        # Regexes cannot search backwards; search in growing windows instead.
        window = 0x10000
        while endpos > pos:
            window_start = max(pos, endpos - window)
            # Align the window to a record start, so that no match is cut off.
            window_start = self._offsets[bisect_right(self._offsets, window_start) - 1]
            window_start = max(window_start, pos)
            last = None
            for last in pattern.finditer(self._data, window_start, endpos):  # noqa: B007
                pass
            if last is not None:
                return bisect_right(self._offsets, last.start()) - 1
            endpos = window_start
            window *= 2
        return None

    def records(
        self,
        priority: PenlogPriority = PenlogPriority.TRACE,
        offset: int | None = None,
        reverse: bool = False,
    ) -> Iterator[PenlogRecord]:
        """Iterates over all records with a priority of at least ``priority``.
        Iterating forwards starts immediately, while the file is still read.

        :param offset: Index of the first record (negative values count from
                       the end). Defaults to the first record, or to the
                       last record if ``reverse`` is set.
        :param reverse: Iterate backwards.
        """
        if offset is not None and offset < 0:
            offset = max(0, len(self) + offset)

        if reverse:
            i = self.rfind(priority, 0, offset + 1 if offset is not None else None)
            while i is not None:
                yield self[i]
                i = self.rfind(priority, 0, i)
            return

        i = offset or 0
        while True:
            self._ensure_indexed(i)
            if i >= len(self._offsets):
                return
            if (found := self._mask(priority).find(1, i, len(self._offsets))) == -1:
                i = len(self._offsets)
                continue
            yield self[found]
            i = found + 1

    def close(self) -> None:
        if isinstance(self._data, mmap.mmap):
            self._data.close()
        if self._source is not None:
            self._source.close()
        if self._raw is not None:
            self._raw.close()
        self._file.close()

    def __len__(self) -> int:
        self.build_index()
        return len(self._offsets)

    def __getitem__(self, index: int) -> PenlogRecord:
        return PenlogRecord.parse_json(self.raw(index))

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


@unique
class ConsoleColor(Enum):
    NOP = ""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    PURPLE = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    GRAY = "\033[0;38;5;245m"
    ORANGE = "\033[38;5;208m"


class _JSONFormatter(logging.Formatter):
    def __init__(self) -> None:
        super().__init__()
        self.hostname = socket.gethostname()

    def format(self, record: logging.LogRecord) -> str:
        tags = record.__dict__["tags"] if "tags" in record.__dict__ else None
        stacktrace = self.formatException(record.exc_info) if record.exc_info else None

        penlog_record = _PenlogRecordV2(
            module=record.name,
            host=self.hostname,
            data=record.getMessage(),
            priority=PenlogPriority.from_level(record.levelno).value,
            datetime=datetime.datetime.fromtimestamp(record.created, tz=tz).isoformat(),
            line=f"{record.pathname}:{record.lineno}",
            stacktrace=stacktrace,
            tags=tags,
            _python_level_no=record.levelno,
            _python_level_name=record.levelname,
            _python_func_name=record.funcName,
            _proto=record.__dict__.get("proto"),
            version=2,
        )
        return json.dumps(dataclasses.asdict(penlog_record))


class _ConsoleFormatter(logging.Formatter):
    colors: bool = False
    volatile_info: bool = False
    syslog_format: bool = False

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        stacktrace = None

        if record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            assert exc_type
            assert exc_value
            assert exc_traceback

            stacktrace = "\n"
            stacktrace += "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))

        name = record.name
        data = record.getMessage()
        levelno = record.levelno
        tags = record.__dict__["tags"] if "tags" in record.__dict__ else None

        if self.syslog_format is True:
            return _format_record_for_syslog(
                name=name,
                data=data,
                levelno=levelno,
                tags=tags,
                stacktrace=stacktrace,
            )
        return _format_record(
            dt=datetime.datetime.fromtimestamp(record.created),
            name=name,
            data=data,
            levelno=levelno,
            tags=tags,
            stacktrace=stacktrace,
            colors=self.colors and sys.platform != "win32" and sys.stderr.isatty(),
            volatile_info=self.volatile_info,
        )


class _ZstdFileHandler(logging.Handler):
    def __init__(
        self, path: Path, queue_handler: QueueHandler, level: int | str = logging.NOTSET
    ) -> None:
        super().__init__(level)
        self.file = zstd.open(path, "wb")
        self.queue_handler = queue_handler
        self.queue_listener: QueueListener | None = None

    def close(self) -> None:
        """This function closes the queue handler, the queue listener, and the log file."""
        self.queue_handler.close()
        # There might be no queue_listener or it might already be closed (_thread is None)
        if self.queue_listener is not None and self.queue_listener._thread is not None:
            self.queue_listener.stop()
        self.file.flush()
        self.file.close()

    def emit(self, record: logging.LogRecord) -> None:
        prio = PenlogPriority.from_level(record.levelno).value
        data = f"<{prio}>{self.format(record)}"
        if not data.endswith("\n"):
            data += "\n"
        self.file.write(data.encode())


class Logger(logging.Logger):
    def trace(
        self,
        msg: Any,
        *args: Any,
        exc_info: Any = None,
        stack_info: bool = False,
        extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if self.isEnabledFor(Loglevel.TRACE):
            self._log(
                Loglevel.TRACE,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                # Report the caller of this method, not this method.
                stacklevel=kwargs.pop("stacklevel", 1) + 1,
                **kwargs,
            )

    def notice(
        self,
        msg: Any,
        *args: Any,
        exc_info: Any = None,
        stack_info: bool = False,
        extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        if self.isEnabledFor(Loglevel.NOTICE):
            self._log(
                Loglevel.NOTICE,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                # Report the caller of this method, not this method.
                stacklevel=kwargs.pop("stacklevel", 1) + 1,
                **kwargs,
            )

    def result(
        self,
        msg: Any,
        *args: Any,
        exc_info: Any = None,
        stack_info: bool = False,
        extra: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        extra = extra if extra is not None else {}
        extra["tags"] = ["result"]
        if self.isEnabledFor(Loglevel.NOTICE):
            self._log(
                Loglevel.NOTICE,
                msg,
                args,
                exc_info=exc_info,
                extra=extra,
                stack_info=stack_info,
                # Report the caller of this method, not this method.
                stacklevel=kwargs.pop("stacklevel", 1) + 1,
                **kwargs,
            )


logging.setLoggerClass(Logger)


def get_logger(name: str) -> Logger:
    return cast(Logger, logging.getLogger(name))
