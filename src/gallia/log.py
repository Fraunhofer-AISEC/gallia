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
import shutil
import socket
import sys
import tempfile
import time
import traceback
from collections.abc import Iterator
from enum import Enum, IntEnum, unique
from logging.handlers import QueueHandler, QueueListener
from pathlib import Path
from queue import Queue
from types import TracebackType
from typing import TYPE_CHECKING, Any, BinaryIO, Self, TextIO, TypeAlias, cast

import zstandard

if TYPE_CHECKING:
    from logging import _ExcInfoType


gmt_offset = time.localtime().tm_gmtoff
tz = datetime.timezone(datetime.timedelta(seconds=gmt_offset))


@unique
class ColorMode(Enum):
    """ColorMode is used as an argument to :func:`set_color_mode`."""

    #: Colors are always turned on.
    ALWAYS = "always"
    #: Colors are turned off if the target
    #: stream (e.g. stderr) is not a tty.
    AUTO = "auto"
    #: No colors are used. In other words,
    #: no ANSI escape codes are included.
    NEVER = "never"


def resolve_color_mode(mode: ColorMode, stream: TextIO = sys.stderr) -> bool:
    """Sets the color mode of the console log handler.

    :param mode: The available options are described in :class:`ColorMode`.
    :param stream: Used as a reference for :attr:`ColorMode.AUTO`.
    """
    if sys.platform == "win32":
        return False

    match mode:
        case ColorMode.ALWAYS:
            return True
        case ColorMode.AUTO:
            if os.getenv("NO_COLOR") is not None:
                return False
            else:
                return stream.isatty()
        case ColorMode.NEVER:
            return False


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
    def for_level(self, message, *args, **kwargs):  # type: ignore
        if self.isEnabledFor(level_num):
            self._log(
                level_num,
                message,
                args,
                **kwargs,
            )

    def to_root(message, *args, **kwargs):  # type: ignore
        logging.log(level_num, message, *args, **kwargs)

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
    NOTICE = logging.NOTICE  # type: ignore
    INFO = logging.INFO
    DEBUG = logging.DEBUG
    TRACE = logging.TRACE  # type: ignore


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
        match self:
            case self.TRACE:
                return Loglevel.TRACE
            case self.DEBUG:
                return Loglevel.DEBUG
            case self.INFO:
                return Loglevel.INFO
            case self.NOTICE:
                return Loglevel.NOTICE
            case self.WARNING:
                return Loglevel.WARNING
            case self.ERROR:
                return Loglevel.ERROR
            case self.CRITICAL:
                return Loglevel.CRITICAL
            case _:
                raise ValueError("invalid value")


def setup_logging(
    level: Loglevel | None = None,
    color_mode: ColorMode = ColorMode.AUTO,
    no_volatile_info: bool = False,
    logger_name: str = "gallia",
) -> None:
    """Enable and configure gallia's logging system.
    If this fuction is not called as early as possible,
    the logging system is in an undefined state und might
    not behave as expected. Always use this function to
    initialize gallia's logging. For instance, ``setup_logging()``
    initializes a QueueHandler to avoid blocking calls during
    logging.

    :param level: The loglevel to enable for the console handler.
                  If this argument is None, the env variable
                  ``GALLIA_LOGLEVEL`` (see :doc:`../env`) is read.
    :param file_level: The loglevel to enable for the file handler.
    :param path: The path to the logfile containing json records.
    :param color_mode: The color mode to use for the console.
    """
    if level is None:
        # FIXME: why is this here and not in config?
        if (raw := os.getenv("GALLIA_LOGLEVEL")) is not None:
            level = PenlogPriority.from_str(raw).to_level()
        else:
            level = Loglevel.DEBUG

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
    colored = resolve_color_mode(color_mode)
    add_stderr_log_handler(logger_name, level, no_volatile_info, colored)


def add_stderr_log_handler(
    logger_name: str,
    level: Loglevel,
    no_volatile_info: bool,
    colored: bool,
) -> None:
    queue: Queue[Any] = Queue()
    logger = logging.getLogger(logger_name)
    logger.addHandler(QueueHandler(queue))

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    console_formatter = _ConsoleFormatter()

    console_formatter.colored = colored
    stderr_handler.terminator = ""  # We manually handle the terminator while formatting
    if no_volatile_info is False:
        console_formatter.volatile_info = True

    stderr_handler.setFormatter(console_formatter)

    queue_listener = QueueListener(
        queue,
        *[stderr_handler],
        respect_handler_level=True,
    )
    queue_listener.start()
    atexit.register(queue_listener.stop)


def add_zst_log_handler(
    logger_name: str, filepath: Path, file_log_level: Loglevel
) -> logging.Handler:
    queue: Queue[Any] = Queue()
    logger = get_logger(logger_name)
    logger.addHandler(QueueHandler(queue))

    zstd_handler = _ZstdFileHandler(
        filepath,
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
    atexit.register(queue_listener.stop)
    return zstd_handler


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


_PenlogRecord: TypeAlias = _PenlogRecordV2


def _colorize_msg(data: str, levelno: int) -> tuple[str, int]:
    if sys.platform == "win32" or not sys.stderr.isatty():
        return data, 0

    out = ""
    match levelno:
        case Loglevel.TRACE:
            style = _Color.GRAY.value
        case Loglevel.DEBUG:
            style = _Color.GRAY.value
        case Loglevel.INFO:
            style = _Color.NOP.value
        case Loglevel.NOTICE:
            style = _Color.BOLD.value
        case Loglevel.WARNING:
            style = _Color.YELLOW.value
        case Loglevel.ERROR:
            style = _Color.RED.value
        case Loglevel.CRITICAL:
            style = _Color.RED.value + _Color.BOLD.value
        case _:
            style = _Color.NOP.value

    out += style
    out += data
    out += _Color.RESET.value

    return out, len(style)


def _format_record(  # noqa: PLR0913
    dt: datetime.datetime,
    name: str,
    data: str,
    levelno: int,
    tags: list[str] | None,
    stacktrace: str | None,
    colored: bool = False,
    volatile_info: bool = False,
) -> str:
    msg = ""
    if volatile_info:
        msg += "\33[2K"
    extra_len = 4
    msg += dt.strftime("%b %d %H:%M:%S.%f")[:-3]
    msg += " "
    msg += name
    if tags is not None and len(tags) > 0:
        msg += f" [{', '.join(tags)}]"
    msg += ": "

    if colored:
        tmp_msg, extra_len_tmp = _colorize_msg(data, levelno)
        msg += tmp_msg
        extra_len += extra_len_tmp
    else:
        msg += data

    if volatile_info and levelno <= Loglevel.INFO:
        terminal_width, _ = shutil.get_terminal_size()
        msg = msg[: terminal_width + extra_len - 1]  # Adapt length to invisible ANSI colors
        msg += _Color.RESET.value
        msg += "\r"
    else:
        msg += "\n"

    if stacktrace is not None:
        msg += "\n"
        msg += stacktrace

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
    colored: bool = False
    line: str | None = None
    stacktrace: str | None = None
    _python_level_no: int | None = None
    _python_level_name: str | None = None
    _python_func_name: str | None = None

    def __str__(self) -> str:
        return _format_record(
            dt=self.datetime,
            name=self.module,
            data=self.data,
            levelno=self._python_level_no
            if self._python_level_no is not None
            else self.priority.to_level(),
            tags=self.tags,
            stacktrace=self.stacktrace,
            colored=self.colored,
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

        return cls(
            module=record["module"],
            host=record["host"],
            data=record["data"],
            datetime=datetime.datetime.fromisoformat(record["datetime"]),
            priority=PenlogPriority(record["priority"]),
            tags=record["tags"] if "tags" in record else None,
            line=record["line"] if "line" in record else None,
            stacktrace=record["stacktrace"] if "stacktrace" in record else None,
            _python_level_no=record["_python_level_no"] if "_python_level_no" in record else None,
            _python_level_name=record["_python_level_name"]
            if "_python_level_name" in record
            else None,
            _python_func_name=record["_python_func_name"]
            if "_python_func_name" in record
            else None,
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


class PenlogReader:
    def __init__(self, path: Path) -> None:
        self.path = path if str(path) != "-" else Path("/dev/stdin")
        self.raw_file = self._prepare_for_mmap(self.path)
        self.file_mmap = mmap.mmap(self.raw_file.fileno(), 0, access=mmap.ACCESS_READ)
        self._current_line = b""
        self._current_record: PenlogRecord | None = None
        self._current_record_index = 0
        self._parsed = False
        self._record_offsets: list[int] = []

    def _test_mmap(self, path: Path) -> bool:
        with path.open("rb") as f:
            try:
                mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                return True
            except ValueError:
                return False

    def _prepare_for_mmap(self, path: Path) -> BinaryIO:
        if path.is_file() and path.suffix in [".zst", ".gz"]:
            tmpfile = tempfile.TemporaryFile()
            match path.suffix:
                case ".zst":
                    with self.path.open("rb") as f:
                        decomp = zstandard.ZstdDecompressor()
                        decomp.copy_stream(f, tmpfile)
                case ".gz":
                    with gzip.open(self.path, "rb") as f:
                        shutil.copyfileobj(cast(BinaryIO, f), tmpfile)

            tmpfile.flush()
            return cast(BinaryIO, tmpfile)

        if path.is_fifo() or self._test_mmap(path) is False:
            tmpfile = tempfile.TemporaryFile()
            with path.open("rb") as f:
                shutil.copyfileobj(f, tmpfile)
            tmpfile.flush()
            return cast(BinaryIO, tmpfile)

        return self.path.open("rb")

    def _parse_file_structure(self) -> None:
        old_offset = self.file_mmap.tell()

        while True:
            self._record_offsets.append(self.file_mmap.tell())

            line = self.file_mmap.readline()
            if line == b"":
                # The last newline char is not relevant, since
                # no data is following.
                del self._record_offsets[-1]
                break

        self.file_mmap.seek(old_offset)
        self._parsed = True

    def _lookup_offset(self, index: int) -> int:
        if index == 0:
            return 0
        if not self._parsed:
            self._parse_file_structure()
        return self._record_offsets[index]

    @property
    def file_size(self) -> int:
        old_offset = self.file_mmap.tell()
        self.file_mmap.seek(0, io.SEEK_END)
        size = self.file_mmap.tell()
        self.file_mmap.seek(old_offset)
        return size

    @property
    def current_record(self) -> PenlogRecord:
        if self._current_record is not None:
            return self._current_record
        return PenlogRecord.parse_json(self._current_line)

    @property
    def current_priority(self) -> int:
        prio = PenlogRecord.parse_priority(self._current_line)
        if prio is None:
            self._current_record = PenlogRecord.parse_json(self._current_line)
            prio = self._current_record.priority
        return prio

    def seek_to_record(self, n: int) -> None:
        self.file_mmap.seek(self._lookup_offset(n))
        self._current_record_index = n

    def seek_to_current_record(self) -> None:
        self.file_mmap.seek(self._lookup_offset(self._current_record_index))

    def seek_to_previous_record(self) -> None:
        self._current_record_index -= 1
        self.seek_to_record(self._current_record_index)

    def seek_to_next_record(self) -> None:
        self._current_record_index += 1
        self.seek_to_record(self._current_record_index)

    def records(
        self,
        priority: PenlogPriority = PenlogPriority.TRACE,
        offset: int = 0,
        reverse: bool = False,
    ) -> Iterator[PenlogRecord]:
        self.seek_to_record(offset)
        if reverse is False:
            while True:
                if self.readline() == b"":
                    break
                if self.current_priority <= priority:
                    yield self.current_record
        else:
            while True:
                self.readline()
                if self.current_priority <= priority:
                    yield self.current_record
                try:
                    self.seek_to_previous_record()
                except IndexError:
                    break

    def readline(self) -> bytes:
        self._current_record = None
        self._current_line = self.file_mmap.readline()
        return self._current_line

    def close(self) -> None:
        self.file_mmap.close()
        self.raw_file.close()

    def __len__(self) -> int:
        if not self._parsed:
            self._parse_file_structure()
        return len(self._record_offsets)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            self.close()


@unique
class _Color(Enum):
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
            version=2,
        )
        return json.dumps(dataclasses.asdict(penlog_record))


class _ConsoleFormatter(logging.Formatter):
    colored: bool = False
    volatile_info: bool = False

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

        return _format_record(
            dt=datetime.datetime.fromtimestamp(record.created),
            name=record.name,
            data=record.getMessage(),
            levelno=record.levelno,
            tags=record.__dict__["tags"] if "tags" in record.__dict__ else None,
            stacktrace=stacktrace,
            colored=self.colored,
            volatile_info=self.volatile_info,
        )


class _ZstdFileHandler(logging.Handler):
    def __init__(self, path: Path, level: int | str = logging.NOTSET) -> None:
        super().__init__(level)
        self.file = zstandard.open(
            filename=path,
            mode="wb",
            cctx=zstandard.ZstdCompressor(
                write_checksum=True,
                write_content_size=True,
                threads=-1,
            ),
        )

    def close(self) -> None:
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
        exc_info: _ExcInfoType = None,
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
                **kwargs,
            )

    def notice(
        self,
        msg: Any,
        *args: Any,
        exc_info: _ExcInfoType = None,
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
                **kwargs,
            )

    def result(
        self,
        msg: Any,
        *args: Any,
        exc_info: _ExcInfoType = None,
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
                **kwargs,
            )


logging.setLoggerClass(Logger)


def get_logger(name: str) -> Logger:
    return cast(Logger, logging.getLogger(name))
