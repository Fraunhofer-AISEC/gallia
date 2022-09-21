# SPDX-FileCopyrightText: AISEC Pentesting Team
#
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import socket
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime
from enum import Enum, IntEnum, unique
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

import msgspec
import zstandard

if TYPE_CHECKING:
    from logging import _ExcInfoType


tz = datetime.utcnow().astimezone().tzinfo


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
            self._log(  # pylint: disable=protected-access
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
class PenlogPriority(IntEnum):
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
        match value:
            case logging.TRACE:  # type: ignore
                return cls.TRACE
            case logging.DEBUG:
                return cls.DEBUG
            case logging.INFO:
                return cls.INFO
            case logging.NOTICE:  # type: ignore
                return cls.NOTICE
            case logging.WARNING:
                return cls.WARNING
            case logging.ERROR:
                return cls.ERROR
            case logging.CRITICAL:
                return cls.CRITICAL
            case _:
                raise ValueError("invalid value")

    def to_level(self) -> int:
        match self:
            case self.TRACE:
                return logging.TRACE  # type: ignore
            case self.DEBUG:
                return logging.DEBUG
            case self.INFO:
                return logging.INFO
            case self.NOTICE:
                return logging.NOTICE  # type: ignore
            case self.WARNING:
                return logging.WARNING
            case self.ERROR:
                return logging.ERROR
            case self.CRITICAL:
                return logging.CRITICAL
            case _:
                raise ValueError("invalid value")


def setup_logging(
    level: int,
    file_level: int = logging.DEBUG,
    path: Path | None = None,
) -> None:
    # These are slow and not used by gallia.
    logging.logMultiprocessing = False
    logging.logThreads = False
    logging.logProcesses = False

    # If ctrl+c is hit, the asyncio logger wants to log some stuff;
    # this causes annoying and kind of useless stacktraces. Disable
    # these messages.
    logging.getLogger("asyncio").setLevel(logging.CRITICAL)
    logging.getLogger("aiosqlite").setLevel(logging.CRITICAL)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(ConsoleFormatter())

    handlers: list[logging.Handler] = [stderr_handler]

    if path is not None:
        zstd_handler = ZstdFileHandler(path, level=file_level)
        zstd_handler.setFormatter(JSONFormatter())
        handlers.append(zstd_handler)

    logging.basicConfig(
        handlers=handlers,
        level=file_level,
        force=True,
    )


class _PenlogRecordV1(msgspec.Struct, omit_defaults=True):
    component: str
    host: str
    data: str
    timestamp: str
    priority: int
    type: str | None = None
    tags: list[str] | None = None
    line: str | None = None
    stacktrace: str | None = None


class _PenlogRecordV2(msgspec.Struct, omit_defaults=True, tag=2, tag_field="version"):
    module: str
    host: str
    data: str
    datetime: str
    priority: int
    tags: list[str] | None = None
    line: str | None = None
    stacktrace: str | None = None
    _python_level_no: int | None = None
    _python_level_name: str | None = None
    _python_func_name: str | None = None


_PenlogRecord = _PenlogRecordV1 | _PenlogRecordV2


@dataclass
class PenlogRecord:
    module: str
    host: str
    data: str
    datetime: datetime
    priority: PenlogPriority
    tags: list[str] | None = None
    line: str | None = None
    stacktrace: str | None = None
    _python_level_no: int | None = None
    _python_level_name: str | None = None
    _python_func_name: str | None = None

    @classmethod
    def parse_json(cls, data: bytes) -> PenlogRecord:
        # PenlogRecordV1 has no version field, thus the tagged
        # union based approach does not work.
        record = _PenlogRecord
        try:
            record = msgspec.json.decode(data, type=_PenlogRecordV2)
        except msgspec.ValidationError:
            record = msgspec.json.decode(data, type=_PenlogRecordV1)

        match record:
            case _PenlogRecordV1():
                try:
                    dt = datetime.fromisoformat(record.timestamp)
                except ValueError:
                    # Workaround for broken ISO strings. Go produced broken strings. :)
                    # We have some old logfiles with this shortcoming.
                    datestr, _ = record.timestamp.split(".", 2)
                    dt = datetime.strptime(datestr, "%Y-%m-%dT%H:%M:%S")

                if record.tags is not None:
                    tags = record.tags
                else:
                    tags = []

                if record.type is not None:
                    tags += [record.type]

                return cls(
                    module=record.component,
                    host=record.host,
                    data=record.data,
                    datetime=dt,
                    priority=PenlogPriority(record.priority),
                    tags=tags,
                    line=record.line,
                    stacktrace=record.stacktrace,
                )
            case _PenlogRecordV2():
                return cls(
                    module=record.module,
                    host=record.host,
                    data=record.data,
                    datetime=datetime.fromisoformat(record.datetime),
                    priority=PenlogPriority(record.priority),
                    tags=record.tags,
                    line=record.line,
                    stacktrace=record.stacktrace,
                    _python_level_no=record._python_level_no,  # pylint: disable=protected-access
                    _python_level_name=record._python_level_name,  # pylint: disable=protected-access
                    _python_func_name=record._python_func_name,  # pylint: disable=protected-access
                )
        raise ValueError("unknown record version")

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


@unique
class Color(Enum):
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


class JSONFormatter(logging.Formatter):
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
            datetime=datetime.fromtimestamp(record.created, tz=tz).isoformat(),
            line=f"{record.pathname}:{record.lineno}",
            stacktrace=stacktrace,
            tags=tags,
            _python_level_no=record.levelno,
            _python_level_name=record.levelname,
            _python_func_name=record.funcName,
        )

        return msgspec.json.encode(penlog_record).decode()


class ConsoleFormatter(logging.Formatter):
    def _colorize_msg(self, record: logging.LogRecord) -> str:
        if not sys.stderr.isatty():
            return record.getMessage()

        out = ""
        if record.levelno == logging.TRACE:  # type: ignore
            style = Color.GRAY.value
        elif record.levelno == logging.DEBUG:
            style = Color.GRAY.value
        elif record.levelno == logging.INFO:
            style = Color.NOP.value
        elif record.levelno == logging.NOTICE:  # type: ignore
            style = Color.BOLD.value
        elif record.levelno == logging.WARNING:
            style = Color.YELLOW.value
        elif record.levelno == logging.ERROR:
            style = Color.RED.value
        elif record.levelno == logging.CRITICAL:
            style = Color.RED.value + Color.BOLD.value
        else:
            style = Color.NOP.value

        out += style
        out += record.getMessage()
        out += Color.RESET.value

        return out

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        msg = ""
        dt = datetime.fromtimestamp(record.created)
        msg += dt.strftime("%b %d %H:%M:%S.%f")[:-3]
        msg += " "
        msg += f"{record.name}"
        if "tags" in record.__dict__ and (tags := record.__dict__["tags"]) is not None:
            msg += f" [{', '.join(tags)}]"
        msg += ": "

        msg += self._colorize_msg(record)

        if record.exc_info:
            exc_type, exc_value, exc_traceback = record.exc_info
            assert exc_type
            assert exc_value
            assert exc_traceback

            msg += "\n"
            msg += "".join(
                traceback.format_exception(exc_type, exc_value, exc_traceback)
            )

        return msg


class ZstdFileHandler(logging.Handler):
    def __init__(self, path: Path, level: int | str = logging.NOTSET) -> None:
        super().__init__(level)
        self.file = path.open("wb")
        self.compressor = zstandard.ZstdCompressor()
        self.zstd_writer = self.compressor.stream_writer(self.file)

    def close(self) -> None:
        self.zstd_writer.flush()
        self.zstd_writer.close()  # type: ignore
        self.file.close()

    def emit(self, record: logging.LogRecord) -> None:
        data = self.format(record)
        if not data.endswith("\n"):
            data += "\n"
        self.zstd_writer.write(data.encode())


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
        if self.isEnabledFor(logging.TRACE):  # type: ignore
            self._log(
                logging.TRACE,  # type: ignore
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
        if self.isEnabledFor(logging.NOTICE):  # type: ignore
            self._log(
                logging.NOTICE,  # type: ignore
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
        if self.isEnabledFor(logging.NOTICE):  # type: ignore
            self._log(
                logging.NOTICE,  # type: ignore
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
